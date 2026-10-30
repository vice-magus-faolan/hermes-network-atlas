# SPDX-License-Identifier: GPL-3.0-or-later
"""Populated legacy/WAL conversion through the actual registered native CLI."""
from contextlib import redirect_stdout
from dataclasses import replace
import argparse
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import time
from unittest.mock import patch

from helpers import symlink_plugin_data


def _history(storage, policy):
    with storage.Store(policy) as store, store.snapshot():
        return list(store.connection.iterdump())


def _first_migration_route(cli, ctx, home, destination, storage, policy):
    """A guessed binding must not turn retained legacy inventory into empty success."""
    native = (home / 'config.yaml').read_bytes()
    history = _history(storage, policy)
    assert not destination.exists()
    refused = cli(['status'], 2)
    try:
        ctx.set_config('policy', {'store': {'shared_sqlite_path': str(destination)}})
        bound = (home / 'config.yaml').read_bytes()
        for argv in (['status'], ['query'], ['create', '--name', 'Must not mask retained inventory']):
            result = cli(argv, 2)
            assert 'selected store is absent' in result['error'], result
            assert not result['persisted'] and not result['applied']
        hermes = shutil.which('hermes')
        assert hermes is not None
        cold = subprocess.run([hermes, 'network-atlas', 'status'], cwd=home.parent, env=os.environ.copy(),
                              input='', capture_output=True, text=True, timeout=45)
        assert cold.returncode == 2, cold.stdout + cold.stderr
        assert 'selected store is absent' in json.loads(cold.stdout)['error']
        assert (home / 'config.yaml').read_bytes() == bound
        assert not destination.exists()
    finally:
        (home / 'config.yaml').write_bytes(native)
    assert 'managed destination is absent' in refused['error'], refused
    assert 'first migration' in refused['error'] and 'deleted' in refused['error']
    assert ctx.get_config('policy', None) == {}
    assert _history(storage, policy) == history


def _writer_overlap(cli, conversion, storage, core, policy, destination):
    """Commit real producer history after copy validation, not a fabricated dump."""
    action = ['convert-legacy', '--writers-stopped', '--accept-legacy-policy']
    before = _history(storage, policy)
    real_fsync = conversion.os.fsync
    written = []

    def commit_writer():
        with storage.Store(policy, writable=True) as writer:
            written.append(core.create_device(writer, 'Concurrent legacy writer')['device_id'])
        assert Path(str(policy.database) + '-wal').stat().st_size > 0

    def fsync_then_write(fd):
        real_fsync(fd)
        if not written:
            commit_writer()

    # Both fingerprints already agree when the real fsync callback permits this
    # otherwise-valid writer. Initial-only comparison used to report success.
    with patch.object(conversion.os, 'fsync', side_effect=fsync_then_write):
        result = cli(action, 2)
    assert 'source changed' in result['error'], result
    assert len(written) == 1
    assert not destination.exists()
    assert list(destination.parent.glob('.atlas-convert-*')) == []
    after = _history(storage, policy)
    assert set(before) < set(after)
    # An earlier write must also refuse; it may be detected by backup comparison.
    real_fingerprint = conversion._fingerprint
    def fingerprint_then_write(connection, deadline):
        result = real_fingerprint(connection, deadline)
        if len(written) == 1:
            commit_writer()
        return result
    with patch.object(conversion, '_fingerprint', side_effect=fingerprint_then_write):
        result = cli(action, 2)
    assert 'backup differs' in result['error'] or 'source changed' in result['error'], result
    assert len(written) == 2 and not destination.exists()
    assert list(destination.parent.glob('.atlas-convert-*')) == []
    assert set(after) < set(_history(storage, policy))
    # Produce an equal completed copy through the real converter, stopping only
    # before native settings. Reuse needs the same final source-change guard.
    real_copy = conversion._copy_store
    def publish_then_interrupt(*args):
        real_copy(*args)
        raise OSError('synthetic interruption before settings commit')
    with patch.object(conversion, '_copy_store', side_effect=publish_then_interrupt):
        cli(action, 2)
    copied = _history(storage, replace(policy, database=destination))
    assert copied == _history(storage, policy)
    destination_bytes = destination.read_bytes()
    def existing_fingerprint_then_write(connection, deadline):
        result = real_fingerprint(connection, deadline)
        database = Path(connection.execute('PRAGMA database_list').fetchone()[2])
        if database == destination:
            commit_writer()
        return result
    with patch.object(conversion, '_fingerprint', side_effect=existing_fingerprint_then_write):
        result = cli(action, 2)
    assert 'source changed' in result['error'], result
    assert len(written) == 3
    assert destination.read_bytes() == destination_bytes
    assert _history(storage, replace(policy, database=destination)) == copied
    return {'source': _history(storage, policy), 'destination': copied}


def _hard_kill(cli, conversion, storage, policy, destination, home):
    """Kill only our actual native converter child while its stage is unpublished."""
    foreign = destination.parent / '.atlas-convert-foreign.sqlite3'
    foreign.write_bytes(b'UNKNOWN_FOREIGN_COPY')
    original = {path.name: path.read_bytes() for path in policy.database.parent.iterdir()
                if path.is_file() and not path.name.endswith('-shm')}
    history = _history(storage, policy)
    ready = home.parent / 'conversion-kill-ready.json'
    child = subprocess.Popen([sys.executable, str(Path(__file__).with_name('runtime_smoke.py')),
                              sys.argv[1], 'conversion_kill_child'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 20
        while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready.exists(), 'owned converter did not reach prepublication staging'
        temporary = Path(json.loads(ready.read_text())['temporary'])
        assert temporary.parent == destination.parent
        assert temporary.name.startswith('.atlas-convert-') and temporary.suffix == '.sqlite3'
        assert not destination.exists()
        assert _history(storage, replace(policy, database=temporary)) == history
        child.kill()
        stdout, stderr = child.communicate(timeout=10)
        assert child.returncode == -signal.SIGKILL, stdout + stderr
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=10)
    assert temporary.exists(), 'SIGKILL cannot run the converter finally block'
    assert foreign.read_bytes() == b'UNKNOWN_FOREIGN_COPY'
    assert original == {path.name: path.read_bytes() for path in policy.database.parent.iterdir()
                        if path.is_file() and not path.name.endswith('-shm')}
    assert _history(storage, policy) == history
    assert not destination.exists()
    return {'temporary': str(temporary), 'digest': hashlib.sha256(temporary.read_bytes()).hexdigest(),
            'foreign': str(foreign)}


def run_conversion(mode, home, manager):
    from plugins.plugin_storage import plugin_data_dir

    loaded = next(item for item in manager._plugins.values() if item.manifest.name == 'network-atlas')
    assert loaded.module is not None
    package = loaded.module.__name__
    config, conversion, storage, core, updates, batches, reconcile = (
        importlib.import_module(package + '.' + name)
        for name in ('config', 'conversion', 'storage', 'core', 'updates', 'batches', 'reconcile'))
    entry = manager._cli_commands['network-atlas']
    ctx = entry['handler_fn'].keywords['ctx']
    parser = argparse.ArgumentParser(allow_abbrev=False)
    entry['setup_fn'](parser)

    def cli(argv, code=0):
        output = io.StringIO()
        with redirect_stdout(output):
            result = entry['handler_fn'](parser.parse_args(argv))
        assert result == code, output.getvalue()
        return json.loads(output.getvalue())

    action = ['convert-legacy', '--writers-stopped', '--accept-legacy-policy']
    legacy = home / 'network-atlas' / 'atlas.sqlite3'
    destination = plugin_data_dir('network-atlas').resolve() / 'atlas.sqlite3'
    saved = home.parent / 'conversion.json'
    if mode == 'conversion_kill_child':
        def wait_before_publication(temporary, target):
            assert Path(target) == destination
            ready = home.parent / 'conversion-kill-ready.json'
            pending = ready.with_suffix('.pending')
            pending.write_text(json.dumps({'temporary': str(temporary)}))
            # The parent treats existence as readiness, so publish only complete JSON.
            os.replace(pending, ready)
            while True:
                signal.pause()
        with patch.object(conversion.os, 'link', side_effect=wait_before_publication):
            cli(action)
        raise AssertionError('owned converter must be killed before publication')
    if mode in {'conversion', 'conversion_overlap', 'conversion_hardkill'}:
        raw = conversion.read_legacy(home)
        assert ctx.get_config('policy', None) == {}
        native_config = (home / 'config.yaml').read_bytes()
        policy = replace(config.validate_policy(raw, home), database=legacy)
        with storage.Store(policy, writable=True) as store:
            store.connection.execute('PRAGMA wal_autocheckpoint=0')
            device = core.create_device(store, 'Synthetic conversion router')['device_id']
            receipt = core.apply_update(store, updates.operator_update({
                'device_id': device, 'field': 'ssh_alias', 'value': 'lab-router'}, policy))
            at = storage.timestamp(storage.utc_now())
            batch = batches.store_batch(store, 'local_passive', 'lab', at, at, 'partial', (
                batches.Probe('ip_addr', 'success', at, at, 'local_host', policy.networks[0].cidr, 'local_interface'),
                batches.Probe('ip_neigh', 'unavailable', at, at, 'none', '', 'none', 'missing_executable'),))
            application = reconcile.reconcile(policy, {'batch_id': batch})
            assert Path(str(legacy) + '-wal').stat().st_size > 0
            history = list(store.connection.iterdump())
            original = {path.name: path.read_bytes() for path in legacy.parent.iterdir()
                        if path.is_file() and not path.name.endswith('-shm')}
            assert 'legacy store' in cli(['query'], 2)['error']
            with (patch.object(conversion, '_copy_store', side_effect=AssertionError('copy before consent')),
                  patch.object(type(ctx), 'set_config', side_effect=AssertionError('settings before consent'))):
                refused = cli(['convert-legacy', '--writers-stopped'], 2)
            assert '--accept-legacy-policy' in refused['error']
            assert (home / 'config.yaml').read_bytes() == native_config
            assert not destination.exists()
            if mode == 'conversion':
                _first_migration_route(cli, ctx, home, destination, storage, policy)
            if mode != 'conversion':
                if mode == 'conversion_overlap':
                    data = _writer_overlap(cli, conversion, storage, core, policy, destination)
                else:
                    data = _hard_kill(cli, conversion, storage, policy, destination, home)
                assert (home / 'config.yaml').read_bytes() == native_config
                assert ctx.get_config('policy', None) == {}
                saved.write_text(json.dumps({'device': device, 'batch': batch, 'receipt': receipt,
                                             'history': history, 'raw': raw, 'application': application,
                                             'adversarial': data}))
                manager.unload()
                print(json.dumps({'mode': mode, 'native_conversion': True}))
                return 0
            # A pre-publication failure must remove only its temporary copy.
            with patch.object(conversion.os, 'link', side_effect=OSError('synthetic publish interruption')) as publish:
                assert not cli(action, 2)['persisted']
            publish.assert_called_once()
            assert not destination.exists()
            assert list(destination.parent.glob('.atlas-convert-*')) == []
            # A divergent destination is never overwritten or silently selected.
            with storage.Store(config.validate_policy({}, home, data_dir=destination.parent), writable=True) as other:
                core.create_device(other, 'Independent conflicting inventory')
            conflict_bytes = destination.read_bytes()
            assert 'conflicts' in cli(action, 2)['error']
            assert destination.read_bytes() == conflict_bytes
            destination.unlink()
            # A nonempty native policy is also a conflict, before DB publication.
            try:
                ctx.set_config('policy', {'render': {'include_addresses': False}})
                assert 'conflicts' in cli(action, 2)['error']
                assert not destination.exists()
            finally:
                # {} merges rather than clears native settings. Restore the
                # complete synthetic input, not a mocked settings result.
                (home / 'config.yaml').write_bytes(native_config)
            assert ctx.get_config('policy', None) == {}
            with patch.object(type(ctx), 'set_config', side_effect=OSError('synthetic settings-write interruption')):
                assert not cli(action, 2)['persisted']
            assert destination.exists(), 'interruption must follow DB publication'
            assert ctx.get_config('policy', None) == {}, 'interruption must precede native settings commit'
            refused = cli(['status'], 2)
            assert 'managed destination exists' in refused['error']
            assert 'does not prove conversion' in refused['error']
            assert original == {path.name: path.read_bytes() for path in legacy.parent.iterdir()
                                if path.is_file() and not path.name.endswith('-shm')}
            # Producer rows, triggers, IDs, receipts and ownership must all survive.
            with storage.Store(replace(policy, database=destination)) as copied:
                assert list(copied.connection.iterdump()) == history
                assert copied.schema_version == store.schema_version
            saved.write_text(json.dumps({'device': device, 'batch': batch, 'receipt': receipt,
                                         'history': history, 'raw': raw, 'application': application}))
    else:
        data = json.loads(saved.read_text())
        assert 'legacy store' in cli(['query'], 2)['error']
        if mode == 'conversion_overlap_reopen':
            native_config = (home / 'config.yaml').read_bytes()
            policy = replace(config.validate_policy(data['raw'], home), database=legacy)
            assert 'conflicts' in cli(action, 2)['error']
            assert _history(storage, policy) == data['adversarial']['source']
            assert _history(storage, replace(policy, database=destination)) == data['adversarial']['destination']
            assert (home / 'config.yaml').read_bytes() == native_config
            manager.unload()
            print(json.dumps({'mode': mode, 'fresh_native_process_persistence': True}))
            return 0
        # A completed DB copy is not evidence that its grants remain intended.
        native_config = (home / 'config.yaml').read_bytes()
        assert '--accept-legacy-policy' in cli(['convert-legacy', '--writers-stopped'], 2)['error']
        assert (home / 'config.yaml').read_bytes() == native_config
        result = cli(action)
        assert result['converted'] and result['originals_retained']
        assert result['copied'] == (mode == 'conversion_hardkill_reopen')
        if mode == 'conversion_hardkill_reopen':
            remnant = data['adversarial']
            assert hashlib.sha256(Path(remnant['temporary']).read_bytes()).hexdigest() == remnant['digest']
            assert Path(remnant['foreign']).read_bytes() == b'UNKNOWN_FOREIGN_COPY'
        converted = {**data['raw'], 'store': {'shared_sqlite_path': str(destination)}}
        assert ctx.get_config('policy', None) == converted
        assert cli(['query'])['devices'][0]['id'] == data['device']
        assert cli(['status'])['authorized_for_atlas_ssh_inspection'] == ['lab-router']
        assert cli(['reconcile', '--batch-id', data['batch']]) == data['application']
        assert not cli(['convert-legacy', '--writers-stopped'])['copied']
        policy = config.load_policy(ctx)
        assert policy.home == home
        assert policy.database == destination
        assert policy.exports == home / 'network-atlas' / 'exports'
        with storage.Store(policy) as copied:
            assert list(copied.connection.iterdump()) == data['history']
            assert {row[0] for row in copied.connection.execute('SELECT DISTINCT policy_context FROM batches')} == {
                str(home)}
        # Explicit sharing is policy conversion only, including a legacy-location
        # binding: never make a private copy or rewrite source ownership.
        shared_home = home.parent / 'conversion-shared-reader'
        shared_link = home.parent / 'explicit-shared-link.sqlite3'
        shared_link.symlink_to(legacy)
        shared_raw = {'store': {'shared_sqlite_path': str(shared_link)}}
        (shared_home / 'network-atlas').mkdir(parents=True)
        layout = os.environ.get('NETWORK_ATLAS_TEST_DATA_LAYOUT')
        if layout is not None:
            symlink_plugin_data(shared_home, layout)
        (shared_home / 'network-atlas' / 'config.yaml').write_text(json.dumps(shared_raw))
        with patch.dict(os.environ, {'HERMES_HOME': str(shared_home)}):
            result = cli(action)
            assert result['shared_store_retained'] and not result['copied']
            assert ctx.get_config('policy', {}) == shared_raw
            assert cli(['query'])['devices'][0]['id'] == data['device']
            assert cli(['status'])['authorized_for_atlas_ssh_inspection'] == []
            refused = cli(['reconcile', '--batch-id', data['batch']], 2)
            assert not refused['applied']
            assert not (shared_home / 'plugin-data' / 'network-atlas' / 'atlas.sqlite3').exists()
        with storage.Store(replace(policy, database=legacy)) as source:
            assert list(source.connection.iterdump()) == data['history']
        # Once native inventory evolves, conversion must not replay old bytes.
        cli(['create', '--name', 'Native successor'])
        assert 'conflicts' in cli(action, 2)['error']
        assert len(cli(['query'])['devices']) == 2
    manager.unload()
    print(json.dumps({'mode': mode, 'native_conversion': True,
                      'fresh_native_process_persistence': mode != 'conversion'}))
    return 0
