# SPDX-License-Identifier: GPL-3.0-or-later
"""Populated legacy/WAL conversion through the actual registered native CLI."""
from contextlib import redirect_stdout
from dataclasses import replace
import argparse
import importlib
import io
import json
import os
from pathlib import Path
from unittest.mock import patch


def run_conversion(mode, home, manager):
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

    action = ['convert-legacy', '--writers-stopped']
    legacy = home / 'network-atlas' / 'atlas.sqlite3'
    destination = home / 'plugin-data' / 'network-atlas' / 'atlas.sqlite3'
    saved = home.parent / 'conversion.json'
    if mode == 'conversion':
        raw = ctx.get_config('policy', {})
        (home / 'network-atlas' / 'config.yaml').write_text(json.dumps(raw))
        ctx.set_config('policy', {})
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
            # A pre-publication failure must remove only its temporary copy.
            with patch.object(conversion.os, 'link', side_effect=OSError('synthetic publish interruption')):
                assert not cli(action, 2)['persisted']
            assert not destination.exists()
            assert list(destination.parent.glob('.atlas-convert-*')) == []
            # A divergent destination is never overwritten or silently selected.
            with storage.Store(config.validate_policy({}, home), writable=True) as other:
                core.create_device(other, 'Independent conflicting inventory')
            conflict_bytes = destination.read_bytes()
            assert 'conflicts' in cli(action, 2)['error']
            assert destination.read_bytes() == conflict_bytes
            destination.unlink()
            # A nonempty native policy is also a conflict, before DB publication.
            ctx.set_config('policy', {'render': {'include_addresses': False}})
            assert 'conflicts' in cli(action, 2)['error']
            assert not destination.exists()
            ctx.set_config('policy', {})
            real_copy = conversion._copy_store
            def publish_then_interrupt(*args):
                real_copy(*args)
                raise OSError('synthetic interruption before settings commit')
            with patch.object(conversion, '_copy_store', publish_then_interrupt):
                assert not cli(action, 2)['persisted']
            assert destination.exists() and ctx.get_config('policy', None) == {}
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
        result = cli(action)
        assert result['converted'] and not result['copied'] and result['originals_retained']
        assert ctx.get_config('policy', {})['store']['shared_sqlite_path'] == str(destination)
        assert cli(['query'])['devices'][0]['id'] == data['device']
        assert cli(['status'])['authorized_for_atlas_ssh_inspection'] == ['lab-router']
        assert cli(['reconcile', '--batch-id', data['batch']]) == data['application']
        assert not cli(action)['copied']
        policy = config.load_policy(ctx)
        with storage.Store(policy) as copied:
            assert list(copied.connection.iterdump()) == data['history']
        # Explicit sharing is policy conversion only, including a legacy-location
        # binding: never make a private copy or rewrite source ownership.
        shared_home = home.parent / 'conversion-shared-reader'
        shared_link = home.parent / 'explicit-shared-link.sqlite3'
        shared_link.symlink_to(legacy)
        shared_raw = {'store': {'shared_sqlite_path': str(shared_link)}}
        (shared_home / 'network-atlas').mkdir(parents=True)
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
