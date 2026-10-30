#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Actual native clones and filesystem defaults, only in test_runtime's owned homes."""
from contextlib import closing
from dataclasses import replace
import importlib
import json
import os
from pathlib import Path
import shlex
import shutil
import sqlite3
import stat
import subprocess
import sys
from unittest.mock import patch

from cumulative_acceptance import NativeAtlas
from native_conversion import _history
from network_guard import deny_network


def _replace_policy(atlas, raw):
    """Use the native replacing CLI; set_config merges omitted store/grant keys."""
    hermes = shutil.which('hermes')
    assert hermes is not None
    result = subprocess.run([hermes, 'config', 'set', 'plugins.entries.network-atlas.settings.policy', json.dumps(raw)],
                            cwd=os.environ['TMPDIR'], env=os.environ.copy(), input='', capture_output=True,
                            text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
    assert atlas.ctx.get_config('policy', None) == raw


def _documented_stop(atlas, home, binding, backup):
    """Run the guide's private-copy and replacing-stop commands in this owned home."""
    from hermes_constants import profile_name_for_home
    from hermes_cli.profiles import get_profile_dir

    profile = profile_name_for_home(home)
    assert profile is not None and get_profile_dir(profile).resolve() == home.resolve()
    guide = (Path(__file__).resolve().parents[1] / 'docs' / 'operator-guide.md').read_text()
    section = guide.split('### Stop collection offline', 1)[1].split('### ', 1)[0]
    snippet = section.split('```sh\n')[2].split('```', 1)[0]
    for template, path in (('/absolute/selected/profile-home', home),
                           ('/absolute/configured/atlas.sqlite3', binding),
                           ('/absolute/selected/database-file', binding.resolve()),
                           ('/absolute/private/atlas-backup-UNIQUE', backup)):
        snippet = snippet.replace(template, shlex.quote(str(path)))
    # Verify the copy before the subsequent native policy replacement changes config.
    copy, stop = snippet.split('hermes -p PROFILE config set', 1)
    original = (home / 'config.yaml').read_bytes()
    mode = stat.S_IMODE((home / 'config.yaml').stat().st_mode)
    env = {**os.environ, 'ATLAS_HOME': str(home), 'ATLAS_BINDING': str(binding),
           'ATLAS_DB': str(binding.resolve()), 'BACKUP': str(backup)}
    result = subprocess.run(['sh', '-ec', copy.rstrip().removesuffix('&&')],
                            cwd=home.parent, env=env, capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (home / 'config.yaml').read_bytes() == original
    assert stat.S_IMODE((home / 'config.yaml').stat().st_mode) == mode
    assert (backup / 'config.yaml').read_bytes() == original
    assert stat.S_IMODE((backup / 'config.yaml').stat().st_mode) == 0o600
    assert stat.S_IMODE(backup.stat().st_mode) == 0o700
    result = subprocess.run(['sh', '-ec', ('hermes -p PROFILE config set' + stop).replace('PROFILE', profile)],
                            cwd=home.parent, env=env, capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    stopped = atlas.cli(['status'])
    assert stopped['database_binding']['database_path'] == str(binding.resolve())
    assert stopped['configured_networks'] == stopped['authorized_for_atlas_ssh_inspection'] == []


def _documented_backup(database, backup):
    """Execute the maintained SQLite backup snippet, not a second implementation."""
    guide = (Path(__file__).resolve().parents[1] / 'docs' / 'operator-guide.md').read_text()
    section = guide.split('### Back up retained data before removal or reset', 1)[1]
    snippet = section.split('```sh\n', 1)[1].split('```', 1)[0]
    result = subprocess.run(['sh', '-ec', snippet], cwd=backup.parent,
                            env={**os.environ, 'ATLAS_DB': str(database), 'BACKUP': str(backup)},
                            capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
    destination = backup / 'atlas.sqlite3'
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    return destination


def _pending_batch(storage, batches, policy):
    """Produce real saved evidence bound to the resolved caller home, without traffic."""
    at = storage.timestamp(storage.utc_now())
    with storage.Store(policy, writable=True) as store:
        return batches.store_batch(store, 'local_passive', 'lab', at, at, 'partial', (
            batches.Probe('ip_addr', 'success', at, at, 'local_host', policy.networks[0].cidr, 'local_interface'),
            batches.Probe('ip_neigh', 'unavailable', at, at, 'none', '', 'none', 'missing_executable'),))


def _binding_status(atlas, config, storage, home, database, known_devices):
    """Observe the selected binding without writes, contact or model-path disclosure."""
    policy = config.load_policy(atlas.ctx)
    assert policy.home == home and policy.database == database
    history = _history(storage, policy) if database.exists() else None
    parent_exists = database.parent.exists()
    before = {path: path.read_bytes() for path in database.parent.glob('*') if path.is_file()}
    native_config = (home / 'config.yaml').read_bytes()
    original = storage.Store.__init__

    def read_only_store(self, selected, **kwargs):
        assert not kwargs.get('writable', False), 'status attempted a writable store'
        return original(self, selected, **kwargs)

    with (patch.object(storage.Store, '__init__', read_only_store),
          patch.object(type(atlas.ctx), 'set_config', side_effect=AssertionError('status changed settings')),
          patch('subprocess.Popen', side_effect=AssertionError('status executed a process')),
          patch('socket.socket', side_effect=AssertionError('status opened a socket'))):
        operator = atlas.cli(['status'])
        assert operator.pop('database_binding') == {'profile_home': str(home), 'database_path': str(database)}
        assert operator['known_devices'] == known_devices
        # Slash provenance is not attested; only the separate local operator
        # status adapter may add binding paths. Existing batch policy_context
        # provenance remains unchanged on the model/slash/query views.
        for result in (atlas.tool('network_query', {'view': 'status'}), atlas.slash('status'),
                       atlas.cli(['query', '--query-json', '{"view":"status"}'])):
            assert result == operator
            assert str(database) not in json.dumps(result)
        refused = atlas.tool('network_query', {'view': 'status', 'database_path': str(database)})
        assert 'error' in refused and str(database) not in json.dumps(refused)
    assert database.parent.exists() == parent_exists
    assert {path: path.read_bytes() for path in database.parent.glob('*') if path.is_file()} == before
    assert (home / 'config.yaml').read_bytes() == native_config
    assert (_history(storage, policy) if database.exists() else None) == history


def _clone_binding(atlas, home, config, storage, batches):
    from hermes_cli.profiles import create_profile, get_profile_dir

    conversion = importlib.import_module(config.__package__ + '.conversion')
    core = importlib.import_module(config.__package__ + '.core')
    raw = conversion.read_legacy(home)
    legacy = replace(config.validate_policy(raw, home), database=home / 'network-atlas' / 'atlas.sqlite3')
    with storage.Store(legacy, writable=True) as store:
        device = core.create_device(store, 'Converted source')['device_id']
    batch = _pending_batch(storage, batches, legacy)
    history = _history(storage, legacy)
    assert atlas.cli(['convert-legacy', '--writers-stopped', '--accept-legacy-policy'])['converted']
    policy = config.load_policy(atlas.ctx)
    assert _history(storage, policy) == history
    converted = atlas.ctx.get_config('policy', None)
    assert converted == {**raw, 'store': {'shared_sqlite_path': str(policy.database)}}
    _binding_status(atlas, config, storage, home, policy.database, 1)
    atlas.cli(['map', '--format', 'markdown', '--export'])
    source_exports = {path: path.read_bytes() for path in policy.exports.iterdir()}
    assert get_profile_dir('atlas-clone').is_relative_to(home)
    clone = create_profile('atlas-clone', clone_config=True, no_alias=True)
    assert clone == home / 'profiles' / 'atlas-clone'
    assert (clone / 'plugins' / 'network-atlas' / 'plugin.yaml').is_file()
    source_config = (home / 'config.yaml').read_bytes()
    local_database = clone / 'plugin-data' / 'network-atlas' / 'atlas.sqlite3'
    with patch.dict(os.environ, {'HERMES_HOME': str(clone)}):
        assert atlas.ctx.get_config('policy', None) == converted
        inherited = config.load_policy(atlas.ctx)
        assert inherited.home == clone.resolve() and inherited.database == policy.database
        assert inherited.exports == clone / 'network-atlas' / 'exports'
        _binding_status(atlas, config, storage, clone, policy.database, 1)
        assert atlas.tool('network_query', {})['devices'][0]['id'] == device
        status = atlas.cli(['status'])
        assert status['configured_networks'] == ['lab']
        assert status['authorized_for_atlas_ssh_inspection'] == ['lab-router']
        assert not atlas.cli(['reconcile', '--batch-id', batch], expected_code=2)['applied']
        shared_device = atlas.cli(['create', '--name', 'Clone shared write'])['device_id']
        clone_batch = _pending_batch(storage, batches, inherited)
        assert not local_database.exists(), 'inherited absolute binding must not silently split history'
        with storage.Store(inherited) as store:
            owners = {row[0] for row in store.connection.execute('SELECT DISTINCT policy_context FROM batches')}
            assert owners == {str(home), str(clone)}
        # A real clone's external selection is the parent's store, never a reset target.
        shared_history = _history(storage, policy)
        shared_bytes = policy.database.read_bytes()
        assert not policy.database.is_relative_to(clone.resolve())
        (clone / 'config.yaml').chmod(0o644)
        _documented_stop(atlas, clone, policy.database, home.parent / 'clone-stop-backup')
        assert atlas.ctx.get_config('policy', None) == {'store': converted['store']}
        _binding_status(atlas, config, storage, clone, policy.database, 2)
        assert len(atlas.tool('network_query', {})['devices']) == 2
        assert atlas.cli(['status'])['configured_networks'] == []
        assert atlas.cli(['status'])['authorized_for_atlas_ssh_inspection'] == []
        with patch('subprocess.Popen', side_effect=AssertionError('stopped clone attempted collection')):
            assert 'error' in atlas.tool('network_discover', {'network': 'lab', 'mode': 'passive'})
            assert 'error' in atlas.tool('network_inspect', {'target': 'lab-router'})
        _replace_policy(atlas, {})
        _binding_status(atlas, config, storage, clone, local_database, 0)
        assert atlas.cli(['status'])['configured_networks'] == []
        assert atlas.cli(['status'])['authorized_for_atlas_ssh_inspection'] == []
        assert atlas.cli(['query'])['devices'] == []
        assert (home / 'config.yaml').read_bytes() == source_config
        assert policy.database.read_bytes() == shared_bytes
        assert _history(storage, policy) == shared_history
        assert {path: path.read_bytes() for path in policy.exports.iterdir()} == source_exports
        # Omit store through the replacing writer: this deliberately selects NEW empty local history.
        _replace_policy(atlas, raw)
        rebound = config.load_policy(atlas.ctx)
        assert rebound.home == clone and rebound.database == local_database
        _binding_status(atlas, config, storage, clone, local_database, 0)
        assert not local_database.exists()
        assert atlas.tool('network_query', {})['devices'] == []
        local_device = atlas.cli(['create', '--name', 'Deliberately independent clone'])['device_id']
        _binding_status(atlas, config, storage, clone, local_database, 1)
        assert atlas.cli(['query'])['devices'][0]['id'] == local_device
        assert _history(storage, policy) == shared_history
        # Ordinary config-only clones of a no-store profile do not copy its populated local DB.
        ordinary = create_profile('atlas-local-clone', clone_config=True, no_alias=True)
        assert ordinary == home / 'profiles' / 'atlas-local-clone'
        with patch.dict(os.environ, {'HERMES_HOME': str(ordinary)}):
            ordinary_policy = config.load_policy(atlas.ctx)
            assert ordinary_policy.home == ordinary
            assert ordinary_policy.database == ordinary / 'plugin-data' / 'network-atlas' / 'atlas.sqlite3'
            _binding_status(atlas, config, storage, ordinary, ordinary_policy.database, 0)
            assert not ordinary_policy.database.exists()
            assert atlas.cli(['query'])['devices'] == []
            independent = atlas.cli(['create', '--name', 'Ordinary local clone'])['device_id']
            _binding_status(atlas, config, storage, ordinary, ordinary_policy.database, 1)
            assert atlas.tool('network_query', {})['devices'][0]['id'] == independent
            ordinary_config = (ordinary / 'config.yaml').read_bytes()
            ordinary_bytes = ordinary_policy.database.read_bytes()
        # Deliberate explicit binding to an absent external target is visible,
        # but status must neither create it nor disturb either existing store.
        absent = home.parent / 'absent-shared' / 'atlas.sqlite3'
        _replace_policy(atlas, {'store': {'shared_sqlite_path': str(absent)}})
        # Native managed storage exists; the selected external parent need not.
        assert not absent.parent.exists()
        _binding_status(atlas, config, storage, clone, absent, 0)
        assert not absent.parent.exists()
        _replace_policy(atlas, raw)
        assert atlas.cli(['query'])['devices'][0]['id'] == local_device
        assert (ordinary / 'config.yaml').read_bytes() == ordinary_config
        assert ordinary_policy.database.read_bytes() == ordinary_bytes
        assert _history(storage, policy) == shared_history
    assert {item['id'] for item in atlas.cli(['query'])['devices']} == {device, shared_device}
    assert not atlas.cli(['reconcile', '--batch-id', clone_batch], expected_code=2)['applied']
    assert (home / 'config.yaml').read_bytes() == source_config
    assert {path: path.read_bytes() for path in policy.exports.iterdir()} == source_exports
    assert _history(storage, legacy) == history
    return {'native_clone_binding': True, 'source_home': str(home), 'clone_home': str(clone),
            'shared_database': str(policy.database), 'rebound_database': str(local_database)}


def _privacy(atlas, home, config, storage, mask):
    directories = [home / 'plugin-data', home / 'plugin-data' / 'network-atlas']
    assert not any(path.exists() for path in directories)
    assert atlas.tool('network_query', {})['devices'] == []
    policy = config.load_policy(atlas.ctx)
    assert not policy.database.exists(), 'native directory creation is not DB initialization'
    modes = [oct(stat.S_IMODE(path.stat().st_mode)) for path in directories]
    assert modes == [oct(0o777 & ~mask)] * 2, modes
    atlas.cli(['create', '--name', 'Native privacy fixture'])
    assert stat.S_IMODE(policy.database.stat().st_mode) == 0o600
    assert [oct(stat.S_IMODE(path.stat().st_mode)) for path in directories] == modes
    assert {path.stat().st_uid for path in [*directories, policy.database]} == {os.getuid()}
    assert os.getuid() != 0, 'native privacy evidence requires the supported non-root runtime'
    with storage.Store(policy) as store:
        assert store.connection.execute('SELECT COUNT(*) FROM devices').fetchone()[0] == 1
    return {'umask': oct(mask), 'directory_modes': modes, 'database_mode': oct(0o600), 'uid': os.getuid()}


def _refuse_legacy_regrant(atlas, home, storage, policy):
    """Missing native policy is not consent, even with a valid retained copy."""
    conversion = importlib.import_module(storage.__package__ + '.conversion')
    native = (home / 'config.yaml').read_bytes()
    history = _history(storage, policy)
    with (patch.object(conversion, '_copy_store', side_effect=AssertionError('copy before legacy consent')),
          patch.object(type(atlas.ctx), 'set_config', side_effect=AssertionError('settings before legacy consent'))):
        refused = atlas.cli(['convert-legacy', '--writers-stopped'], expected_code=2)
    assert not refused['persisted'] and not refused['applied']
    assert '--accept-legacy-policy' in refused['error'] and 'revoked collection grants' in refused['error']
    for result in (atlas.cli(['status'], expected_code=2), atlas.tool('network_query', {'view': 'status'}),
                   atlas.slash('status')):
        assert 'binding-only recovery' in result['error'] and 'revoked collection grants' in result['error']
    assert (home / 'config.yaml').read_bytes() == native
    assert _history(storage, policy) == history


def _retained_reinstall(atlas, home, config, storage, policy):
    """Exercise native removal/selection offline, not the network-dependent installer."""
    from hermes_cli.config import load_config
    from hermes_cli.plugins_cmd import cmd_remove
    from hermes_constants import profile_name_for_home
    from plugins.plugin_storage import plugin_data_dir
    from helpers import copy_plugin

    cmd_remove('network-atlas')
    plugins = load_config()['plugins']
    assert 'network-atlas' not in plugins.get('entries', {})
    assert 'network-atlas' not in plugins.get('enabled', [])
    assert atlas.ctx.get_config('policy', None) is None
    plugin = home / 'plugins' / 'network-atlas'
    assert not plugin.exists()
    # Restore only fixture plugin files; no online install/PM resync is claimed.
    copy_plugin(plugin)
    _refuse_legacy_regrant(atlas, home, storage, policy)
    # Missing notes: derive the unchanged conversion selection without converting
    # or importing its legacy grants into native settings.
    conversion = importlib.import_module(config.__package__ + '.conversion')
    raw = conversion.read_legacy(home)
    data = plugin_data_dir('network-atlas').resolve()
    recovered = config.validate_policy(raw, home, data_dir=data)
    assert recovered.database.resolve() == policy.database
    binding = Path(raw.get('store', {}).get('shared_sqlite_path', str(data / 'atlas.sqlite3')))
    assert binding.suffix == '.sqlite3' and binding.resolve() == policy.database
    hermes = shutil.which('hermes')
    assert hermes is not None
    profile = profile_name_for_home(home)
    assert profile is not None
    # Only offline native selection, not PM enable, dependency resolution or
    # gateway reload. Exercise the cold CLI before repairing the missing binding.
    selected = subprocess.run([hermes, 'config', 'set', 'plugins.enabled', '["network-atlas"]'],
                              cwd=home.parent, env=os.environ.copy(), input='', capture_output=True,
                              text=True, timeout=45)
    assert selected.returncode == 0, selected.stdout + selected.stderr
    native = (home / 'config.yaml').read_bytes()
    cold = subprocess.run([hermes, 'network-atlas', 'convert-legacy', '--writers-stopped'],
                          cwd=home.parent, env=os.environ.copy(), input='', capture_output=True,
                          text=True, timeout=45)
    assert cold.returncode == 2, cold.stdout + cold.stderr
    refused = json.loads(cold.stdout)
    assert '--accept-legacy-policy' in refused['error'] and 'revoked collection grants' in refused['error']
    assert not refused['persisted'] and not refused['applied']
    assert (home / 'config.yaml').read_bytes() == native
    guide = (Path(__file__).resolve().parents[1] / 'docs' / 'operator-guide.md').read_text()
    section = guide.split('### Re-enable or reinstall with retained data', 1)[1].split('### ', 1)[0]
    snippet = section.split('```sh\n')[2].split('```', 1)[0]
    snippet = snippet.replace('/absolute/configured/atlas.sqlite3', shlex.quote(str(binding)))
    snippet = snippet.replace('/absolute/selected/database-file', shlex.quote(str(policy.database)))
    # A derived path is not retained data. Losing the actual selected file must
    # refuse both the documented replacement and a mistakenly pre-bound runtime.
    history = _history(storage, policy)
    retained = home.parent / 'retained-reinstall-inventory.sqlite3'
    policy.database.rename(retained)
    try:
        missing = subprocess.run(['sh', '-ec', snippet.replace('PROFILE', profile)], cwd=home.parent,
                                 env=os.environ.copy(), capture_output=True, text=True, timeout=90)
        assert missing.returncode != 0, missing.stdout + missing.stderr
        assert (home / 'config.yaml').read_bytes() == native
        cold = subprocess.run([hermes, 'network-atlas', 'status'], cwd=home.parent, env=os.environ.copy(),
                              input='', capture_output=True, text=True, timeout=45)
        assert cold.returncode == 2, cold.stdout + cold.stderr
        unbound = json.loads(cold.stdout)
        assert 'deleted converted data' in unbound['error']
        assert 'uncertain' in unbound['error']
        _replace_policy(atlas, {'store': {'shared_sqlite_path': str(binding)}})
        with patch.object(
                storage, '_prepare_file', side_effect=AssertionError('replacement store attempted')) as prepare:
            for result in (atlas.cli(['status'], expected_code=2), atlas.tool('network_query', {}),
                           atlas.slash('status'), atlas.cli(['create', '--name', 'Not recovery'], expected_code=2)):
                assert not result['applied']
                assert 'selected store is absent' in result['error'], result
            prepare.assert_not_called()
        cold = subprocess.run([hermes, 'network-atlas', 'query'], cwd=home.parent, env=os.environ.copy(),
                              input='', capture_output=True, text=True, timeout=45)
        assert cold.returncode == 2, cold.stdout + cold.stderr
        refused = json.loads(cold.stdout)
        assert not refused['applied'] and not refused['persisted']
        assert 'selected store is absent' in refused['error']
        assert not policy.database.exists()
    finally:
        retained.rename(policy.database)
        (home / 'config.yaml').write_bytes(native)
    assert _history(storage, policy) == history
    # Existing candidates still require inventory verification, not an inference
    # that a managed filename proves conversion. A mismatched target cannot bind.
    unbound = atlas.cli(['status'], expected_code=2)
    assert 'uncertain' in unbound['error']
    unrelated = home.parent / 'unrelated.sqlite3'
    with storage.Store(replace(policy, database=unrelated), writable=True):
        pass
    unrelated_bytes = unrelated.read_bytes()
    wrong = snippet.replace('ATLAS_DB=' + shlex.quote(str(policy.database)),
                            'ATLAS_DB=' + shlex.quote(str(unrelated)))
    mismatched = subprocess.run(['sh', '-ec', wrong.replace('PROFILE', profile)], cwd=home.parent,
                               env=os.environ.copy(), capture_output=True, text=True, timeout=90)
    assert mismatched.returncode != 0, mismatched.stdout + mismatched.stderr
    assert (home / 'config.yaml').read_bytes() == native
    assert unrelated.read_bytes() == unrelated_bytes
    restored = subprocess.run(['sh', '-ec', snippet.replace('PROFILE', profile)], cwd=home.parent,
                              env=os.environ.copy(), capture_output=True, text=True, timeout=90)
    assert restored.returncode == 0, restored.stdout + restored.stderr
    assert 'network-atlas' in load_config()['plugins'].get('enabled', [])
    assert atlas.ctx.get_config('policy', None) == {'store': {'shared_sqlite_path': str(binding)}}
    cold = subprocess.run([hermes, 'network-atlas', 'status'], cwd=home.parent, env=os.environ.copy(),
                          input='', capture_output=True, text=True, timeout=45)
    assert cold.returncode == 0, cold.stdout + cold.stderr
    status = json.loads(cold.stdout)
    assert status['database_binding']['database_path'] == str(policy.database)
    assert status['configured_networks'] == status['authorized_for_atlas_ssh_inspection'] == []
    assert status['known_devices'] == 1
    cold = subprocess.run([hermes, 'network-atlas', 'query'], cwd=home.parent, env=os.environ.copy(),
                          input='', capture_output=True, text=True, timeout=45)
    assert cold.returncode == 0, cold.stdout + cold.stderr
    assert {item['id'] for item in json.loads(cold.stdout)['devices']} == {
        item['id'] for item in atlas.cli(['query'])['devices']}
    assert _history(storage, policy) == history


def _deliberate_converted_selection(atlas, home, config, storage, retained_binding):
    """Retained legacy state must not forbid a distinct new store or its owned reset."""
    original = atlas.ctx.get_config('policy', None)
    selected = home / 'deliberate-new.sqlite3'
    binding = home / 'deliberate-link.sqlite3'
    binding.symlink_to(selected)
    _replace_policy(atlas, {'store': {'shared_sqlite_path': str(binding)}})
    _binding_status(atlas, config, storage, home, selected, 0)
    assert not selected.exists()
    device = atlas.cli(['create', '--name', 'Deliberately separate inventory'])['device_id']
    assert {item['id'] for item in atlas.cli(['query'])['devices']} == {device}
    policy = config.load_policy(atlas.ctx)
    history = _history(storage, policy)
    backup_dir = home.parent / 'deliberate-store-backup'
    backup_dir.mkdir(mode=0o700)
    backup = _documented_backup(selected, backup_dir)
    assert _history(storage, replace(policy, database=backup)) == history
    # Every connection is closed. Reset only this exclusively owned synthetic
    # target while retaining the explicitly chosen binding and old legacy files.
    for suffix in ('', '-wal', '-shm', '-journal'):
        Path(str(selected) + suffix).unlink(missing_ok=True)
    _binding_status(atlas, config, storage, home, selected, 0)
    hermes = shutil.which('hermes')
    assert hermes is not None
    cold = subprocess.run([hermes, 'network-atlas', 'status'], cwd=home.parent, env=os.environ.copy(),
                          input='', capture_output=True, text=True, timeout=45)
    assert cold.returncode == 0, cold.stdout + cold.stderr
    status = json.loads(cold.stdout)
    assert status['known_devices'] == 0 and status['last_collection'] is None
    assert status['configured_networks'] == status['authorized_for_atlas_ssh_inspection'] == []
    assert status['database_binding']['database_path'] == str(selected)
    assert atlas.cli(['query'])['devices'] == [] and not selected.exists()
    successor = atlas.cli(['create', '--name', 'After deliberate reset'])['device_id']
    assert successor != device
    assert {item['id'] for item in atlas.cli(['query'])['devices']} == {successor}
    assert _history(storage, replace(policy, database=backup)) == history
    _replace_policy(atlas, original)
    assert atlas.ctx.get_config('policy', None) == {'store': {'shared_sqlite_path': str(retained_binding)}}


def _converted_stop(atlas, home, config, storage, batches, *, shared_binding, managed_file_link=False):
    """Reconversion after native revocation/removal must not silently restore grants."""
    from plugins.plugin_storage import plugin_data_dir

    conversion = importlib.import_module(config.__package__ + '.conversion')
    core = importlib.import_module(config.__package__ + '.core')
    raw = conversion.read_legacy(home)
    if shared_binding:
        shared = home.parent / 'shared'
        shared.mkdir()
        binding = shared / 'atlas.sqlite3'
        binding.symlink_to(shared / 'inventory.db')
        raw['store'] = {'shared_sqlite_path': str(binding)}
        (home / 'network-atlas' / 'config.yaml').write_text(json.dumps(raw))
    legacy = replace(config.validate_policy(raw, home), database=home / 'network-atlas' / 'atlas.sqlite3')
    with storage.Store(legacy, writable=True) as store:
        core.create_device(store, 'Converted stop inventory')
    _pending_batch(storage, batches, legacy)
    managed = plugin_data_dir('network-atlas').resolve() / 'atlas.sqlite3'
    if managed_file_link:
        # Conversion accepts a pre-existing managed file link when its actual
        # target already contains the identical legacy history.
        managed.symlink_to(home.parent / 'managed-inventory.db')
        with (closing(sqlite3.connect(legacy.database)) as source,
              closing(sqlite3.connect(managed.resolve())) as destination):
            source.backup(destination)
    if 'shared_sqlite_path' in raw.get('store', {}):
        shared = config.validate_policy(raw, home)
        assert shared.database.suffix == '.db'
        with (closing(sqlite3.connect(legacy.database)) as source,
              closing(sqlite3.connect(shared.database)) as destination):
            source.backup(destination)
    converted = atlas.cli(['convert-legacy', '--writers-stopped', '--accept-legacy-policy'])
    assert converted['converted']
    if managed_file_link:
        assert not converted['copied'] and managed.is_symlink()
    policy = config.load_policy(atlas.ctx)
    binding = Path(atlas.ctx.get_config('policy')['store']['shared_sqlite_path'])
    assert binding.suffix == '.sqlite3' and binding.resolve() == policy.database
    atlas.cli(['map', '--format', 'markdown', '--export'])
    exports = {path: path.read_bytes() for path in policy.exports.iterdir()}
    history = _history(storage, policy)
    legacy_bytes = legacy.database.read_bytes()
    legacy_config = (home / 'network-atlas' / 'config.yaml').read_bytes()
    (home / 'config.yaml').chmod(0o644)
    _documented_stop(atlas, home, binding, home.parent / 'converted-backup')
    backup = _documented_backup(policy.database, home.parent / 'converted-backup')
    assert _history(storage, replace(policy, database=backup)) == history
    backup_bytes = backup.read_bytes()
    assert atlas.ctx.get_config('policy', None) == {'store': {'shared_sqlite_path': str(binding)}}
    assert atlas.cli(['status'])['known_devices'] == 1
    # Recovery from the former empty-policy stop must not re-import the old grants.
    _replace_policy(atlas, {})
    _refuse_legacy_regrant(atlas, home, storage, policy)
    assert 'legacy store present' in atlas.cli(['status'], expected_code=2)['error']
    _documented_stop(atlas, home, binding, home.parent / 'converted-recovery-backup')
    # Repeating the stop on an already valid, grant-free policy stays harmless.
    _documented_stop(atlas, home, binding, home.parent / 'converted-stopped-backup')
    assert atlas.ctx.get_config('policy', None) == {'store': {'shared_sqlite_path': str(binding)}}
    with patch('subprocess.Popen', side_effect=AssertionError('stopped converted profile collected')):
        assert 'error' in atlas.tool('network_discover', {'network': 'lab', 'mode': 'passive'})
        assert 'error' in atlas.tool('network_inspect', {'target': 'lab-router'})
    _retained_reinstall(atlas, home, config, storage, policy)
    _binding_status(atlas, config, storage, home, policy.database, 1)
    with patch('subprocess.Popen', side_effect=AssertionError('reinstalled profile attempted collection')):
        assert 'error' in atlas.tool('network_discover', {'network': 'lab', 'mode': 'passive'})
        assert 'error' in atlas.tool('network_inspect', {'target': 'lab-router'})
    _deliberate_converted_selection(atlas, home, config, storage, binding)
    _binding_status(atlas, config, storage, home, policy.database, 1)
    assert _history(storage, policy) == history
    assert {path: path.read_bytes() for path in policy.exports.iterdir()} == exports
    assert backup.read_bytes() == backup_bytes
    assert legacy.database.read_bytes() == legacy_bytes
    assert (home / 'network-atlas' / 'config.yaml').read_bytes() == legacy_config
    return {'converted_stop_no_grants': True, 'retained_reinstall_no_grants': True}


def _reset_walkthrough(atlas, home, config, storage, batches, *, custom):
    """Back up populated native state, then reset only this owned, unshared selection."""
    from hermes_cli.profiles import create_profile

    raw = atlas.ctx.get_config('policy', None)
    shared = home.parent / 'shared.sqlite3'
    foreign = create_profile('atlas-retained', clone_config=True, no_alias=True)
    with patch.dict(os.environ, {'HERMES_HOME': str(foreign)}):
        _replace_policy(atlas, {**raw, 'store': {'shared_sqlite_path': str(shared)}})
        foreign_device = atlas.cli(['create', '--name', 'Retained shared inventory'])['device_id']
        _pending_batch(storage, batches, config.load_policy(atlas.ctx))
        atlas.cli(['map', '--format', 'markdown', '--export'])
        foreign_policy = config.load_policy(atlas.ctx)
        foreign_history = _history(storage, foreign_policy)
        foreign_exports = {path: path.read_bytes() for path in foreign_policy.exports.iterdir()}
    foreign_config, shared_bytes = (foreign / 'config.yaml').read_bytes(), shared.read_bytes()
    # Detaching this profile must preserve the shared store, not call it erased.
    _replace_policy(atlas, {'store': {'shared_sqlite_path': str(shared)}})
    assert atlas.cli(['query'])['devices'][0]['id'] == foreign_device
    selected = {**raw, 'store': {'shared_sqlite_path': str(home / 'custom.sqlite3')}} if custom else raw
    _replace_policy(atlas, selected)
    policy = config.load_policy(atlas.ctx)
    assert policy.database != shared and not policy.database.exists()
    atlas.cli(['create', '--name', 'Owned reset inventory'])
    backup = home.parent / 'private-backup'
    original_config = (home / 'config.yaml').read_bytes()
    # Separate robustness contrast: deliberately pin a read snapshot while real
    # native writers commit WAL-only rows. This is NOT the stopped-writer walkthrough.
    wal_backup = home.parent / 'wal-robustness'
    wal_backup.mkdir(mode=0o700)
    with (storage.Store(policy, writable=True) as anchor,
          closing(sqlite3.connect(policy.database.as_uri() + '?mode=ro', uri=True)) as source):
        anchor.connection.execute('PRAGMA wal_autocheckpoint=0')
        source.execute('BEGIN')
        source.execute('SELECT COUNT(*) FROM devices').fetchone()
        device = atlas.cli(['create', '--name', 'Committed WAL inventory'])['device_id']
        batch = _pending_batch(storage, batches, policy)
        atlas.cli(['map', '--format', 'mermaid', '--export'])
        assert Path(str(policy.database) + '-wal').stat().st_size > 0
        history = _history(storage, policy)
        wal_database = _documented_backup(policy.database, wal_backup)
        assert _history(storage, replace(policy, database=wal_database)) == history
    # All reader/writer contexts above are now closed. Follow the operator stop,
    # private config copy and maintained backup snippet with no live connections.
    (home / 'config.yaml').chmod(0o644)
    _documented_stop(atlas, home, policy.database, backup)
    database = _documented_backup(policy.database, backup)
    assert _history(storage, replace(policy, database=database)) == history
    exports = {path.name: path.read_bytes() for path in policy.exports.iterdir()}
    assert set(exports) == {'network_map.md', 'network_map.mmd'}
    shutil.copytree(policy.exports, backup / 'exports')
    backup_bytes = database.read_bytes()
    # Stop revokes grants without detaching the selection, including custom stores.
    stopped = atlas.cli(['status'])
    assert stopped['configured_networks'] == stopped['authorized_for_atlas_ssh_inspection'] == []
    assert stopped['known_devices'] == 2
    assert stopped['database_binding']['database_path'] == str(policy.database)
    with patch('subprocess.Popen', side_effect=AssertionError('stopped policy attempted collection')):
        for name, arguments in (('network_discover', {'network': 'lab', 'mode': 'passive'}),
                                ('network_inspect', {'target': 'lab-router'})):
            refused = atlas.tool(name, arguments)
            assert 'error' in refused and not refused['persisted'] and not refused['applied']
    assert _history(storage, policy) == history, 'revocation/detachment is not deletion'
    # All connections are closed. Only known fixture-owned regular files go;
    # never recurse over a profile, shared directory or the backup.
    assert policy.database.is_relative_to(home.resolve())
    for suffix in ('', '-wal', '-shm', '-journal'):
        path = Path(str(policy.database) + suffix)
        assert not path.is_symlink()
        path.unlink(missing_ok=True)
    for name in exports:
        (policy.exports / name).unlink()
    # Re-select the old custom path too: a default-only empty query is insufficient.
    _replace_policy(atlas, {'store': {'shared_sqlite_path': str(policy.database)}})
    _binding_status(atlas, config, storage, home, policy.database, 0)
    assert atlas.cli(['query'])['devices'] == []
    _replace_policy(atlas, {})
    _binding_status(atlas, config, storage, home, home / 'plugin-data/network-atlas/atlas.sqlite3', 0)
    hermes = shutil.which('hermes')
    assert hermes is not None
    cold = subprocess.run([hermes, 'network-atlas', 'status'], cwd=home.parent, env=os.environ.copy(),
                          input='', capture_output=True, text=True, timeout=45)
    assert cold.returncode == 0, cold.stdout + cold.stderr
    cold_status = json.loads(cold.stdout)
    assert cold_status['known_devices'] == cold_status['endpoint_evidence_batches'] == 0
    assert cold_status['last_collection'] is None
    assert atlas.cli(['query'])['devices'] == []
    assert atlas.cli(['map', '--format', 'markdown'])['exports'] == []
    assert not any(policy.exports.iterdir())
    for database_path in (policy.database, home / 'plugin-data/network-atlas/atlas.sqlite3'):
        assert not any(Path(str(database_path) + suffix).exists() for suffix in ('', '-wal', '-shm', '-journal'))
    # The standalone backup remains usable through public native reads, including
    # its WAL-only device and saved evidence, without restoring it into active use.
    _replace_policy(atlas, {'store': {'shared_sqlite_path': str(database)}})
    assert device in {row['id'] for row in atlas.cli(['query'])['devices']}
    assert atlas.cli(['status'])['last_collection']['id'] == batch
    assert _history(storage, config.load_policy(atlas.ctx)) == history
    _replace_policy(atlas, {})
    assert database.read_bytes() == backup_bytes
    assert (backup / 'config.yaml').read_bytes() == original_config
    assert {path.name: path.read_bytes() for path in (backup / 'exports').iterdir()} == exports
    assert (foreign / 'config.yaml').read_bytes() == foreign_config and shared.read_bytes() == shared_bytes
    assert _history(storage, foreign_policy) == foreign_history
    assert {path: path.read_bytes() for path in foreign_policy.exports.iterdir()} == foreign_exports
    return {'owned_backup_reset': True, 'custom_store': custom, 'shared_store_retained': True}


def main():
    root, mode = Path(sys.argv[1]), sys.argv[2]
    home, scratch = Path(os.environ['HERMES_HOME']).resolve(), Path(os.environ['TMPDIR']).resolve()
    assert home.is_relative_to(scratch) and (scratch / 'synthetic-atlas-home').is_file()
    deny_network()
    mask = int(os.environ['NETWORK_ATLAS_TEST_UMASK'], 8)
    previous = os.umask(mask)
    try:
        atlas = NativeAtlas(root)
        loaded = next(item for item in atlas.manager._plugins.values() if item.manifest.name == 'network-atlas')
        assert loaded.module is not None
        config, storage, batches = (importlib.import_module(loaded.module.__name__ + '.' + name)
                                    for name in ('config', 'storage', 'batches'))
        if mode == 'native_clone':
            receipt = _clone_binding(atlas, home, config, storage, batches)
        elif mode in {'native_reset', 'native_reset_custom'}:
            receipt = _reset_walkthrough(atlas, home, config, storage, batches, custom=mode == 'native_reset_custom')
        elif mode in {'native_stop_converted', 'native_stop_converted_shared', 'native_stop_converted_file_link'}:
            receipt = _converted_stop(atlas, home, config, storage, batches, shared_binding=mode.endswith('_shared'),
                                      managed_file_link=mode.endswith('_file_link'))
        else:
            assert mode == 'native_privacy'
            receipt = _privacy(atlas, home, config, storage, mask)
        atlas.manager.unload()
        print(json.dumps({'mode': mode, **receipt}, sort_keys=True))
    finally:
        os.umask(previous)


if __name__ == '__main__':
    main()
