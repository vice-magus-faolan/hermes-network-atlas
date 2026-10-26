#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Actual native clones and filesystem defaults, only in test_runtime's owned homes."""
from dataclasses import replace
import importlib
import json
import os
from pathlib import Path
import shutil
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


def _pending_batch(storage, batches, policy):
    """Produce real saved evidence bound to the resolved caller home, without traffic."""
    at = storage.timestamp(storage.utc_now())
    with storage.Store(policy, writable=True) as store:
        return batches.store_batch(store, 'local_passive', 'lab', at, at, 'partial', (
            batches.Probe('ip_addr', 'success', at, at, 'local_host', policy.networks[0].cidr, 'local_interface'),
            batches.Probe('ip_neigh', 'unavailable', at, at, 'none', '', 'none', 'missing_executable'),))


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
    assert atlas.cli(['convert-legacy', '--writers-stopped'])['converted']
    policy = config.load_policy(atlas.ctx)
    assert _history(storage, policy) == history
    converted = atlas.ctx.get_config('policy', None)
    assert converted == {**raw, 'store': {'shared_sqlite_path': str(policy.database)}}
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
        # Explicit sharing with no grants remains usable; stored evidence grants nothing.
        _replace_policy(atlas, {'store': converted['store']})
        assert len(atlas.tool('network_query', {})['devices']) == 2
        assert atlas.cli(['status'])['configured_networks'] == []
        assert atlas.cli(['status'])['authorized_for_atlas_ssh_inspection'] == []
        assert 'error' in atlas.tool('network_discover', {'network': 'lab', 'mode': 'passive'})
        shared_history = _history(storage, policy)
        # Omit store through the replacing writer: this deliberately selects NEW empty local history.
        _replace_policy(atlas, raw)
        rebound = config.load_policy(atlas.ctx)
        assert rebound.home == clone and rebound.database == local_database
        assert atlas.tool('network_query', {})['devices'] == []
        local_device = atlas.cli(['create', '--name', 'Deliberately independent clone'])['device_id']
        assert atlas.cli(['query'])['devices'][0]['id'] == local_device
        assert _history(storage, policy) == shared_history
        # Ordinary config-only clones of a no-store profile do not copy its populated local DB.
        ordinary = create_profile('atlas-local-clone', clone_config=True, no_alias=True)
        assert ordinary == home / 'profiles' / 'atlas-local-clone'
        with patch.dict(os.environ, {'HERMES_HOME': str(ordinary)}):
            ordinary_policy = config.load_policy(atlas.ctx)
            assert ordinary_policy.home == ordinary
            assert ordinary_policy.database == ordinary / 'plugin-data' / 'network-atlas' / 'atlas.sqlite3'
            assert atlas.cli(['query'])['devices'] == []
            independent = atlas.cli(['create', '--name', 'Ordinary local clone'])['device_id']
            assert atlas.tool('network_query', {})['devices'][0]['id'] == independent
        assert atlas.cli(['query'])['devices'][0]['id'] == local_device
        assert _history(storage, policy) == shared_history
    assert {item['id'] for item in atlas.cli(['query'])['devices']} == {device, shared_device}
    assert not atlas.cli(['reconcile', '--batch-id', clone_batch], expected_code=2)['applied']
    assert (home / 'config.yaml').read_bytes() == source_config
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
        else:
            assert mode == 'native_privacy'
            receipt = _privacy(atlas, home, config, storage, mask)
        atlas.manager.unload()
        print(json.dumps({'mode': mode, **receipt}, sort_keys=True))
    finally:
        os.umask(previous)


if __name__ == '__main__':
    main()
