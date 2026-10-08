# SPDX-License-Identifier: GPL-3.0-or-later
"""Tiny actual Git/child/export regressions; no Docker or native admission."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
sys.path.insert(0, str(ROOT / 'scripts'))
from offline_guard import deny_network
deny_network()
import acceptance_support as support
import docker_acceptance as controller
import docker_inside as inside
import docker_snapshot as snapshot
from docker_evidence import BoundedDirectory


def tiny_repo(root):
    source = root / 'source'
    source.mkdir()
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(root / 'absent'), 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null'}
    def git(*args):
        return subprocess.check_output(['git', '-C', str(source), *args], env=env).decode().strip()
    git('init', '-q')
    (source / 'public.txt').write_text('public fixture\n')
    git('add', '.')
    git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
    candidate = root / 'candidate'
    controller.snapshot(source, git('rev-parse', 'HEAD'), candidate)
    return candidate, git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')


class StartupTests(unittest.TestCase):
    def test_real_git_different_owner_refusal_then_exact_snapshot_identity(self):
        with scratch_home() as directory:
            candidate, commit, tree = tiny_repo(Path(directory))
            ambient = dict(os.environ, GIT_TEST_ASSUME_DIFFERENT_OWNER='1', GIT_CONFIG_COUNT='0',
                           GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
            refused = subprocess.run(['git', '-C', str(candidate), 'rev-parse', 'HEAD'], env=ambient,
                                     capture_output=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn(b'dubious ownership', refused.stderr)
            real_environment = snapshot.git_environment
            def different_owner(root):
                return dict(real_environment(root), GIT_TEST_ASSUME_DIFFERENT_OWNER='1')
            with patch.object(snapshot, 'CANDIDATE', candidate), patch.dict(os.environ, ambient, clear=True), \
                    patch.object(snapshot, 'git_environment', side_effect=different_owner):
                actual = snapshot.validate_snapshot(candidate)
                self.assertEqual(actual, {'commit': commit, 'tree': tree})
                self.assertEqual(support.git_head(candidate), commit)
                self.assertEqual(support.git_tree(candidate), tree)
            self.assertEqual(json.loads((candidate / '.git' / snapshot.RECORD).read_text()), actual)

    def test_exact_path_metadata_symlink_scope_and_no_ambient_authority(self):
        with scratch_home() as directory:
            root = Path(directory)
            candidate, _commit, _tree = tiny_repo(root)
            with patch.object(snapshot, 'CANDIDATE', candidate):
                for bad in (root, candidate / '..' / 'candidate', candidate / 'public.txt'):
                    with self.subTest(path=str(bad)), self.assertRaises(ValueError):
                        snapshot.git_environment(bad)
                link = root / 'link'
                link.symlink_to(candidate, target_is_directory=True)
                with self.assertRaises(ValueError):
                    snapshot.git_environment(link)
                record = candidate / '.git' / snapshot.RECORD
                saved = record.read_bytes()
                record.chmod(0o644)  # Controlled fixture drift, not a production permission change.
                record.unlink()
                with self.assertRaises(OSError):
                    snapshot.git_environment(candidate)
                record.write_bytes(saved)
                for data in ({'commit': '*', 'tree': 'a' * 40}, {'commit': 'a'*40, 'tree': 'b'*40, 'path': '*'}):
                    record.write_text(json.dumps(data))
                    with self.assertRaises(ValueError):
                        snapshot.git_environment(candidate)
                record.unlink()
                record.symlink_to(root / 'outside')
                with self.assertRaises((ValueError, OSError)):
                    snapshot.git_environment(candidate)
                record.unlink()
                record.write_bytes(saved)
                with patch.dict(os.environ, {'GIT_DIR': '/outside', 'GIT_CONFIG_COUNT': '1',
                                              'GIT_CONFIG_KEY_0': 'safe.directory', 'GIT_CONFIG_VALUE_0': '*',
                                              'HOME': '/private/operator', 'HTTPS_PROXY': 'private'}, clear=True):
                    env = snapshot.git_environment(candidate)
                    self.assertEqual(env['GIT_CONFIG_VALUE_0'], str(candidate))
                    self.assertNotIn('GIT_DIR', env)
                    self.assertNotIn('HTTPS_PROXY', env)
                    self.assertEqual(env['HOME'], '/nonexistent')

    def test_commit_tree_dirty_blob_and_git_escape_drift_refuse(self):
        with scratch_home() as directory:
            candidate, _commit, _tree = tiny_repo(Path(directory))
            record = candidate / '.git' / snapshot.RECORD
            saved = record.read_bytes()
            record.chmod(0o644)  # Controlled fixture drift.
            with patch.object(snapshot, 'CANDIDATE', candidate):
                for field in ('commit', 'tree'):
                    data = json.loads(saved)
                    data[field] = 'a' * 40
                    record.write_text(json.dumps(data))
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        snapshot.validate_snapshot(candidate)
                record.write_bytes(saved)
                path = candidate / 'public.txt'
                path.write_text('hostile change\n')
                with self.assertRaises(ValueError):
                    snapshot.validate_snapshot(candidate)
                path.write_text('public fixture\n')
                path.unlink()
                path.symlink_to('/etc/passwd')
                with self.assertRaises(ValueError):
                    snapshot.validate_snapshot(candidate)
                path.unlink()
                path.write_text('public fixture\n')
                (candidate / 'untracked').write_text('drift')
                with self.assertRaises(ValueError):
                    snapshot.validate_snapshot(candidate)
                (candidate / 'untracked').unlink()
                (candidate / '.git' / 'objects' / 'escape').symlink_to('/outside')
                with self.assertRaises(ValueError):
                    snapshot.validate_snapshot(candidate)
                (candidate / '.git' / 'objects' / 'escape').unlink()
                config = candidate / '.git' / 'config'
                config.write_bytes(snapshot.CONFIG + b'[include]\n\tpath = /outside\n')
                with self.assertRaises(ValueError):
                    snapshot.git_environment(candidate)

    def test_sanitized_native_child_git_trust_is_exact_and_other_repos_refuse(self):
        with scratch_home() as directory:
            root = Path(directory)
            candidate, commit, _tree = tiny_repo(root)
            other = root / 'other'
            other.mkdir()
            subprocess.run(['git', '-C', str(other), 'init', '-q'], check=True)
            with patch.object(snapshot, 'CANDIDATE', candidate), patch.object(support, 'ROOT', candidate):
                env = support.fixture_environment(root)
            self.assertEqual(env['HOME'], str(root / 'user'))
            self.assertEqual(env['GIT_CONFIG_VALUE_0'], str(candidate))
            env['GIT_TEST_ASSUME_DIFFERENT_OWNER'] = '1'  # Git's own test seam, no chown/elevation.
            actual = subprocess.check_output(['git', '-C', str(candidate), 'rev-parse', 'HEAD'], env=env).decode().strip()
            self.assertEqual(actual, commit)
            refused = subprocess.run(['git', '-C', str(other), 'status', '--porcelain'], env=env, capture_output=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn(b'dubious ownership', refused.stderr)
            self.assertEqual(subprocess.check_output(['git', 'config', '--get-all', 'safe.directory'], env=env).decode().splitlines(), [str(candidate)])

    def test_private_runner_layout_allows_container_listing_and_bounded_write(self):
        with scratch_home() as directory:
            root = Path(directory)
            root.chmod(0o700)
            attempts = root / 'evidence'
            attempts.mkdir(mode=0o700)
            attempt = attempts / ('a' * 40 + '-smoke')
            attempt.mkdir(mode=0o700)
            incoming = attempt / 'incoming'
            incoming.mkdir(mode=0o700)
            incoming.chmod(0o733)  # predecessor: different UID can write, not list.
            self.assertEqual(incoming.stat().st_mode & 7, 3)
            incoming.chmod(0o700)
            controller.prepare_hosted_export(root, attempt)
            self.assertEqual(incoming.stat().st_mode & 0o7777, 0o1777)
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            # Actual bounded writer enumerates then publishes mode0600. Cross-UID
            # access is POSIX mode proof, not a locally executed container/UID switch.
            BoundedDirectory(incoming).json('probe.json', {'native_acceptance': False})
            self.assertEqual((incoming / 'probe.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads((incoming / 'probe.json').read_text()), {'native_acceptance': False})
            with self.assertRaises(ValueError):
                controller.prepare_hosted_export(root, attempt)
            (incoming / 'probe.json').unlink()
            incoming.chmod(0o700)
            root.chmod(0o755)
            with self.assertRaises(ValueError):
                controller.prepare_hosted_export(root, attempt)
            root.chmod(0o700)
            incoming.rmdir()
            incoming.symlink_to(root)
            with self.assertRaises(ValueError):
                controller.prepare_hosted_export(root, attempt)
            incoming.unlink()
            incoming.mkdir(mode=0o700)
            with patch.object(controller.os, 'geteuid', return_value=os.getuid() + 1), self.assertRaises(ValueError):
                controller.prepare_hosted_export(root, attempt)
            alias = root / 'alias'
            alias.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                controller.prepare_hosted_export(alias, alias / 'evidence' / attempt.name)

    def test_early_git_started_and_hosted_refusals_export_without_identity_claims(self):
        with scratch_home() as directory:
            export = Path(directory)
            for mode in ('smoke', 'hosted-accept'):
                with self.subTest(mode=mode), patch.object(sys, 'argv', ['inside', mode]), \
                        patch.object(inside, 'EXPORT', export), \
                        patch.object(inside, 'git_head', side_effect=RuntimeError('actual early git failure')), \
                        patch.object(inside, 'export_native'), patch.object(inside, 'prepare') as prepare:
                    with self.assertRaisesRegex(RuntimeError, 'actual early git failure'):
                        inside.main()
                    prepare.assert_not_called()
                    data = json.loads((export / 'error.json').read_text())
                    self.assertFalse(data['native_acceptance'])
                    self.assertNotIn('commit', data)
                    self.assertNotIn('tree', data)
                    self.assertFalse((export / 'started.json').exists())
                    self.assertFalse((export / 'result.json').exists())
            empty = export / 'not-a-repository'
            empty.mkdir()
            def actual_head():
                with patch.dict(os.environ, {'PATH': '/usr/bin:/bin', 'HOME': str(empty),
                                              'GIT_CEILING_DIRECTORIES': str(empty.parent)}, clear=True):
                    return support.git_head(empty)
            # Keep the bounded export flat; the actual Git failure is elsewhere.
            output = export / 'diagnostics'
            output.mkdir()
            with patch.object(sys, 'argv', ['inside', 'smoke']), patch.object(inside, 'EXPORT', output), \
                    patch.object(inside, 'git_head', side_effect=actual_head), patch.object(inside, 'export_native'):
                with self.assertRaises(subprocess.CalledProcessError) as actual:
                    inside.main()
                self.assertEqual(actual.exception.returncode, 128)
                self.assertEqual(json.loads((output / 'error.json').read_text())['error'], 'CalledProcessError')
                self.assertFalse((output / 'started.json').exists())
            with patch.object(sys, 'argv', ['inside', 'smoke']), patch.object(inside, 'EXPORT', export), \
                    patch.object(inside, 'git_head', return_value='a'*40), \
                    patch.object(inside, 'git_tree', return_value='b'*40), \
                    patch.object(inside, 'write_json', side_effect=PermissionError('started export refused')), \
                    patch.object(inside, 'export_native', side_effect=OSError('secondary export')):
                with self.assertRaisesRegex(PermissionError, 'started export refused') as error:
                    inside.main()
                self.assertIn('error evidence export failed: PermissionError', error.exception.__notes__)
                self.assertIn('native evidence export failed: OSError', error.exception.__notes__)

    def test_all_mode_argv_isolation_and_identity_export_guards_unchanged(self):
        from docker_contract import Identity, MODES, create_command
        from test_hosted_docker import diagnostics
        with scratch_home() as directory:
            root = Path(directory)
            ident = Identity('a'*40, 'b'*40, 'sha256:'+'c'*64, 'fixture')
            for mode in MODES:
                argv = create_command(ident, root, mode, root, hosted=diagnostics(Path('/candidate')) if mode == 'hosted-accept' else None)
                self.assertEqual(argv[-4:], [ident.image, 'python3', '/candidate/scripts/docker_inside.py', mode])
                self.assertIn('--read-only', argv)
                self.assertEqual(argv[argv.index('--cap-drop')+1], 'ALL')
                self.assertEqual(argv[argv.index('--network')+1], 'none')
                self.assertEqual(argv[argv.index('--user')+1], '1000:1000')


if __name__ == '__main__':
    unittest.main()
