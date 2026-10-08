# SPDX-License-Identifier: GPL-3.0-or-later
"""Tiny real source/PM publication seams; no acquisition/install/core copies."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
from test_runtime import runtime_root
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'docker'))
import core_identity as identity
import base_setup as setup
import docker_inside as inside
import acquisition_support as acquisition
from offline_guard import deny_network


def tiny_source(root):
    root.mkdir()
    (root / 'source.py').write_bytes(b'public source\n')
    (root / 'runner').write_bytes(b'public executable\n')
    (root / 'runner').chmod(0o755)
    (root / 'link').symlink_to('source.py')
    return identity.source_manifest(root)


def tiny_archive(source, root):
    git = lambda *args: subprocess.check_output(['git', '-C', str(source), *args], stderr=subprocess.PIPE).strip()
    git('init', '--quiet')
    git('add', '--force', '--all')
    tree = git('write-tree').decode()
    # Explicit local identity/config only; no user config or signing helper.
    git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false',
        'commit', '--quiet', '-m', 'tiny public fixture')
    commit = git('rev-parse', 'HEAD').decode()
    archive = root / 'hermes.tar'
    archive.write_bytes(git('archive', 'HEAD'))
    obj = root / 'hermes.commit'
    obj.write_bytes(subprocess.check_output(['git', '-C', str(source), 'cat-file', 'commit', 'HEAD']))
    return archive, obj, commit, tree


class CoreIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deny_network()

    def authenticate(self, digest):
        real = identity.require_identity
        return patch.object(identity, 'require_identity', side_effect=lambda value: real(value, expected_digest=digest))

    def test_real_pinned_named_install_publishes_source_local_launchers(self):
        core = runtime_root()
        self.assertEqual(subprocess.check_output(['git', '-C', str(core), 'rev-parse', 'HEAD'], text=True).strip(),
                         '5645275e50d66dca04c9565634f9b5207a38aef5')
        sys.path.insert(0, str(core))
        import pm.cli as cli
        import pm.install as install
        from hermes_cli import _launchers, venv_sync
        self.assertEqual(Path(cli.__file__).resolve(), core / 'pm/cli.py')
        with scratch_home() as directory:
            root = Path(directory)
            source = root / 'project'
            before = tiny_source(source)
            (source / '.git').mkdir()  # real publish_launchers treats this as a checkout
            with patch.object(cli, 'repo_root', return_value=source), \
                    patch.object(install, '_install_operation', return_value=contextlib.nullcontext(object())), \
                    patch.object(cli, 'ensure') as ensure, \
                    patch.object(_launchers, 'resolve_store_python', return_value=Path(sys.executable)), \
                    patch.object(_launchers, 'expose_cli', return_value={'ok': True}) as expose, \
                    patch.dict(os.environ, {'HERMES_HOME': str(root / 'isolated-home')}), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli._install_names(['python', 'uv']), 0)
            self.assertEqual(ensure.call_count, 2)  # acquisition boundary replaced; dispatch/publication is real
            expose.assert_called_once_with(source, create=False)
            after = identity.source_manifest(source)
            report = identity.identity_report(after, before, 'real-pinned-pm-launchers')
            self.assertGreater(report['difference_count'], 0)
            self.assertTrue(all(row['path'].startswith('.hermes/bin/') for row in report['differences']))
            with self.assertRaisesRegex(ValueError, 'complete Hermes source identity mismatch'):
                identity.require_identity(after, expected_digest=identity.manifest_digest(before))
            self.assertFalse((root / 'isolated-home').exists())
            print('Real pinned PM launcher delta: ' + json.dumps(report, sort_keys=True))

    def test_producer_rebuilds_entire_source_before_readability_and_rejects_bad_archive(self):
        with scratch_home() as directory:
            root = Path(directory)
            public = root / 'public'
            expected = tiny_source(public)
            archive, obj, commit, tree = tiny_archive(public, root)
            seed = root / 'seed'
            seed.mkdir()
            source = seed / 'hermes-source'
            shutil.copytree(public, source, symlinks=True)
            # Same real pinned publication as RED, then the actual new producer
            # reconstruction; only tool acquisition/operation and PATH exposure
            # are replaced. No fake launcher bytes stand in for the defect.
            sys.path.insert(0, str(runtime_root()))
            import pm.cli as cli
            import pm.install as install
            from hermes_cli import _launchers
            with patch.object(cli, 'repo_root', return_value=source), \
                    patch.object(install, '_install_operation', return_value=contextlib.nullcontext(object())), \
                    patch.object(cli, 'ensure'), \
                    patch.object(_launchers, 'resolve_store_python', return_value=Path(sys.executable)), \
                    patch.object(_launchers, 'expose_cli', return_value={'ok': True}), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli._install_names(['python', 'uv']), 0)
            (source / 'source.py').write_text('mutated work material')
            log = io.StringIO()
            with patch.object(setup, 'source_layout', return_value=(source, seed)), \
                    self.authenticate(identity.manifest_digest(expected)), \
                    patch.dict(os.environ, {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}, clear=True), \
                    patch.object(acquisition, 'COMMAND_LOG', acquisition.CommandLog()), contextlib.redirect_stdout(log):
                result = setup.publish_source(archive, obj, commit, tree)
            self.assertEqual(result['before']['difference_count'], 3)
            self.assertEqual(result['published']['difference_count'], 0)
            self.assertEqual(identity.source_manifest(source), expected)
            self.assertEqual(json.loads((seed / 'core-source-manifest.json').read_text()), expected)
            self.assertFalse((seed / 'authenticated-core').exists())
            self.assertIn('producer-after-pm', log.getvalue())
            archive.write_bytes(b'not a tar archive')
            with patch.object(setup, 'source_layout', return_value=(source, seed)), self.assertRaises(tarfile.ReadError):
                setup.publish_source(archive, obj, commit, tree)
            self.assertEqual(identity.source_manifest(source), expected)
            with patch.dict(os.environ, {}, clear=True), patch.object(setup.Path, 'mkdir') as mkdir, self.assertRaises(ValueError):
                setup.publish_source(Path('/opt/inputs/hermes.tar'), Path('/opt/inputs/hermes.commit'), commit, tree)
            mkdir.assert_not_called()

    def test_mutation_addition_removal_mode_and_symlink_drift_refuse(self):
        for operation in ('mutation', 'addition', 'removal', 'mode', 'symlink'):
            with self.subTest(operation=operation), scratch_home() as directory:
                source = Path(directory) / 'core'
                expected = tiny_source(source)
                if operation == 'mutation':
                    (source / 'source.py').write_bytes(b'changed')
                elif operation == 'addition':
                    (source / 'extra').write_bytes(b'new')
                elif operation == 'removal':
                    (source / 'source.py').unlink()
                elif operation == 'mode':
                    (source / 'runner').chmod(0o644)
                else:
                    (source / 'link').unlink()
                    (source / 'link').symlink_to('runner')
                actual = identity.source_manifest(source)
                self.assertEqual(identity.identity_report(actual, expected, operation)['difference_count'], 1)
                with self.assertRaises(ValueError):
                    identity.require_identity(actual, expected_digest=identity.manifest_digest(expected))

    def test_consumer_exports_actual_manifest_before_seed_and_copy_refusal(self):
        with scratch_home() as directory:
            root = Path(directory)
            expected = tiny_source(root / 'source')
            export = root / 'export'
            export.mkdir()
            (root / 'core-source-manifest.json').write_bytes(identity.canonical(expected))
            with patch.object(inside, 'SEED', root), patch.object(inside, 'EXPORT', export), \
                    self.authenticate(identity.manifest_digest(expected)):
                inside.authenticate_source(root / 'source', 'consumer-seed')
                shutil.copytree(root / 'source', root / 'copy', symlinks=True)
                (root / 'copy/runner').chmod(0o644)
                with self.assertRaises(ValueError):
                    inside.authenticate_source(root / 'copy', 'consumer-copy', expected=expected)
                self.assertEqual(json.loads((export / 'consumer-copy-identity.json').read_text())['differences'][0]['path'], 'runner')
                self.assertEqual(json.loads((export / 'consumer-copy-manifest.json').read_text()), identity.source_manifest(root / 'copy'))
                (root / 'source/extra').write_bytes(b'pollution')
                with self.assertRaises(ValueError):
                    inside.authenticate_source(root / 'source', 'consumer-seed')
                self.assertEqual(json.loads((export / 'consumer-seed-identity.json').read_text())['difference_count'], 1)

    def test_bounds_special_types_and_primary_error_survive_export_failure(self):
        with scratch_home() as directory:
            root = Path(directory)
            expected = tiny_source(root / 'source')
            for name, limit in [('MEMBER_COUNT', 1), ('SOURCE_BYTES', 1), ('MANIFEST_BYTES', 1)]:
                with patch.object(identity, name, limit), self.assertRaises(ValueError):
                    identity.source_manifest(root / 'source')
            os.mkfifo(root / 'source/fifo')
            with self.assertRaisesRegex(ValueError, 'member type'):
                identity.source_manifest(root / 'source')
            (root / 'source/fifo').unlink()
            (root / 'source/extra').write_bytes(b'pollution')
            with self.authenticate(identity.manifest_digest(expected)), \
                    patch.object(inside, 'BoundedDirectory', side_effect=OSError('actual export seam')), \
                    self.assertRaisesRegex(ValueError, 'complete Hermes source identity mismatch') as raised:
                inside.authenticate_source(root / 'source', 'consumer-copy', expected=expected)
            self.assertIn('core identity export failed: OSError', raised.exception.__notes__)
            hostile = {str(i) + '\u2603\n': ['symlink', '\u2603\n'] for i in range(100)}
            report = identity.identity_report(hostile, {}, 'bounded-hostile')
            self.assertEqual((report['difference_count'], len(report['differences']), report['omitted_differences']), (100, 64, 36))

    def test_actual_public_archive_manifest_matches_unchanged_pin_without_extraction(self):
        core = runtime_root()
        child = subprocess.Popen(['git', '-C', str(core), 'archive', '5645275e50d66dca04c9565634f9b5207a38aef5'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        manifest = {}
        total = 0
        try:
            with tarfile.open(fileobj=child.stdout, mode='r|') as archive:
                for member in archive:
                    if member.isfile():
                        total += member.size
                        with archive.extractfile(member) as stream:
                            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                        manifest[member.name] = ['file', bool(member.mode & 0o111), digest]
                    elif member.issym():
                        manifest[member.name] = ['symlink', member.linkname]
                    elif not member.isdir():
                        self.fail('unexpected public archive type')
            self.assertEqual(child.wait(timeout=15), 0)
            identity.require_identity(manifest)
            self.assertLessEqual(total, identity.SOURCE_BYTES)
            print('Streamed pinned archive: ' + json.dumps({'members': len(manifest), 'source_bytes': total,
                  'manifest_bytes': len(identity.canonical(manifest)), 'digest': identity.manifest_digest(manifest)}))
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()
            child.stdout.close()
            child.stderr.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
