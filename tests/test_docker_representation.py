# SPDX-License-Identifier: GPL-3.0-or-later
"""Actual tiny Git-only publication/materialization; never full-core/native fixtures."""
import ast
from contextlib import ExitStack, redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'docker'))
import acquisition_support as acquisition
import core_representation as representation
import hosted_retention as retention
from core_identity import source_manifest, manifest_digest, canonical
from offline_guard import deny_network


class RepresentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deny_network()

    def fixture(self, root):
        original = root / 'original'
        original.mkdir()
        def git(*args, cwd=original, data=None):
            return subprocess.check_output(['git', '-C', str(cwd), *args], input=data,
                                           env=representation.environment(), stderr=subprocess.STDOUT, timeout=10)
        git('init', '-q')
        (original / 'parent').write_bytes(b'parent\n')
        git('add', '.')
        identity = ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false']
        git(*identity, 'commit', '-qm', 'parent')
        parent = git('rev-parse', 'HEAD').decode().strip()
        (original / 'parent').unlink()
        (original / '.gitattributes').write_bytes(b'*.ps1 text eol=crlf\n*.py text eol=lf\n')
        (original / 'probe.ps1').write_bytes(b'Write-Output "one"\r\nWrite-Output "two"\r\n')
        for name in ('code.py', 'test.py', 'documentation.md'):
            (original / name).write_bytes((b'complete fixture contents\n' * 128) + name.encode())
        (original / 'code.py').chmod(0o755)
        (original / 'link').symlink_to('code.py')
        git('add', '-A')
        git(*identity, 'commit', '-qm', 'source')
        commit, tree = git('rev-parse', 'HEAD', 'HEAD^{tree}').decode().splitlines()
        seed = root / 'seed'
        core = seed / 'hermes-source'
        core.mkdir(parents=True)
        bundle = git('archive', 'HEAD')
        with tarfile.open(fileobj=io.BytesIO(bundle)) as stream:
            stream.extractall(core, filter='data')
        obj = root / 'commit'
        obj.write_bytes(git('cat-file', 'commit', 'HEAD'))
        clean_env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        with patch.dict(os.environ, clean_env, clear=True), patch.object(acquisition, 'COMMAND_LOG', acquisition.CommandLog()), redirect_stdout(io.StringIO()):
            acquisition.reconstruct_public_core(core, obj, commit, tree)
        unreachable = git('hash-object', '-w', '--stdin', cwd=core, data=b'unreachable retained fixture\n').decode().strip()
        manifest = source_manifest(core)
        (seed / 'core-source-manifest.json').write_bytes(canonical(manifest))
        return seed, core, commit, tree, parent, unreachable, manifest

    def context(self, core, commit, tree, manifest):
        stack = ExitStack()
        stack.enter_context(patch.dict(os.environ, {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}, clear=True))
        digest = manifest_digest(manifest)
        stack.enter_context(patch.object(representation, 'HERMES_COMMIT', commit))
        stack.enter_context(patch.object(representation, 'CORE_TREE', tree))
        stack.enter_context(patch.object(representation, 'CORE_SOURCE_DIGEST', digest))
        check = lambda value: self.assertEqual(manifest_digest(value), digest)
        stack.enter_context(patch.object(representation, 'require_identity', side_effect=check))
        stack.enter_context(patch.object(retention, 'require_identity', side_effect=check))
        stack.enter_context(patch.object(retention, 'owned_layout'))
        stack.enter_context(patch.object(representation, 'producer_layout'))
        stack.enter_context(patch.object(representation, 'producer_store'))
        # Tiny roots replace only literal container ownership boundaries. Actual
        # Git/source/object/metadata/archive/accounting paths all execute unchanged.
        def retire(actual, seed, expected):
            self.assertEqual(actual, core)
            self.assertFalse((actual / '.git').exists())
            self.assertEqual(source_manifest(actual), expected)
        stack.enter_context(patch.object(representation, 'producer_retirement', side_effect=retire))
        stack.enter_context(patch.object(acquisition, 'COMMAND_LOG', acquisition.CommandLog()))
        stack.enter_context(redirect_stdout(io.StringIO()))
        return stack

    def publish(self, seed, core, commit, tree):
        compact = retention.compact_core(core, seed, commit, tree)
        return representation.publish(core, seed, compact), compact

    def test_producer_consumer_and_controller_use_actual_versioned_path_before_native(self):
        producer = ast.parse((ROOT / 'docker/hosted_setup.py').read_text())
        main = next(node for node in producer.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        calls = [node.func.id for statement in main.body for node in ast.walk(statement)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id in {'compact_core', 'publish', 'seal_inventory'}]
        self.assertEqual(calls, ['compact_core', 'publish', 'seal_inventory'])
        import docker_inside
        prepare = ast.parse((ROOT / 'scripts/docker_inside.py').read_text())
        function = next(node for node in prepare.body if isinstance(node, ast.FunctionDef) and node.name == 'prepare')
        names = [node.func.id for node in ast.walk(function) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        self.assertIn('restore', names)
        self.assertIn('authenticate_inventory', names)
        import hosted_docker
        self.assertEqual(hosted_docker.PUBLIC_FILES['core_representation.py'], 'scripts/core_representation.py')
        self.assertFalse((ROOT / 'docker/measurement-phase.json').exists())
        module = ast.parse((ROOT / 'scripts/core_representation.py').read_text())
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.module and node.module.startswith('pm') for node in ast.walk(module)))
        with scratch_home() as directory:
            root = Path(directory)
            seed, core, commit, tree, _, _, expected = self.fixture(root)
            with self.context(core, commit, tree, expected):
                row, compact = self.publish(seed, core, commit, tree)
                for name in ('tools', 'uv-cache'):
                    (seed / name).mkdir()
                    (seed / name / 'synthetic').write_bytes(b'tiny prerequisite fixture')
                verifier = root / 'verifier'
                verifier.mkdir()
                representation.seal_inventory(seed, verifier, {'core_representation': row}, compact, row)
                work, export, candidate = root / 'work', root / 'export', root / 'candidate'
                for path in (work, export, candidate): path.mkdir()
                (candidate / 'synthetic-candidate').write_bytes(b'fixture only')
                original_copy = representation.shutil.copytree
                original_inventory = representation.authenticate_inventory
                def copy_tree(source, destination, *args, **kwargs):
                    return original_copy(candidate if source == Path('/candidate') else source, destination, *args, **kwargs)
                import core_identity
                with patch.object(docker_inside, 'ROOT', Path('/candidate')), patch.object(docker_inside, 'SEED', seed), \
                        patch.object(docker_inside, 'WORK', work), patch.object(docker_inside, 'FIXTURE', work / 'fixture'), \
                        patch.object(docker_inside, 'EXPORT', export), patch.object(representation.shutil, 'copytree', side_effect=copy_tree), \
                        patch.object(representation, 'authenticate_inventory', side_effect=lambda actual, literal: original_inventory(actual, verifier)), \
                        patch.object(core_identity, 'require_identity', side_effect=lambda value: self.assertEqual(value, expected)):
                    restored, env = docker_inside.prepare()
                self.assertEqual(source_manifest(restored), expected)
                self.assertEqual(Path(env['UV_CACHE_DIR']), work / 'fixture/hermes/cache/uv')
                self.assertEqual(json.loads((export / 'core-materialization.json').read_text())['stage'], 'complete')

    def test_real_git_only_red_green_complete_crlf_modes_links_objects_and_shallow(self):
        with scratch_home() as directory:
            root = Path(directory)
            seed, core, commit, tree, parent, unreachable, expected = self.fixture(root)
            with self.context(core, commit, tree, expected):
                before = {}
                retention.measure(seed, before)
                row, compact = self.publish(seed, core, commit, tree)
                self.assertFalse(core.exists())
                # Actual predecessor's expanded source reader cannot consume v1.
                import docker_inside
                with self.assertRaisesRegex(ValueError, 'complete core directory'):
                    docker_inside.authenticate_source(core, 'consumer-seed', expected=expected)
                work = root / 'work'
                work.mkdir()
                restored = work / 'hermes-source'
                emitted = []
                proof = representation.restore(seed, restored, work, lambda value: emitted.append(copy.deepcopy(value)))
                self.assertEqual(proof['stage'], 'complete')
                self.assertEqual(source_manifest(restored), expected)
                self.assertEqual((restored / 'probe.ps1').read_bytes(), b'Write-Output "one"\r\nWrite-Output "two"\r\n')
                self.assertTrue((restored / 'code.py').stat().st_mode & 0o111)
                self.assertEqual(os.readlink(restored / 'link'), 'code.py')
                self.assertEqual((restored / '.git/shallow').read_text(), commit + '\n')
                self.assertEqual(representation.objects(restored, row['objects'], time.monotonic() + 120), row['objects'])
                output = subprocess.check_output(['git', '-C', str(restored), 'cat-file', 'blob', unreachable])
                self.assertEqual(output, b'unreachable retained fixture\n')
                self.assertNotEqual(subprocess.run(['git', '-C', str(restored), 'cat-file', '-e', parent], capture_output=True).returncode, 0)
                self.assertFalse((restored / '.atlas-core-source.tar').exists())
                self.assertEqual(proof['objects'], compact['objects_before'])
                self.assertFalse(proof['native_acceptance'])

    def test_real_self_inclusive_physical_logical_and_verifier_accounting(self):
        with scratch_home() as directory:
            root = Path(directory)
            seed, core, commit, tree, _, _, expected = self.fixture(root)
            with self.context(core, commit, tree, expected):
                row, compact = self.publish(seed, core, commit, tree)
                verifier = root / 'verifier'
                verifier.mkdir()
                (verifier / 'actual').write_bytes(b'verifier bytes')
                inventory = {'core_representation': row}
                representation.seal_inventory(seed, verifier, inventory, compact, row)
                readback = representation.authenticate_inventory(seed, verifier)
                self.assertEqual(readback, inventory)
                self.assertEqual(inventory['retained_inventory']['logical_expanded_seed_bytes'], inventory['seed_usage']['bytes'] + row['expanded_bytes'])
                self.assertEqual(inventory['verifier_usage']['bytes'], len(b'verifier bytes'))
                (seed / 'unexpected').write_bytes(b'drift')
                with self.assertRaisesRegex(ValueError, 'whole-root'):
                    representation.authenticate_inventory(seed, verifier)

    def test_old_mixed_partial_boolean_and_forged_ledger_refuse_before_copy(self):
        with scratch_home() as directory:
            root = Path(directory)
            seed, core, commit, tree, _, _, expected = self.fixture(root)
            with self.context(core, commit, tree, expected):
                row, _ = self.publish(seed, core, commit, tree)
                for key, value in [('format', 'expanded-v0'), ('commit', '0' * 40), ('source_members', True),
                                   ('objects', {}), ('native_acceptance', True), ('native_acceptance', 0)]:
                    bad = copy.deepcopy(row)
                    bad[key] = value
                    with self.subTest(key=key), self.assertRaises(ValueError): representation.require_record(bad)
                core.mkdir()
                with patch.object(representation.shutil, 'copytree') as copier, self.assertRaises(ValueError):
                    representation.restore(seed, root / 'never', root, lambda value: None)
                copier.assert_not_called()

    def test_config_hooks_alternates_grafts_replace_links_and_attributes_refuse(self):
        for relative in ('objects/info/alternates', 'objects/info/http-alternates', 'info/grafts', 'refs/replace',
                         'info/attributes', 'hooks/pre-commit', 'commondir'):
            with self.subTest(relative=relative), scratch_home() as directory:
                root = Path(directory)
                seed, core, commit, tree, _, _, expected = self.fixture(root)
                with self.context(core, commit, tree, expected):
                    target = core / '.git' / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text('hostile authority\n')
                    with self.assertRaises(ValueError): representation.storage(core / '.git')
                    self.assertTrue(core.exists())
        with scratch_home() as directory:
            seed, core, commit, tree, _, _, expected = self.fixture(Path(directory))
            with self.context(core, commit, tree, expected):
                (core / '.git/config').write_text('[filter "hostile"]\nclean = touch /escape\n')
                with self.assertRaises(ValueError): representation.storage(core / '.git')
                (core / '.git/config').unlink()
                (core / '.git/config').symlink_to('/foreign')
                with self.assertRaises(ValueError): representation.storage(core / '.git')

    def test_object_source_mode_and_metadata_tamper_never_reach_archive(self):
        for mode in ('source', 'mode', 'object', 'metadata'):
            with self.subTest(mode=mode), scratch_home() as directory:
                root = Path(directory)
                seed, core, commit, tree, _, _, expected = self.fixture(root)
                with self.context(core, commit, tree, expected):
                    if mode in ('source', 'mode'):
                        if mode == 'source': (core / 'documentation.md').write_bytes(b'tampered')
                        else: (core / 'code.py').chmod(0o644)
                        with self.assertRaises(AssertionError): representation.publish(core, seed, {})
                    else:
                        row, _ = self.publish(seed, core, commit, tree)
                        if mode == 'metadata':
                            (seed / representation.STORE / '.git/HEAD').write_bytes(b'bad')
                        else:
                            row['objects']['sha256'] = '0' * 64
                            (seed / representation.RECORD).write_bytes(canonical(row))
                        with patch.object(representation, 'archive') as archive, self.assertRaises(ValueError):
                            representation.restore(seed, root / 'copy', root, lambda value: None)
                        archive.assert_not_called()

    def test_archive_path_hardlink_special_symlink_ancestor_and_duplicate_refuse(self):
        with scratch_home() as directory:
            root = Path(directory)
            for name, kind, link in [('../escape', tarfile.REGTYPE, ''), ('/escape', tarfile.REGTYPE, ''),
                                      ('.git/HEAD', tarfile.REGTYPE, ''), ('hard', tarfile.LNKTYPE, 'file'),
                                      ('fifo', tarfile.FIFOTYPE, ''), ('link', tarfile.SYMTYPE, '../escape')]:
                member = tarfile.TarInfo(name)
                member.type, member.linkname = kind, link
                with self.subTest(name=name), self.assertRaises(ValueError): representation.safe_member(member, root)
            (root / 'ancestor').symlink_to('/foreign')
            with self.assertRaises(ValueError): representation.safe_member(tarfile.TarInfo('ancestor/file'), root)
            spool = root / 'duplicate.tar'
            with tarfile.open(spool, 'w') as bundle:
                for _ in range(2): bundle.addfile(tarfile.TarInfo('duplicate'))
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                representation.extract(spool, root, time.monotonic() + 120, {}, root)

    def test_actual_binary_stream_deadline_size_and_failed_child_are_reaped(self):
        with scratch_home() as directory:
            root = Path(directory)
            for name, argv, deadline, error in [
                ('deadline', [sys.executable, '-c', 'import time; time.sleep(10)'], time.monotonic() + .1, TimeoutError),
                ('size', [sys.executable, '-c', 'import os; os.write(1,b"x"*2048)'], time.monotonic() + 10, ValueError),
                ('exit', [sys.executable, '-c', 'import sys; print("failure",file=sys.stderr); sys.exit(7)'], time.monotonic() + 10, RuntimeError)]:
                audit, report = {}, {}
                with patch.object(representation, 'SOURCE_BYTES', 1024), self.assertRaises(error):
                    representation.stream_archive(argv, root, root / name, deadline, audit, report, root)
                self.assertIsNotNone(audit['exit_code'])
                self.assertIn('source_sha256', audit)
                self.assertLessEqual(len(audit['output']), 32768)

    def test_partial_cleanup_primary_enospc_export_and_existing_destination(self):
        with scratch_home() as directory:
            root = Path(directory)
            seed, core, commit, tree, _, _, expected = self.fixture(root)
            with self.context(core, commit, tree, expected):
                self.publish(seed, core, commit, tree)
                for failure in (TimeoutError('primary deadline'), OSError(28, 'primary ENOSPC')):
                    destination = root / 'copy'
                    def emit(value):
                        if value['stage'] == 'failed': raise OSError('secondary evidence')
                    with patch.object(representation, 'extract', side_effect=failure), self.assertRaises(type(failure)) as caught:
                        representation.restore(seed, destination, root, emit)
                    self.assertIs(caught.exception, failure)
                    self.assertFalse(destination.exists())
                    self.assertTrue(any('cleanup/export' in note for note in caught.exception.__notes__))
                destination.mkdir()
                (destination / 'keep').write_bytes(b'not ours')
                with self.assertRaises(FileExistsError): representation.restore(seed, destination, root, lambda value: None)
                self.assertEqual((destination / 'keep').read_bytes(), b'not ours')

    def test_local_producer_and_unowned_retirement_fail_before_effects(self):
        with patch.object(representation, 'storage') as storage, self.assertRaises(ValueError):
            representation.publish(Path('/opt/seed/hermes-source'), Path('/opt/seed'), {})
        storage.assert_not_called()
        with scratch_home() as directory:
            root = Path(directory)
            core = root / 'partial'
            core.mkdir()
            original = RuntimeError('primary')
            with patch.object(representation.shutil, 'rmtree', side_effect=OSError('secondary cleanup')):
                representation.finalize(core, core / 'spool', {}, original, lambda value: None)
            self.assertTrue(core.exists())
            self.assertTrue(any('cleanup/export' in note for note in original.__notes__))

    def test_actual_limits_include_spool_and_no_inventory_flag_shortcut(self):
        with scratch_home() as directory:
            root = Path(directory)
            (root / 'source').write_bytes(b'x' * 1024)
            (root / 'spool').write_bytes(b'x' * 1024)
            with patch.object(representation, 'WORK_LIMIT', 1536), self.assertRaises(ValueError): representation.peak(root, {})
            with self.assertRaises(ValueError): representation.validate_inventory({'core_representation': {'format': representation.FORMAT}})
            with patch.object(retention, 'BYTE_LIMIT', 2000), self.assertRaises(ValueError): representation.write_inventory(root, b'final')

    def test_ambient_git_authority_is_not_forwarded_and_export_ignore_is_no_success(self):
        with patch.dict(os.environ, {'GIT_DIR': '/foreign', 'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_VALUE_0': 'hostile', 'HTTP_PROXY': 'http://foreign'}):
            env = representation.environment()
            self.assertEqual(env['GIT_ATTR_NOSYSTEM'], '1')
            for key in ('GIT_DIR', 'GIT_CONFIG_COUNT', 'HTTP_PROXY'): self.assertNotIn(key, env)
        with scratch_home() as directory:
            root = Path(directory)
            seed, core, commit, tree, _, _, expected = self.fixture(root)
            with (core / '.gitattributes').open('ab') as stream:
                stream.write(b'documentation.md export-ignore\n')
            argv = ['git', '-C', str(core)]
            subprocess.check_call([*argv, 'add', '-A'], env=representation.environment())
            subprocess.check_call([*argv, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                                   '-c', 'commit.gpgsign=false', 'commit', '-qm', 'hostile archive attributes'], env=representation.environment())
            expected = source_manifest(core)
            spool = root / 'omitted.tar'
            spool.write_bytes(subprocess.check_output([*argv, 'archive', '--format=tar', 'HEAD'], env=representation.environment()))
            destination = root / 'omitted'
            destination.mkdir()
            representation.extract(spool, destination, time.monotonic() + 120, {}, root)
            actual = source_manifest(destination)
            self.assertIn('documentation.md', expected)
            self.assertNotIn('documentation.md', actual)
            self.assertIn('code.py', actual)
            from core_identity import require_identity
            with self.assertRaises(ValueError): require_identity(actual, expected_digest=manifest_digest(expected))

    def test_controller_readbacks_require_actual_source_objects_accounting_and_export(self):
        import hosted_docker
        import docker_acceptance
        from test_docker_bootstrap_repair import ExportDocker, archive
        from test_docker_builder import identity
        with scratch_home() as directory:
            root = Path(directory)
            seed, core, commit, tree, _, _, expected = self.fixture(root)
            with self.context(core, commit, tree, expected):
                row, compact = self.publish(seed, core, commit, tree)
                verifier = root / 'verifier'
                verifier.mkdir()
                inventory = {'core_representation': row}
                representation.seal_inventory(seed, verifier, inventory, compact, row)
                work = root / 'work'
                work.mkdir()
                proof = representation.restore(seed, work / 'source', work, lambda value: None)
                representation.require_materialization(proof, inventory, expected)
                for field in ('source_members', 'expanded_bytes', 'objects', 'git_metadata', 'stage'):
                    altered = copy.deepcopy(proof)
                    altered[field] = None
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        representation.require_materialization(altered, inventory, expected)
                evidence = root / 'evidence'
                evidence.mkdir()
                fake = ExportDocker(evidence, failed=False)
                def run(argv, **kwargs):
                    name = Path(argv[1]).name
                    return archive(name, (seed / name).read_bytes())
                fake.run = run
                outcome = {}
                with patch.object(hosted_docker, 'stopped_bootstrap', return_value=fake.data), patch.object(hosted_docker, 'validate_bootstrap'):
                    hosted_docker.export_representation(fake, evidence, identity(), root, {}, outcome)
                self.assertNotIn('export_error', outcome)
                hosted_docker.compare_representation(evidence, inventory)
                (evidence / 'core-representation-diagnostic.json').write_bytes(b'{"stage":"failed"}')
                with self.assertRaises(ValueError): hosted_docker.compare_representation(evidence, inventory)
                attempt = root / 'attempt'
                (attempt / 'export').mkdir(parents=True)
                with self.assertRaises(FileNotFoundError):
                    docker_acceptance.verify_representation_export(attempt, inventory, {'mode': 'smoke'})
                (attempt / 'export/core-materialization.json').write_bytes(canonical(proof))
                (attempt / 'export/consumer-copy-manifest.json').write_bytes(canonical(expected))
                docker_acceptance.verify_representation_export(attempt, inventory, {'mode': 'smoke'})

    def test_producer_retirement_failure_preserves_git_source_and_primary_diagnostic(self):
        with scratch_home() as directory:
            root = Path(directory)
            seed, core, commit, tree, _, _, expected = self.fixture(root)
            with self.context(core, commit, tree, expected):
                compact = retention.compact_core(core, seed, commit, tree)
                primary = RuntimeError('primary retirement refusal')
                with patch.object(representation, 'producer_retirement', side_effect=primary), self.assertRaises(RuntimeError) as caught:
                    representation.publish(core, seed, compact)
                self.assertIs(caught.exception, primary)
                self.assertEqual(source_manifest(core), expected)
                self.assertTrue((seed / representation.STORE / '.git').is_dir())
                self.assertFalse((seed / representation.RECORD).exists())
                diagnostic = json.loads((seed / 'core-representation-diagnostic.json').read_bytes())
                self.assertEqual(diagnostic['stage'], 'failed')
                self.assertEqual(diagnostic['objects'], compact['objects_after'])
                with self.assertRaises(ValueError): representation.publish(core, seed, compact)
