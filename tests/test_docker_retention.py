# SPDX-License-Identifier: GPL-3.0-or-later
"""Tiny real reconstructed Git and retention seams, not hosted/native acceptance."""
import ast
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
import random
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'docker'))
from offline_guard import deny_network
import acquisition_support as acquisition
import hosted_setup as setup


class RetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deny_network()

    def test_actual_producer_reduces_before_unchanged_inventory_guard(self):
        # Execute actual producer calls in their source order, not arbitrary mock argv.
        source = ast.parse((ROOT / 'docker/hosted_setup.py').read_text())
        main = next(node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        calls = []
        for statement in main.body:
            for node in ast.walk(statement):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {'compact_core', 'retained_inventory'}:
                    calls.append(node.func.id)
        self.assertEqual(calls, ['compact_core', 'retained_inventory'],
                         'producer reaches retained guard without meaningful compaction/accounting')

    def fixture(self, root):
        source = root / 'source'
        source.mkdir()
        def git(*args, cwd=source):
            return subprocess.check_output(['git', '-C', str(cwd), *args], stderr=subprocess.STDOUT)
        git('init', '-q')
        (source / 'parent').write_text('not present in child source\n')
        git('add', '.')
        identity = ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false']
        git(*identity, 'commit', '-qm', 'parent')
        parent = git('rev-parse', 'HEAD').decode().strip()
        (source / 'parent').unlink()
        shared = random.Random(0).randbytes(8192)
        for number in range(16):
            (source / f'source-{number}').write_bytes(shared + str(number).encode())
        (source / 'source-0').chmod(0o755)
        (source / 'link').symlink_to('source-0')
        git('add', '-A')
        git(*identity, 'commit', '-qm', 'child')
        commit, tree = [git('rev-parse', value).decode().strip() for value in ('HEAD', 'HEAD^{tree}')]
        archive, obj = root / 'source.tar', root / 'commit'
        archive.write_bytes(git('archive', 'HEAD'))
        obj.write_bytes(git('cat-file', 'commit', 'HEAD'))
        seed = root / 'seed'
        core = seed / 'hermes-source'
        core.mkdir(parents=True)
        import tarfile
        with tarfile.open(archive) as bundle:
            bundle.extractall(core, filter='data')
        with patch.dict(os.environ, {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}, clear=True), redirect_stdout(io.StringIO()), patch.object(acquisition, 'COMMAND_LOG', acquisition.CommandLog()):
            acquisition.reconstruct_public_core(core, obj, commit, tree)
        # An actual unreachable object must survive; repacking only refs is not all objects.
        unreachable = subprocess.check_output(['git', '-C', str(core), 'hash-object', '-w', '--stdin'], input=b'unreachable fixture\n').decode().strip()
        return seed, core, commit, tree, parent, unreachable

    def compact(self, seed, core, commit, tree):
        import hosted_retention as retention
        from core_identity import source_manifest, manifest_digest
        digest = manifest_digest(source_manifest(core))
        with patch.dict(os.environ, {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}, clear=True), patch.object(retention, 'owned_layout'), patch.object(retention, 'require_identity', side_effect=lambda value: self.assertEqual(manifest_digest(value), digest)), redirect_stdout(io.StringIO()), patch.object(acquisition, 'COMMAND_LOG', acquisition.CommandLog()):
            return retention.compact_core(core, seed, commit, tree)

    def test_real_git_pack_retains_every_object_missing_parent_source_modes_and_links(self):
        from core_identity import source_manifest
        with scratch_home() as directory:
            seed, core, commit, tree, parent, unreachable = self.fixture(Path(directory))
            before = source_manifest(core)
            report = self.compact(seed, core, commit, tree)
            self.assertLess(report['after']['bytes'], report['before']['bytes'])
            self.assertEqual(report['objects_before'], report['objects_after'])
            self.assertEqual(before, source_manifest(core))
            self.assertEqual((core / '.git/shallow').read_text(), commit + '\n')
            self.assertEqual(subprocess.check_output(['git', '-C', str(core), 'cat-file', 'blob', unreachable]), b'unreachable fixture\n')
            missing = subprocess.run(['git', '-C', str(core), 'cat-file', '-e', parent], capture_output=True)
            self.assertNotEqual(missing.returncode, 0)
            self.assertEqual(json.loads((seed / 'retained-inventory.json').read_text())['compaction']['stage'], 'complete')

    def test_local_wrong_layout_ambient_git_and_alternate_object_store_refuse_before_effects(self):
        import hosted_retention as retention
        with patch.object(retention, 'audited_run') as run, self.assertRaises(ValueError):
            retention.compact_core(Path('/opt/seed/hermes-source'), Path('/opt/seed'), 'a' * 40, 'b' * 40)
        run.assert_not_called()
        with scratch_home() as directory:
            seed, core, commit, tree, _, _ = self.fixture(Path(directory))
            for mode in ('alternate', 'symlink', 'shallow', 'ambient'):
                with self.subTest(mode=mode):
                    target = core / '.git/objects/info/alternates'
                    if mode == 'alternate': target.write_text('/foreign\n')
                    if mode == 'symlink': target.symlink_to('/foreign')
                    if mode == 'shallow': (core / '.git/shallow').write_text('0' * 40 + '\n')
                    with patch.object(retention, 'owned_layout'), patch.dict(os.environ, {'GIT_CONFIG_COUNT': '0'} if mode == 'ambient' else {}), patch.object(retention, 'audited_run') as run, self.assertRaises(ValueError):
                        retention.compact_core(core, seed, commit, tree)
                    run.assert_not_called()
                    target.unlink(missing_ok=True)
                    (core / '.git/shallow').write_text(commit + '\n')

    def test_corrupt_objects_or_manifest_drift_refuse_without_success(self):
        import hosted_retention as retention
        with scratch_home() as directory:
            seed, core, commit, tree, _, unreachable = self.fixture(Path(directory))
            object_path = core / '.git/objects' / unreachable[:2] / unreachable[2:]
            object_path.chmod(0o600)
            object_path.write_bytes(b'corrupted actual loose object')
            with self.assertRaises(RuntimeError): self.compact(seed, core, commit, tree)
            proof = json.loads((seed / 'retained-inventory.json').read_text())
            self.assertEqual(proof['compaction']['stage'], 'failed')
        with self.assertRaises(ValueError): retention.object_rows('not-an-object\n')
        with self.assertRaises(ValueError): retention.object_rows(('a' * 40 + ' blob 1\n') * 2)

    def test_bounded_component_totals_and_current_guard_keep_failure_evidence(self):
        import hosted_retention as retention
        with scratch_home() as directory:
            seed, verifier = Path(directory) / 'seed', Path(directory) / 'verifier'
            (seed / 'hermes-source/.git').mkdir(parents=True)
            verifier.mkdir()
            (seed / 'hermes-source/source').write_bytes(b'12345')
            (seed / 'hermes-source/.git/object').write_bytes(b'123')
            (seed / 'cache').write_bytes(b'1234567')
            (seed / 'link').symlink_to('cache')
            (verifier / 'tool').write_bytes(b'12')
            with patch.object(retention, 'owned_layout'), patch.object(retention, 'BYTE_LIMIT', 10), self.assertRaisesRegex(ValueError, 'public retained inventory bound'):
                retention.retained_inventory(seed, verifier, {})
            report = json.loads((seed / 'retained-inventory.json').read_text())
            self.assertTrue(report['seed']['complete'])
            self.assertEqual(report['seed']['bytes'], 15)
            self.assertEqual(report['seed']['components']['hermes-source/.git']['bytes'], 3)
            self.assertEqual(report['violations'], ['seed:bytes'])
            with patch.object(retention, 'owned_layout'), patch.object(retention, 'FILE_LIMIT', 1), self.assertRaises(ValueError):
                retention.retained_inventory(seed, verifier, {})
            self.assertIn('seed:files', json.loads((seed / 'retained-inventory.json').read_text())['violations'])

    def test_success_requires_complete_compaction_report_and_current_limits(self):
        import hosted_retention as retention
        with scratch_home() as directory:
            seed, core, commit, tree, _, _ = self.fixture(Path(directory))
            compaction = self.compact(seed, core, commit, tree)
            verifier = Path(directory) / 'verifier'
            verifier.mkdir()
            with patch.object(retention, 'owned_layout'):
                report = retention.retained_inventory(seed, verifier, compaction)
            retention.require_complete(report)
            self.assertEqual((retention.BYTE_LIMIT, retention.FILE_LIMIT), (1073741824, 100000))
            for key in ('stage', 'violations', 'compaction', 'seed'):
                bad = dict(report)
                bad[key] = None
                with self.subTest(key=key), self.assertRaises(ValueError): retention.require_complete(bad)

    def test_failed_child_primary_survives_diagnostic_failure_and_no_pruning(self):
        import hosted_retention as retention
        with scratch_home() as directory:
            seed, core, commit, tree, _, _ = self.fixture(Path(directory))
            original = retention.retain
            writes = 0
            def retain(*args):
                nonlocal writes
                writes += 1
                if writes > 1: raise OSError('secondary diagnostic')
                original(*args)
            with patch.dict(os.environ, {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}, clear=True), patch.object(retention, 'require_identity'), patch.object(retention, 'owned_layout'), patch.object(retention, 'retain', side_effect=retain), patch.object(retention, 'audited_run', side_effect=RuntimeError('primary child')) as run, self.assertRaisesRegex(RuntimeError, 'primary child') as raised:
                retention.compact_core(core, seed, commit, tree)
            self.assertEqual(run.call_count, 1)
            self.assertIn('retention diagnostic failed: OSError', raised.exception.__notes__)

    def test_independent_export_ownership_size_and_primary_error(self):
        import hosted_docker as hosted
        from unittest.mock import Mock
        with scratch_home() as directory:
            evidence = Path(directory)
            outcome = {'error': 'primary'}
            with patch.object(hosted, 'stopped_bootstrap', side_effect=ValueError('ownership')) as stopped, patch.object(hosted, 'copy_seed_member') as copy:
                hosted.export_retention(Mock(), evidence, Mock(), evidence, {}, outcome)
            stopped.assert_called_once()
            copy.assert_not_called()
            self.assertEqual(outcome['error'], 'primary')
            self.assertIn('ownership', outcome['export_error'])
            with patch.object(hosted, 'stopped_bootstrap', return_value={'Id': 'owned', 'State': {'ExitCode': 0}}), patch.object(hosted, 'validate_bootstrap'), patch.object(hosted, 'copy_seed_member', return_value={'status': 'missing'}):
                result = {}
                hosted.export_retention(Mock(), evidence, Mock(), evidence, {}, result)
            self.assertIn('required retained inventory absent', result['export_error'])

    def test_real_same_budget_red_then_pack_green_with_no_source_or_cache_exclusions(self):
        import hosted_retention as retention
        with scratch_home() as directory:
            seed, core, commit, tree, _, _ = self.fixture(Path(directory))
            verifier = Path(directory) / 'verifier'
            verifier.mkdir()
            # Lowered fixture-only byte limit: same accounting/policy before and
            # after real Git packing. No sparse GiB fixture or fabricated totals.
            with patch.object(retention, 'owned_layout'), patch.object(retention, 'BYTE_LIMIT', 200000), self.assertRaisesRegex(ValueError, 'public retained inventory bound'):
                retention.retained_inventory(seed, verifier, {})
            red = json.loads((seed / 'retained-inventory.json').read_text())
            self.assertGreater(red['seed']['bytes'], 200000)
            compaction = self.compact(seed, core, commit, tree)
            with patch.object(retention, 'owned_layout'), patch.object(retention, 'BYTE_LIMIT', 200000):
                green = retention.retained_inventory(seed, verifier, compaction)
            self.assertLess(green['seed']['bytes'], 200000)
            print('Actual tiny retained-budget RED/GREEN: ' + json.dumps({'red_bytes': red['seed']['bytes'], 'green_bytes': green['seed']['bytes'], 'limit': 200000, 'compaction': compaction}, sort_keys=True))

    def test_real_owned_runner_output_deadline_and_unrelated_child_survives(self):
        import hosted_retention as retention
        with scratch_home() as directory:
            core = Path(directory)
            (core / '.git').mkdir()
            unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'])
            try:
                with patch.object(acquisition, 'COMMAND_LOG', acquisition.CommandLog()), redirect_stdout(io.StringIO()):
                    run = retention.runner(core)
                    with self.assertRaises(RuntimeError): run([sys.executable, '-c', 'raise SystemExit(7)'])
                    with self.assertRaisesRegex(ValueError, 'output bound'): run([sys.executable, '-c', 'import os; os.write(1, b"x" * (4194304 + 1))'])
                    actual = retention.bounded_run
                    def short(argv, cwd, **kwargs):
                        kwargs['timeout'] = 0.05
                        return actual(argv, cwd, **kwargs)
                    with patch.object(retention, 'bounded_run', side_effect=short), self.assertRaises(TimeoutError):
                        run([sys.executable, '-c', 'import time; time.sleep(20)'])
                self.assertIsNone(unrelated.poll())
                with patch.object(retention.time, 'monotonic', side_effect=[0, 0, 121, 121]), patch.object(retention, 'bounded_run') as spawn, self.assertRaises(TimeoutError):
                    retention.runner(core)(['git', 'fsck'])
                spawn.assert_not_called()
            finally:
                unrelated.kill()
                unrelated.wait()

    def test_pack_or_object_drift_failure_prevents_pruning_success_and_retains_stage(self):
        import hosted_retention as retention
        for fault in ('repack', 'verify-pack', 'objects', 'source'):
            with self.subTest(fault=fault), scratch_home() as directory:
                seed, core, commit, tree, _, _ = self.fixture(Path(directory))
                actual = retention.audited_run
                def run(argv, *args, **kwargs):
                    if fault in argv: raise RuntimeError('real boundary ' + fault)
                    result = actual(argv, *args, **kwargs)
                    if fault == 'source' and 'prune-packed' in argv:
                        (core / 'source-1').write_text('mutated')
                    return result
                rows = retention.object_rows
                count = 0
                def drift(output):
                    nonlocal count
                    count += 1
                    value = rows(output)
                    if fault == 'objects' and count == 2: value['sha256'] = '0' * 64
                    return value
                with patch.object(retention, 'audited_run', side_effect=run), patch.object(retention, 'object_rows', side_effect=drift), self.assertRaises((RuntimeError, ValueError, AssertionError)):
                    self.compact(seed, core, commit, tree)
                self.assertEqual(json.loads((seed / 'retained-inventory.json').read_text())['compaction']['stage'], 'failed')

    def test_export_actual_report_size_type_and_forged_success_refuse(self):
        import hosted_docker as hosted
        import hosted_retention as retention
        import core_identity as identity
        from test_docker_bootstrap_repair import archive
        from unittest.mock import Mock
        with scratch_home() as directory:
            evidence = Path(directory)
            for payload in (b'x' * (32768 + 1), b'{}', b'{'):
                # Keep the production evidence leaf flat; fixture roots are siblings.
                fake = Mock()
                fake.run.return_value = archive('retained-inventory.json', payload)
                data = {'Id': 'owned', 'State': {'ExitCode': 0}}
                with patch.object(hosted, 'stopped_bootstrap', return_value=data), patch.object(hosted, 'validate_bootstrap'):
                    result = {'error': 'primary'}
                    hosted.export_retention(fake, evidence, Mock(), evidence, {}, result)
                self.assertIn('export_error', result)
                self.assertEqual(result['error'], 'primary')
                fake.run.assert_called_once()
            root = evidence
            evidence = root / 'flat-export'
            evidence.mkdir()
            seed, core, commit, tree, _, _ = self.fixture(root)
            compact = self.compact(seed, core, commit, tree)
            verifier = root / 'verifier'
            verifier.mkdir()
            with patch.object(retention, 'owned_layout'):
                proof = retention.retained_inventory(seed, verifier, compact)
            fake.run.return_value = archive('retained-inventory.json', json.dumps(proof).encode())
            with patch.object(hosted, 'stopped_bootstrap', return_value=data), patch.object(hosted, 'validate_bootstrap'), patch.object(hosted, 'HERMES_COMMIT', commit), patch.object(hosted, 'CORE_TREE', tree), patch.object(identity, 'CORE_SOURCE_DIGEST', compact['source_digest']):
                result = {}
                hosted.export_retention(fake, evidence, Mock(), evidence, {}, result)
                self.assertNotIn('export_error', result)
                self.assertEqual(result['retained_inventory']['status'], 'present')
                with patch.object(hosted, 'CORE_TREE', '0' * 40):
                    result = {}
                    hosted.export_retention(fake, evidence, Mock(), evidence, {}, result)
                self.assertIn('source identity differs', result['export_error'])

    def test_accounting_special_files_deadline_and_report_size_refuse_without_success(self):
        import hosted_retention as retention
        with scratch_home() as directory:
            root = Path(directory)
            (root / 'file').write_bytes(b'x')
            with patch.object(retention.time, 'monotonic', side_effect=[0, 11]), self.assertRaises(ValueError):
                retention.measure(root, {})
            os.mkfifo(root / 'fifo')
            with self.assertRaisesRegex(ValueError, 'special'): retention.measure(root, {})
            (root / 'fifo').unlink()
            with self.assertRaisesRegex(ValueError, 'report bound'):
                retention.retain(root, {'unbounded': 'x' * 32768})
            self.assertFalse((root / 'retained-inventory.pending').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
