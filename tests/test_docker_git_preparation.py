# SPDX-License-Identifier: GPL-3.0-or-later
"""Packet-denied producer seams; substituted installs are NOT native acceptance."""
from contextlib import redirect_stdout
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
from test_runtime import runtime_root
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'docker'))
from offline_guard import deny_network
import acquisition_support as acquisition
import hosted_git as preparation
import hosted_setup as setup


def origin():
    return {'url': preparation.URL, 'vcs_info': {'vcs': 'git', 'commit_id': preparation.COMMIT,
                                              'requested_revision': preparation.COMMIT}}


def install_fixture(target):
    """Tiny explicitly synthetic installer output; no package or source acquisition."""
    distribution = target / 'misaki-0.9.4.dist-info'
    distribution.mkdir()
    (distribution / 'METADATA').write_text('Metadata-Version: 2.1\nName: misaki\nVersion: 0.9.4\n')
    (distribution / 'direct_url.json').write_text(json.dumps(origin()))
    (target / 'misaki.py').write_text('# tiny inert fixture\n')
    return distribution


def tiny_git(root):
    root.mkdir()
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.STDOUT).decode()
    git('init', '--quiet')
    (root / 'source.txt').write_text('tiny synthetic source\n')
    git('add', 'source.txt')
    git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
    return git('rev-parse', 'HEAD').strip(), root / '.git'


class GitPreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deny_network()
        from test_docker_pm import NativePMContractTests
        NativePMContractTests.setUpClass()
        cls.core = runtime_root()

    def producer_sequence(self, run, source=None):
        tree = ast.parse(source or (ROOT / 'docker/hosted_setup.py').read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        for node in ast.walk(main):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'run'
                    and node.args and isinstance(node.args[0], ast.List)
                    and any(isinstance(value, ast.Constant) and value.value in {'fetch-tools', 'prepare-git', 'warm'}
                            for value in node.args[0].elts)):
                expression = compile(ast.Expression(node), 'actual-producer-command', 'eval')
                eval(expression, {'run': run, 'sys': sys, 'PUBLIC': setup.PUBLIC})

    def test_producer_prepares_before_fresh_native_warm(self):
        prepared = []
        def run(argv):
            if argv[-1] == 'prepare-git':
                self.assertEqual(argv[0], '/opt/verifier/bin/python')
                prepared.append(argv)
            if argv[-1] == 'warm':
                self.assertEqual(len(prepared), 1, 'fresh union reached without Git preparation')
        self.producer_sequence(run)
        self.assertEqual(len(prepared), 1)

    def test_exact_actual_core_requirement_lock_and_drift_refuse(self):
        contract = preparation.source_contract(self.core)
        self.assertEqual(contract['version'], '0.9.4')
        self.assertEqual(contract['requirement'], 'misaki @ git+https://github.com/NousResearch/misaki.git@f03fd2be7346952a83d3d4845c217fc7667f322d')
        with scratch_home() as directory:
            root = Path(directory)
            for name in ('pyproject.toml', 'uv.lock'):
                (root / name).write_bytes((self.core / name).read_bytes())
            for name in ('pyproject.toml', 'uv.lock'):
                original = (root / name).read_bytes()
                (root / name).write_bytes(original.replace(preparation.COMMIT.encode(), b'a' * 40))
                with self.assertRaisesRegex(ValueError, 'literal immutable'):
                    preparation.source_contract(root)
                (root / name).write_bytes(original)
            (root / 'uv.lock').write_text('[[package]\n')
            with self.assertRaises(ValueError):
                preparation.source_contract(root)

    def test_pinned_uv_cli_contract_and_no_optional_dependency_acquisition(self):
        from pm._uv import _toolchain
        # The retained interpreter's fixture tool store is read only. Help parses
        # actual pinned CLI without resolving, installing, importing or networking.
        declared = os.environ.get('NETWORK_ATLAS_ACCEPTANCE_FIXTURE')
        fixture = Path(declared) if declared else Path(sys.executable).parents[7]
        self.assertTrue((fixture / 'synthetic-atlas-home').is_file(), 'marked disposable tool fixture required')
        stores = [fixture / 'tools', fixture / 'hermes/tools']
        binaries = [store / 'uv-0.12.3-linux-x64/uv' for store in stores
                    if (store / 'uv-0.12.3-linux-x64/uv').is_file()]
        self.assertEqual(len(binaries), 1, 'one existing fixture uv required')
        uv = binaries[0]
        if not uv.is_file():
            self.fail('existing pinned uv help validator missing')
        self.assertEqual(subprocess.check_output([str(uv), '--version'], text=True).strip(),
                         'uv 0.12.3 (x86_64-unknown-linux-gnu)')
        argv = preparation.install_argv(uv, Path('/pinned/python'), Path('/cache'), Path('/owned/target'), offline=True)
        help_result = subprocess.run([*argv, '--help'], capture_output=True, text=True, timeout=10)
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        for flag in ('--no-deps', '--target', '--cache-dir', '--offline', '--no-python-downloads', '--link-mode'):
            self.assertIn(flag, help_result.stdout)
        self.assertEqual(argv[-2:], [preparation.REQUIREMENT, '--offline'])
        self.assertNotIn('--all-extras', argv)
        self.assertNotIn('--extra', argv)
        self.assertNotIn('--system', argv)
        with patch('pm.install.ensure', side_effect=AssertionError('acquisition forbidden')), \
                patch('pm.install._installed_location', return_value=None):
            self.assertIsNone(_toolchain(realize=False))

    def prepare_fixture(self, root, *, fail_phase=None):
        seed = root / 'seed'
        seed.mkdir()
        tools = seed / 'tools'
        tools.mkdir()
        uv, python = tools / 'uv', tools / 'python'
        uv.write_text('inert synthetic tool identity')
        python.write_text('inert synthetic tool identity')
        calls = []
        primary = RuntimeError('synthetic actual command failure')
        def run(argv, cwd, **kwargs):
            calls.append(argv)
            target = Path(argv[argv.index('--target') + 1])
            if target.name == fail_phase:
                raise primary
            install_fixture(target)
            return ''
        return seed, (uv, python), calls, primary, run

    def test_meaningful_online_then_independent_offline_replay_and_owned_disposal(self):
        from pm.environment import _base_environment
        for phase in (None, 'online', 'offline'):
            with self.subTest(failure=phase), scratch_home() as directory:
                root = Path(directory)
                seed, tools, calls, primary, run = self.prepare_fixture(root, fail_phase=phase)
                with patch.object(preparation, 'container_setup_guard'), \
                        patch('pm._uv._toolchain', return_value=tools) as chain, \
                        patch.object(preparation, 'audited_run', side_effect=run), \
                        patch.object(preparation, 'git_identity', return_value={'synthetic': True}):
                    if phase:
                        with self.assertRaises(RuntimeError) as raised:
                            preparation.prepare(self.core, seed)
                        self.assertIs(raised.exception, primary)
                    else:
                        report = preparation.prepare(self.core, seed)
                        self.assertTrue(report['narrow_offline_replay'])
                        self.assertFalse(report['offline_union_proven'])
                        self.assertFalse(report['native_acceptance'])
                        self.assertEqual(report['online']['metadata_sha256'], report['offline']['metadata_sha256'])
                chain.assert_called_once_with(realize=False)
                self.assertEqual(len(calls), 1 if phase == 'online' else 2)
                self.assertNotIn('--offline', calls[0])
                if len(calls) == 2:
                    self.assertIn('--offline', calls[1])
                    self.assertNotEqual(calls[0][calls[0].index('--target') + 1], calls[1][calls[1].index('--target') + 1])
                saved = json.loads((seed / 'git-preparation.json').read_text())
                self.assertTrue(saved['cleanup_verified'])
                self.assertFalse((seed / 'git-preparation').exists())
                self.assertFalse((seed / 'selected.json').exists())
                self.assertNotIn('UV_OFFLINE', _base_environment({'UV_OFFLINE': '1'}))

    def test_actual_pep610_missing_malformed_commit_and_extra_distribution_refuse(self):
        mutations = [None, {}, {'url': preparation.URL, 'vcs_info': {'vcs': 'git', 'commit_id': 'a' * 40}},
                     {'url': 'https://example.invalid/misaki', 'vcs_info': origin()['vcs_info']}]
        for value in mutations:
            with self.subTest(value=value), scratch_home() as directory:
                target = Path(directory)
                distribution = install_fixture(target)
                path = distribution / 'direct_url.json'
                path.unlink() if value is None else path.write_text(json.dumps(value))
                with self.assertRaises((ValueError, FileNotFoundError)):
                    preparation.installed_identity(target, '0.9.4')
        with scratch_home() as directory:
            target = Path(directory)
            distribution = install_fixture(target)
            for payload in ('not json', '[]'):
                (distribution / 'direct_url.json').write_text(payload)
                with self.assertRaises(ValueError):
                    preparation.installed_identity(target, '0.9.4')
            (distribution / 'direct_url.json').write_text(json.dumps(origin()))
            with self.assertRaisesRegex(ValueError, 'name/version'):
                preparation.installed_identity(target, '1.0.0')
            (target / 'extra-1.0.dist-info').mkdir()
            with self.assertRaisesRegex(ValueError, 'narrow'):
                preparation.installed_identity(target, '0.9.4')

    def test_real_tiny_git_commit_readback_hash_and_absent_object_refusal(self):
        with scratch_home() as directory:
            root = Path(directory)
            commit, repository = tiny_git(root / 'source')
            databases = root / 'git-v0/db'
            databases.mkdir(parents=True)
            import shutil
            shutil.copytree(repository, databases / 'opaque-key/.git')
            def run(argv):
                with redirect_stdout(io.StringIO()):
                    return acquisition.audited_run(argv, root, log=acquisition.CommandLog())
            with patch.object(preparation, 'COMMIT', commit):
                report = preparation.git_identity(root, run)
            data = subprocess.check_output(['git', '--git-dir', str(repository), 'cat-file', 'commit', commit])
            self.assertEqual(report['commit'], commit)
            self.assertEqual(report['commit_sha256'], hashlib.sha256(data).hexdigest())
            with self.assertRaisesRegex(ValueError, 'absent'):
                preparation.git_identity(root, run)
            with patch.object(preparation, 'COMMIT', commit), self.assertRaisesRegex(ValueError, 'mismatch'):
                preparation.git_identity(root, lambda argv: 'tree ' + 'a' * 40 + '\nforged\n')

    def test_direct_local_guard_missing_tools_and_existing_owned_directory_precede_effects(self):
        with scratch_home() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, 'hosted-first'):
                preparation.prepare(self.core, root / 'absent')
            self.assertFalse((root / 'absent').exists())
            from acceptance_support import fixture_environment
            refusal = subprocess.run([sys.executable, str(ROOT / 'docker/hosted_setup.py'), 'prepare-git'],
                                     env=fixture_environment(root), capture_output=True, text=True, timeout=15)
            self.assertNotEqual(refusal.returncode, 0)
            self.assertIn('hosted-first diagnostics mismatch', refusal.stderr)
            seed, tools, _, _, _ = self.prepare_fixture(root)
            with patch.object(preparation, 'container_setup_guard'), patch('pm._uv._toolchain', return_value=None), \
                    self.assertRaisesRegex(ValueError, 'toolchain'):
                preparation.prepare(self.core, seed)
            self.assertFalse((seed / 'git-preparation').exists())
            existing = seed / 'git-preparation'
            existing.mkdir()
            (existing / 'owner.txt').write_text('not ours')
            with patch.object(preparation, 'container_setup_guard'), patch('pm._uv._toolchain', return_value=tools), \
                    self.assertRaises(FileExistsError):
                preparation.prepare(self.core, seed)
            self.assertEqual((existing / 'owner.txt').read_text(), 'not ours')

    def test_resources_real_owned_child_output_deadline_and_primary_error(self):
        with scratch_home() as directory:
            root = Path(directory)
            cache = root / 'cache'
            temporary = root / 'git-preparation'
            cache.mkdir()
            temporary.mkdir()
            (cache / 'tiny').write_bytes(b'ab')
            with self.assertRaisesRegex(ValueError, 'bound'):
                preparation.usage(cache, entries=1, byte_limit=1)
            (cache / 'pipe').symlink_to(root / 'outside')
            self.assertEqual(preparation.usage(cache, entries=2, byte_limit=2)['file_bytes'], 2)
            child = root / 'child.py'
            child.write_text('import os, time\nprint(os.getpid(), flush=True)\ntime.sleep(30)\n')
            import time
            runner = preparation.runner_for(cache, temporary, time.monotonic() + .25, dict(os.environ))
            audit = {}
            with self.assertRaises((TimeoutError, ValueError)):
                runner([sys.executable, str(child)], root, audit=audit)
            self.assertEqual(audit['exit_code'], -9)
            self.assertFalse(Path('/proc/' + audit['output'].strip()).exists())
            child.write_text('print("x" * (1024**2 + 1))\n')
            runner = preparation.runner_for(cache, temporary, time.monotonic() + 10, dict(os.environ))
            with self.assertRaisesRegex(ValueError, 'output bound'):
                runner([sys.executable, str(child)], root, audit={})
            primary = RuntimeError('primary')
            with patch.object(preparation, 'dispose', side_effect=OSError('cleanup')), \
                    patch.object(preparation, 'retain', side_effect=ValueError('export')):
                preparation.finish(temporary, root, {}, primary)
            self.assertEqual(len(primary.__notes__), 2)
            with patch.object(preparation, 'REPORT_LIMIT', 2), self.assertRaisesRegex(ValueError, 'report bound'):
                preparation.retain(root, {'large': True})

    def test_failed_preparation_never_reaches_native_warm_or_hides_primary(self):
        primary = RuntimeError('preparation failed')
        phases = []
        def run(argv):
            phases.append(argv[-1])
            if argv[-1] == 'prepare-git':
                raise primary
        with self.assertRaises(RuntimeError) as raised:
            self.producer_sequence(run)
        self.assertIs(raised.exception, primary)
        self.assertEqual(phases, ['fetch-tools', 'prepare-git'])

    def test_independent_export_requires_complete_proof_and_ownership_before_reads(self):
        import hosted_docker as hosted
        from test_docker_bootstrap_repair import ExportDocker, archive
        from test_docker_builder import identity
        # Explicitly synthetic exporter proof; no actual acquisition is claimed.
        installed = {'direct_url': origin(), 'version': '0.9.4', 'metadata_sha256': 'a' * 64,
                     'direct_url_sha256': 'b' * 64, 'entries': 3, 'file_bytes': 123}
        proof = {'schema': 1, 'stage': 'complete', 'narrow_offline_replay': True, 'cleanup_verified': True,
                 'native_acceptance': False, 'offline_union_proven': False,
                 'contract': preparation.source_contract(self.core),
                 'git': {'commit': preparation.COMMIT, 'tree': 'a' * 40, 'commit_sha256': 'c' * 64},
                 'online': installed, 'offline': installed,
                 'cache_before': {'entries': 0, 'file_bytes': 0}, 'cache_after': {'entries': 3, 'file_bytes': 123},
                 'commands': [preparation.install_argv(Path('/opt/seed/tools/uv'), Path('/opt/seed/tools/python'),
                              Path('/opt/seed/hermes/cache/uv'), Path('/opt/seed/git-preparation') / phase,
                              offline=phase == 'offline') for phase in ('online', 'offline')]}
        values = [b'{}', b'x' * (32 * 1024 + 1), b'not-json',
                  json.dumps({'stage': 'complete', 'narrow_offline_replay': True,
                              'cleanup_verified': True}).encode(), json.dumps(proof).encode()]
        for payload in values:
            with self.subTest(payload_bytes=len(payload)), scratch_home() as directory:
                root = Path(directory)
                fake = ExportDocker(root, failed=False)
                fake.run = lambda argv, **kwargs: archive('git-preparation.json', payload)
                outcome = {'error': 'actual primary'}
                with patch.object(hosted, 'validate_bootstrap'):
                    hosted.export_git_preparation(fake, root, identity(), root, {}, outcome)
                self.assertEqual(outcome['error'], 'actual primary')
                if payload == values[-1]:
                    self.assertNotIn('export_error', outcome)
                    self.assertEqual(outcome['git_preparation']['sha256'], hashlib.sha256(payload).hexdigest())
                else:
                    self.assertIn('export_error', outcome)
        with scratch_home() as directory:
            root = Path(directory)
            fake = ExportDocker(root, failed=False)
            fake.data['Config']['Labels']['org.network-atlas.acceptance.owner'] = 'not-owner'
            outcome = {'error': 'actual primary'}
            hosted.export_git_preparation(fake, root, identity(), root, {}, outcome)
            self.assertFalse(fake.calls)
            self.assertEqual(outcome['error'], 'actual primary')
            self.assertIn('export_error', outcome)


if __name__ == '__main__':
    unittest.main()
