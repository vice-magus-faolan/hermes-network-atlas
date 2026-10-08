# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded actual diagnostic seams; never acquire or admit a native plugin."""
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
sys.path.insert(0, str(ROOT / 'scripts'))
from offline_guard import deny_network
import docker_inside as inside
from acceptance_support import fixture_environment


def inputs(root):
    source = root / 'hermes-source'
    source.mkdir()
    (source / 'pyproject.toml').write_text('[project]\nname="tiny"\n[tool.uv]\nexclude-newer="14 days"\n')
    (source / 'uv.lock').write_text('version=1\n[options]\nexclude-newer="14 days"\n')
    cache = root / 'hermes/cache/uv'
    cache.mkdir(parents=True)
    metadata = cache / 'wheels-v5/url/abc/kittentts/revision.http'
    metadata.parent.mkdir(parents=True)
    metadata.write_bytes(b'actual tiny opaque cache metadata')
    return source, cache, metadata


class UnionDiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deny_network()
        from test_docker_pm import NativePMContractTests
        NativePMContractTests.setUpClass()

    def test_real_failed_enable_retains_primary_log_in_export(self):
        with scratch_home() as directory:
            root = Path(directory)
            source, _, _ = inputs(root)
            export = root / 'export'
            export.mkdir()
            child = root / 'enable-child.py'
            child.write_text("print('Prepare these with Hermes through PM now? [y/N]:', flush=True)\n"
                             "input()\nprint('actual enable failure', flush=True)\nraise SystemExit(7)\n")
            with patch.object(inside, 'FIXTURE', root), patch.object(inside, 'EXPORT', export), \
                    patch.object(inside, 'ROOT', ROOT), patch.object(inside, 'git_head', return_value='a'*40), \
                    patch('hosted_contract.require_hosted', return_value={}), \
                    patch.object(inside, 'tool_diagnostics', return_value=None), \
                    patch.object(inside, 'execute', return_value=(0, 'installation boundary intercepted')), \
                    self.assertRaises(RuntimeError) as raised:
                inside.hosted_install([sys.executable, str(child), str(source)], root / 'candidate',
                                      source, fixture_environment(root))
            self.assertTrue((export / 'enable.log').is_file(), 'primary enable log lost on exception')
            self.assertIn(b'actual enable failure', (export / 'enable.log').read_bytes())
            self.assertIn('7', str(raised.exception))

    def test_real_enable_success_failure_audit_and_no_duplicate_output(self):
        from prepare_acceptance import enable
        for code in (0, 9):
            with self.subTest(code=code), scratch_home() as directory:
                root = Path(directory)
                child = root / 'child.py'
                child.write_text(f"print('x'*100000, flush=True)\nraise SystemExit({code})\n")
                if code:
                    with self.assertRaisesRegex(RuntimeError, 'exit=9') as raised:
                        enable([sys.executable, str(child)], root, fixture_environment(root))
                    self.assertLess(len(str(raised.exception)), 1024)
                else:
                    enable([sys.executable, str(child)], root, fixture_environment(root))
                audit = json.loads((root / 'enable-command.json').read_text())
                payload = (root / 'enable.log').read_bytes()
                self.assertEqual(audit['exit_code'], code)
                self.assertEqual(audit['output_bytes'], len(payload))
                self.assertEqual(audit['output_sha256'], hashlib.sha256(payload).hexdigest())
                self.assertTrue(audit['output_complete'])
                self.assertEqual(audit['argv'], [sys.executable, str(child)])

    def test_cache_metadata_hashes_bounds_symlinks_and_no_mutation(self):
        from native_union_diagnostics import cache_snapshot
        with scratch_home() as directory:
            root = Path(directory)
            _, cache, metadata = inputs(root)
            before = metadata.read_bytes()
            report = cache_snapshot(cache)
            row = report['kittentts'][0]
            self.assertEqual(row['sha256'], hashlib.sha256(before).hexdigest())
            self.assertEqual(row['bytes'], len(before))
            self.assertEqual(report['entries'], 5)
            self.assertEqual(metadata.read_bytes(), before)
            metadata.unlink()
            metadata.symlink_to(root / 'absent')
            report = cache_snapshot(cache)
            self.assertEqual(report['kittentts'][0]['type'], 'symlink')
            self.assertNotIn('sha256', report['kittentts'][0])
            with patch('native_union_diagnostics.ENTRY_LIMIT', 1), self.assertRaisesRegex(ValueError, 'count'):
                cache_snapshot(cache)

    def test_actual_source_lock_settings_and_member_declaration_are_read_only(self):
        from native_union_diagnostics import snapshot
        with scratch_home() as directory:
            root = Path(directory)
            source, cache, _ = inputs(root)
            member = root / 'plugin'
            member.mkdir()
            (member / 'plugin.yaml').write_text('python_dependencies: ["ruamel.yaml>=0.18.16,<0.19"]')
            before = (source / 'pyproject.toml').read_bytes()
            report = snapshot(source, cache, member=member)
            self.assertEqual(report['source']['settings']['exclude-newer'], '14 days')
            self.assertEqual(report['source']['lock_options']['exclude-newer'], '14 days')
            self.assertEqual(report['member']['plugin.yaml']['sha256'], hashlib.sha256((member / 'plugin.yaml').read_bytes()).hexdigest())
            self.assertEqual((source / 'pyproject.toml').read_bytes(), before)
            self.assertFalse(report['native_acceptance'])
            self.assertEqual(report['exact_cache_deficiency'], 'UNKNOWN')

    def test_real_pinned_pm_argv_environment_and_api_offline_contract(self):
        from test_runtime import runtime_root
        core = runtime_root()
        sys.path.insert(0, str(core))
        from pm.environment import PythonEnvironment, _base_environment
        from pm.runtime import runtime_environment
        import inspect
        self.assertEqual(Path(sys.modules['pm.environment'].__file__).resolve(), core / 'pm/environment.py')
        env = {'UV_OFFLINE': '1', 'UV_CACHE_DIR': '/not-authority', 'HERMES_VERBOSE': '1', 'RUST_LOG': 'uv=debug'}
        self.assertNotIn('UV_OFFLINE', _base_environment(env))
        with patch.dict(os.environ, env, clear=True):
            self.assertNotIn('UV_OFFLINE', runtime_environment())
        self.assertNotIn('offline', inspect.signature(PythonEnvironment.sync).parameters)
        with scratch_home() as directory:
            root = Path(directory)
            engine = PythonEnvironment(uv=root/'uv', python=root/'python', destination=root/'venv', cache=root/'cache', env=env)
            calls = []
            def capture(argv, **kwargs):
                calls.append((argv, kwargs))
                return subprocess.CompletedProcess(argv, 0, '', '')
            with patch('pm.environment.subprocess.run', side_effect=capture):
                engine.lock(root)
                engine.sync(root, frozen=True)
            self.assertEqual(calls[0][0], [str(root/'uv'), 'lock', '--python', str(root/'python')])
            self.assertNotIn('--offline', calls[1][0])
            self.assertNotIn('UV_OFFLINE', calls[0][1]['env'])
            self.assertEqual(calls[0][1]['env']['UV_CACHE_DIR'], str(root/'cache'))
            self.assertEqual(calls[0][1]['env']['RUST_LOG'], 'uv=debug')

    def test_diagnostic_export_error_never_replaces_actual_enable_failure(self):
        with scratch_home() as directory:
            root = Path(directory)
            source, _, _ = inputs(root)
            primary = RuntimeError('actual enable primary')
            with patch.object(inside, 'FIXTURE', root), patch.object(inside, 'EXPORT', root), \
                    patch('prepare_acceptance.enable', side_effect=primary), \
                    patch.object(inside, 'union_diagnostics', return_value=None), \
                    patch.object(inside.BoundedDirectory, 'copy', side_effect=OSError('export seam')), \
                    self.assertRaises(RuntimeError) as raised:
                inside.hosted_enable(['not-executed'], source, fixture_environment(root))
            self.assertIs(raised.exception, primary)
            self.assertTrue(any('enable evidence export' in note for note in primary.__notes__))

    def test_producer_before_after_readback_survives_warm_failure(self):
        sys.path.insert(0, str(ROOT / 'docker'))
        import hosted_setup as setup
        with scratch_home() as directory:
            root = Path(directory)
            source, _, _ = inputs(root)
            member = root / 'dependency-input'
            member.mkdir()
            (member / 'plugin.yaml').write_text('{}')
            primary = RuntimeError('actual native warm failure seam')
            output = io.StringIO()
            with patch.object(setup, 'CORE', source), patch.object(setup, 'SEED', root), \
                    patch.object(setup, 'container_setup_guard'), \
                    patch('pm.sync_venv', side_effect=primary), patch.dict(os.environ, fixture_environment(root)), \
                    patch.object(setup, 'source_warm_diagnostics', wraps=setup.source_warm_diagnostics), \
                    patch('sys.stdout', output), self.assertRaises(RuntimeError) as raised:
                setup.warm()
            self.assertIs(raised.exception, primary)
            rows = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual([row['union_phase'] for row in rows], ['before-warm', 'after-warm-failure'])
            self.assertTrue(all(row['native_acceptance'] is False for row in rows))

    def test_diagnostic_bounds_fail_closed_without_fabricating_cache_evidence(self):
        from native_union_diagnostics import snapshot, emit
        with scratch_home() as directory:
            root = Path(directory)
            source, cache, _ = inputs(root)
            with patch('native_union_diagnostics.REPORT_LIMIT', 16), self.assertRaisesRegex(ValueError, 'report bound'):
                emit(snapshot(source, cache), lambda row: None)
            (source / 'pyproject.toml').write_text('invalid = [')
            with self.assertRaises(ValueError):
                snapshot(source, cache)

    def test_near_cap_enable_output_deadline_and_owned_cleanup_are_bounded(self):
        from prepare_acceptance import enable, enable_output
        import time
        with scratch_home() as directory:
            root = Path(directory)
            child = root / 'child.py'
            child.write_text("import os\nos.write(1, b'x' * (4*1024**2 - 2048))\nraise SystemExit(11)\n")
            with self.assertRaisesRegex(RuntimeError, 'exit=11') as raised:
                enable([sys.executable, str(child)], root, fixture_environment(root))
            payload = (root / 'enable.log').read_bytes()
            self.assertEqual(len(payload), 4*1024**2 - 2048)
            self.assertLess(len(str(raised.exception).encode()), 1024)
            self.assertEqual(json.loads((root/'enable-command.json').read_text())['output_bytes'], len(payload))
        with scratch_home() as directory:
            root = Path(directory)
            child = root / 'child.py'
            child.write_text("import os,time\nprint(os.getpid(), flush=True)\ntime.sleep(10)\n")
            with patch('prepare_acceptance.enable_output',
                       side_effect=lambda master, output, deadline: enable_output(master, output, time.monotonic()+0.2)), \
                    self.assertRaisesRegex(TimeoutError, 'deadline'):
                enable([sys.executable, str(child)], root, fixture_environment(root))
            audit = json.loads((root/'enable-command.json').read_text())
            self.assertFalse(audit['output_complete'])
            pid = int((root/'enable.log').read_bytes().strip())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_independent_producer_file_export_bounds_and_guard_precede_reads(self):
        from native_union_diagnostics import retain_producer
        import hosted_docker as hosted
        from test_docker_bootstrap_repair import ExportDocker, archive
        from test_docker_builder import identity
        with scratch_home() as directory:
            root = Path(directory)
            retain_producer(root, 'before-warm', {'native_acceptance': False})
            retain_producer(root, 'after-warm-failure', {'error': 'actual tiny failure'})
            retained = (root/'union-diagnostics.json').read_bytes()
            self.assertEqual(set(json.loads(retained)), {'before-warm', 'after-warm-failure'})
            self.assertEqual((root/'union-diagnostics.json').stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(ValueError, 'repeated/count'):
                retain_producer(root, 'before-warm', {})
            fake = ExportDocker(root)
            outcome = {'error': 'actual primary'}
            with patch.object(hosted, 'validate_bootstrap'):
                hosted.export_union_diagnostics(fake, root, identity(), root, {}, outcome)
            self.assertEqual(outcome['error'], 'actual primary')
            self.assertEqual(outcome['union_diagnostics']['status'], 'present')
            fake.calls.clear()
            fake.data['Config']['Labels']['org.network-atlas.acceptance.owner'] = 'not-owner'
            hosted.export_union_diagnostics(fake, root, identity(), root, {}, outcome)
            self.assertFalse(fake.calls)
            self.assertEqual(outcome['error'], 'actual primary')
        with scratch_home() as directory:
            root = Path(directory)
            fake = ExportDocker(root)
            fake.run = lambda argv, **kwargs: archive('union-diagnostics.json', b'x'*(32*1024+1))
            outcome = {'error': 'actual primary'}
            with patch.object(hosted, 'validate_bootstrap'):
                hosted.export_union_diagnostics(fake, root, identity(), root, {}, outcome)
            self.assertIn('aggregate bound', outcome['export_error'])
            self.assertEqual(outcome['error'], 'actual primary')
            self.assertFalse((root/'union-diagnostics.json').exists())

    def test_pinned_member_workspace_quarantine_moves_cutoff_without_source_edit(self):
        from pm.workspace import lock_and_sync
        from pm.environment import PythonEnvironment
        with scratch_home() as directory:
            root = Path(directory)
            source, _, _ = inputs(root)
            (source/'uv.lock').write_text('version=1\n[[package]]\nname="ruamel-yaml"\nversion="0.18.16"\n'
                                        '[package.source]\nregistry="https://pypi.org/simple"\n')
            member = root/'dependency-input'
            member.mkdir()
            (member/'plugin.yaml').write_text('python_dependencies: ["ruamel.yaml>=0.18.16,<0.19"]')
            before = (source/'pyproject.toml').read_bytes()
            calls = []
            engine = PythonEnvironment(uv=root/'uv', python=root/'python', destination=root/'venv', cache=root/'cache', env={})
            def capture(argv, **kwargs):
                calls.append(argv)
                return subprocess.CompletedProcess(argv, 0, '', '')
            with patch('pm.environment.subprocess.run', side_effect=capture):
                lock_and_sync([member], [], root=root/'workspace', source=source,
                              seed_lock=source/'uv.lock', environment=engine, frozen=False)
            import tomllib
            document = tomllib.loads((root/'workspace/pyproject.toml').read_text())
            self.assertNotIn('exclude-newer', document['tool']['uv'])
            self.assertEqual(document['tool']['uv']['exclude-newer-package']['ruamel-yaml'], '14 days')
            self.assertEqual((source/'pyproject.toml').read_bytes(), before)
            self.assertEqual(calls[0][1], 'lock')
            self.assertEqual(calls[1][1], 'sync')
            self.assertIn('--all-packages', calls[1])
            self.assertFalse((root/'venv').exists(), 'intercepted engine is NOT a resolved/installed generation')


if __name__ == '__main__':
    unittest.main()
