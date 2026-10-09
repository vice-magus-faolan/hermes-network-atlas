# SPDX-License-Identifier: GPL-3.0-or-later
"""Tiny active native identity/readback regressions, not install or Docker proof."""
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
sys.path.insert(0, str(ROOT / 'scripts'))
import ci_admission
import core_identity
import docker_cold
from offline_guard import deny_network


class DisposableNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deny_network()

    def test_complete_core_identity_counts_all_source_and_refuses_drift_types_and_bounds(self):
        with scratch_home() as value:
            source = Path(value)
            for directory in ('tests', 'docs', 'pm', '.git', '__pycache__'):
                (source / directory).mkdir()
            for name in ('tests/test_native.py', 'docs/guide.md', 'pm/entry.py'):
                (source / name).write_bytes(b'synthetic source\n')
            (source / '.git/cache').write_bytes(b'not source')
            (source / '__pycache__/entry.pyc').write_bytes(b'not source')
            (source / 'link').symlink_to('pm/entry.py')
            manifest = core_identity.source_manifest(source)
            self.assertEqual(set(manifest), {'tests/test_native.py', 'docs/guide.md', 'pm/entry.py', 'link'})
            digest = core_identity.manifest_digest(manifest)
            core_identity.require_identity(manifest, expected_digest=digest)
            (source / 'pm/entry.py').chmod(0o700)
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                core_identity.require_identity(core_identity.source_manifest(source), expected_digest=digest)
            with patch.object(core_identity, 'SOURCE_BYTES', 1), self.assertRaisesRegex(ValueError, 'source byte bound'):
                core_identity.source_manifest(source)
            with patch.object(core_identity, 'MEMBER_COUNT', 1), self.assertRaisesRegex(ValueError, 'member/path bound'):
                core_identity.source_manifest(source)
            with patch.object(core_identity, 'MANIFEST_BYTES', 2), self.assertRaisesRegex(ValueError, 'manifest byte bound'):
                core_identity.source_manifest(source)
            os.mkfifo(source / 'special')
            with self.assertRaisesRegex(ValueError, 'member type'):
                core_identity.source_manifest(source)

    def test_removed_hosted_controller_context_and_offline_install_refuse_before_effects(self):
        with patch.object(ci_admission, 'git_head', return_value='a' * 40):
            with self.assertRaisesRegex(ValueError, 'diagnostics mismatch'):
                ci_admission.select_mode(ci_admission.MODE, {'GITHUB_JOB': 'hosted-docker'})
        env = {'PATH': '/usr/bin:/bin', 'TMPDIR': os.environ['TMPDIR'], 'PYTHONDONTWRITEBYTECODE': '1'}
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/native_install.py'),
                                 '/unavailable-synthetic-source', 'install', '--offline-enable'],
                                env=env, capture_output=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'offline dependency policy is enable-only', result.stderr)
        self.assertNotIn(b'synthetic scratch fixture marker', result.stderr)

    def test_cold_native_selection_checks_generation_interpreter_config_and_installed_tree(self):
        from pm import environments
        from hermes_cli import config
        with scratch_home() as value:
            root = Path(value)
            source = root / 'source'
            source.mkdir()
            generation = Path(sys.prefix).resolve()
            # Only the containment seam admits the existing test interpreter;
            # no generation or native install is fabricated as acceptance.
            receipt = {'native_generation': str(generation), 'native_facts': str(source / 'facts'),
                       'plugin': str(root / 'plugin'), 'installed_commit': 'c', 'candidate_tree': 't'}
            with patch.object(environments, 'committed_venv', return_value=generation), \
                    patch.object(environments, 'venv_python', return_value=Path(sys.executable)), \
                    patch.object(environments, 'runtime_facts_path', return_value=source / 'facts'), \
                    patch.object(config, 'load_config_readonly', return_value={'plugins': {'enabled': ['network-atlas']}}) as selector, \
                    patch.object(docker_cold, 'contained', side_effect=lambda _root, path: Path(path).resolve()), \
                    patch.object(docker_cold, 'git_head', return_value='c'), \
                    patch.object(docker_cold, 'git_tree', return_value='t') as tree:
                docker_cold.check_selection(root, receipt, source)
                for field in ('native_generation', 'native_facts', 'installed_commit', 'candidate_tree'):
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        docker_cold.check_selection(root, dict(receipt, **{field: '/wrong'}), source)
                selector.return_value = {'plugins': {'enabled': []}}
                with self.assertRaisesRegex(ValueError, 'enabled selection mismatch'):
                    docker_cold.check_selection(root, receipt, source)
                self.assertEqual(tree.call_count, 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
