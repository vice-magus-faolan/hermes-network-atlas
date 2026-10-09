# SPDX-License-Identifier: GPL-3.0-or-later
"""Actual shell failure and cold PM-import regressions; no Docker/install/core copy."""
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import sysconfig
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
from test_runtime import runtime_root
sys.path.insert(0, str(ROOT / 'scripts'))
import disposable_validation as validation
from offline_guard import deny_network
from ruamel.yaml import YAML


IMPORT_PROBE = '''import importlib
import json
import os
from pathlib import Path
import sys
sys.path.append(sys.argv[3])  # dependencies only; no site/.pth/native bootstrap
sys.path.insert(0, sys.argv[1] + '/scripts')
from offline_guard import deny_network
deny_network()
import verify
core = Path(sys.argv[2]).resolve()
os.environ['NETWORK_ATLAS_HERMES_ROOT'] = str(core)
if 'pm' in sys.modules:
    raise ValueError('probe requires a genuinely cold native package import')
if sys.argv[5] == 'successor':
    verify.pin_runtime_imports()
alias = Path(sys.argv[4]) / 'ephemeral-core'
alias.symlink_to(core, target_is_directory=True)
sys.path.insert(0, str(alias))
# The actual pinned scanner-policy import loads pm from the temporary source.
from hermes_cli import plugins_cmd
pm = sys.modules['pm']
print(json.dumps({'pm_file_before_cleanup': pm.__file__, 'pm_path': list(pm.__path__)}), flush=True)
alias.unlink()  # tiny path-lifetime seam; never copy/delete real core source
sys.path.insert(0, str(core))
if sys.argv[5] == 'stale':
    verify.pin_runtime_imports()  # must refuse, not clear/rewrite cached modules
origins = {}
for name in ('pm.cli', 'pm.store', 'pm.install', 'pm.environment'):
    module = importlib.import_module(name)
    origin = Path(module.__file__).resolve()
    if origin != core / (name.replace('.', '/') + '.py'):
        raise ValueError('wrong actual pinned PM origin: ' + name)
    origins[name] = str(origin)
print(json.dumps({'origins': origins}), flush=True)
'''


class DisposableFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deny_network()

    def test_workflow_explicit_bash_propagates_real_producer_failure_through_tee(self):
        workflow = YAML(typ='safe').load((ROOT / '.github/workflows/verify.yml').read_text())
        self.assertEqual(workflow.get('defaults', {}).get('run', {}).get('shell'), 'bash')
        for job in workflow['jobs'].values():
            self.assertNotIn('defaults', job)
            self.assertNotIn('continue-on-error', job)
            for step in job['steps']:
                self.assertNotIn('continue-on-error', step)
                if 'run' in step:
                    self.assertNotIn('shell', step)
        with scratch_home() as directory:
            root = Path(directory)
            script = root / 'workflow-step.sh'
            script.write_text("{ printf 'actual producer failure\\n'; /usr/bin/false; } 2>&1 | tee producer.log\n"
                              "printf 'must not reach acceptance\\n' > acceptance\n")
            # Exact explicit-bash GitHub template, with a real script file.
            failed = subprocess.run(['/usr/bin/bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', str(script)],
                                    cwd=root, capture_output=True, timeout=15)
            self.assertEqual(failed.returncode, 1, failed.stderr)
            self.assertEqual((root / 'producer.log').read_text(), 'actual producer failure\n')
            self.assertFalse((root / 'acceptance').exists())
            # The actual previous implicit-shell template reproduces the false-green.
            masked = subprocess.run(['/usr/bin/bash', '-e', str(script)], cwd=root,
                                    capture_output=True, timeout=15)
            self.assertEqual(masked.returncode, 0, masked.stderr)
            self.assertTrue((root / 'acceptance').exists())

    def test_cold_interpreter_real_pinned_pm_import_survives_temporary_source_cleanup(self):
        tree = ast.parse((ROOT / 'scripts/verify.py').read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        pin = next(node for node in ast.walk(main) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Name) and node.func.id == 'pin_runtime_imports')
        discovery = next(node for node in ast.walk(main) if isinstance(node, ast.Call)
                         and isinstance(node.func, ast.Attribute) and node.func.attr == 'discover')
        self.assertLess(pin.lineno, discovery.lineno, 'real canonical entry must pin before test discovery')
        with scratch_home() as directory:
            root = Path(directory)
            script = root / 'import-probe.py'
            script.write_text(IMPORT_PROBE)
            base = [sys.executable, *(['-O'] if sys.flags.optimize else []), '-S', '-B', str(script), str(ROOT), str(runtime_root()),
                    sysconfig.get_path('purelib'), str(root)]
            for mode, expected in (('predecessor', 1), ('stale', 1), ('successor', 0)):
                with self.subTest(mode=mode):
                    result = subprocess.run([*base, mode], capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    if mode == 'predecessor':
                        self.assertIn("No module named 'pm.cli'", result.stderr)
                        self.assertIn('ephemeral-core/pm', result.stdout)
                    elif mode == 'stale':
                        self.assertIn('resolved outside pinned core: pm', result.stderr)
                    else:
                        proof = json.loads(result.stdout.splitlines()[-1])
                        self.assertEqual(set(proof['origins']), {'pm.cli', 'pm.store', 'pm.install', 'pm.environment'})
                        self.assertNotIn('ephemeral-core/pm', result.stdout)

    def test_real_failed_canonical_child_cannot_publish_proof_or_reach_cold(self):
        with scratch_home() as directory:
            root = Path(directory)
            receipt = {'candidate_tree': 't', 'native_generation': 'g'}
            calls = []
            real_run = validation.run
            def execute(argv, env):
                calls.append(argv)
                # Actual child exits test propagation; admission itself is not mocked as proof.
                real_run(['/usr/bin/false' if argv[-1] == 'scripts/verify.py' else '/usr/bin/true'], env)
            with patch.object(validation, 'EVIDENCE', root), \
                    patch.object(validation, 'admitted', return_value=(root, receipt)), \
                    patch.object(validation, 'run', side_effect=execute):
                with self.assertRaises(subprocess.CalledProcessError) as raised:
                    validation.verify()
                self.assertEqual(raised.exception.returncode, 1)
                self.assertEqual(len(calls), 3)
                self.assertFalse((root / 'canonical-complete.json').exists())
                with self.assertRaises(FileNotFoundError):
                    validation.cold('sha256:' + 'a' * 64)
                self.assertEqual(len(calls), 3, 'missing proof must refuse before cold execution')


if __name__ == '__main__':
    unittest.main(verbosity=2)
