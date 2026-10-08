# SPDX-License-Identifier: GPL-3.0-or-later
"""Packet-denied conventional Docker source/lifecycle tests; no Docker or admission."""
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
sys.path.insert(0, str(ROOT / 'scripts'))
import disposable_validation as validation
from offline_guard import deny_network
from ruamel.yaml import YAML


class DisposableValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deny_network()

    def workflow(self):
        return YAML(typ='safe').load((ROOT / '.github/workflows/verify.yml').read_text())

    def test_all_events_use_one_conventional_path_without_retained_controller(self):
        workflow = self.workflow()
        self.assertEqual(set(workflow['jobs']), {'offline-verification'})
        job = workflow['jobs']['offline-verification']
        self.assertNotIn('if', job)
        self.assertNotIn('needs', job)
        self.assertEqual(job['runs-on'], 'ubuntu-24.04')
        self.assertEqual(job['timeout-minutes'], 60)
        text = json.dumps(workflow)
        for forbidden in ('hosted_docker.py', 'measurement_route.py', 'packing_measurement.py',
                          'setup-python@', 'self-hosted', 'secrets.', 'pull_request_target',
                          'docker commit', 'docker system prune', '--privileged', 'type=bind',
                          'SYS_ADMIN', 'seccomp=unconfined', 'apparmor=unconfined', '--network host', '--pid host'):
            self.assertNotIn(forbidden, text)
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertEqual(workflow['on'], {'push': {'branches': ['main', 'feat/6-host-discovery']},
                                          'pull_request': {'branches': ['main']}})

    def test_online_once_then_network_none_verify_and_cold_same_owned_volume(self):
        steps = self.workflow()['jobs']['offline-verification']['steps']
        runs = [step['run'] for step in steps if 'docker run ' in step.get('run', '')]
        self.assertEqual(len(runs), 3)
        self.assertNotIn('--network none', runs[0])
        for run, phase in zip(runs, ('setup', 'verify', 'cold')):
            self.assertIn('"$ATLAS_CI_PREFIX" ' + phase + ' --admission-mode hosted-ci-caution', run)
            for flag in ('--user 1000:1000', '--cap-drop ALL', '--security-opt no-new-privileges',
                         '--cpus 2', '--memory 6g', '--memory-swap 6g', '--pids-limit 256', '--read-only',
                         'type=volume,source=$ATLAS_CI_PREFIX-state,target=/state',
                         '--env GITHUB_WORKSPACE=/workspace/network-atlas'):
                self.assertIn(flag, run)
        for run in runs[1:]:
            self.assertIn('--network none', run)
            self.assertIn('volume-subpath=$ATLAS_FIXTURE/hermes-source,target=/state/$ATLAS_FIXTURE/hermes-source,readonly', run)
            self.assertIn('volume-subpath=$ATLAS_FIXTURE/hermes/plugins/network-atlas,target=/state/$ATLAS_FIXTURE/hermes/plugins/network-atlas,readonly', run)
        self.assertIn('--image "$image"', runs[2])
        dockerfile = (ROOT / 'docker/validation.Dockerfile').read_text()
        self.assertIn('python:3.14.7-slim-bookworm@sha256:998acd06f485adfd6890e3e15a4b542543e0cf22ff904310095da328a5e3e561', dockerfile)
        self.assertIn('COPY --chown=1000:1000 . /workspace/network-atlas', dockerfile)
        self.assertIn('USER 1000:1000', dockerfile)
        self.assertIn('--index-url https://pypi.org/simple', dockerfile)
        self.assertNotIn('trusted-host', dockerfile)
        self.assertNotIn('prepare_acceptance.py', dockerfile, 'native selection must not enter a reusable image layer')

    def test_local_entrypoint_refuses_before_setup_or_state_effects(self):
        env = {'PATH': '/usr/bin:/bin', 'TMPDIR': os.environ['TMPDIR'], 'PYTHONDONTWRITEBYTECODE': '1'}
        for phase in ('setup', 'verify', 'cold'):
            result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/disposable_validation.py'),
                                     phase, '--admission-mode', 'hosted-ci-caution'], env=env,
                                    capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'diagnostics mismatch', result.stderr)

    def test_verify_runs_full_canonical_and_receipt_refuses_stale_selection(self):
        with scratch_home() as value:
            root = Path(value)
            receipt = {'candidate_tree': 't', 'native_generation': 'real-readback-path'}
            with patch.object(validation, 'EVIDENCE', root), patch.object(validation, 'admitted', return_value=(root, receipt)), \
                    patch.object(validation, 'run') as run, patch.object(validation, 'validate_receipt') as readback, \
                    patch.object(validation, 'git_head', return_value='c'):
                validation.verify()
                self.assertEqual([call.args[0][2] for call in run.call_args_list],
                                 ['tests/test_ci_admission.py', 'tests/test_caution_confirmation.py', 'scripts/verify.py'])
                self.assertTrue(all(call.args[1]['NETWORK_ATLAS_ACCEPTANCE_FIXTURE'] == str(root) for call in run.call_args_list))
                readback.assert_called_once_with(root)
                self.assertEqual(json.loads((root / 'canonical-complete.json').read_text())['canonical_exit'], 0)
            (root / 'canonical-complete.json').unlink()
            with patch.object(validation, 'EVIDENCE', root), patch.object(validation, 'admitted', return_value=(root, receipt)), \
                    patch.object(validation, 'run'), patch.object(validation, 'validate_receipt', side_effect=ValueError('drift')), \
                    self.assertRaisesRegex(ValueError, 'drift'):
                validation.verify()
            self.assertFalse((root / 'canonical-complete.json').exists())

    def test_cold_requires_prior_candidate_success_and_uses_selected_python_without_install(self):
        with scratch_home() as value:
            root = Path(value)
            receipt = {'candidate_tree': 't', 'native_generation': 'g', 'python': '/selected/bin/python',
                       'environment': {'HOME': 'synthetic', 'HERMES_HOME': 'synthetic'}}
            with patch.object(validation, 'EVIDENCE', root), patch.object(validation, 'admitted', return_value=(root, receipt)), \
                    patch.object(validation, 'run') as run, patch.object(validation, 'validate_receipt'), \
                    patch.object(validation, 'git_head', return_value='c'):
                with self.assertRaises(FileNotFoundError):
                    validation.cold('sha256:' + 'a' * 64)
                run.assert_not_called()
                proof = {'candidate_commit': 'wrong', 'candidate_tree': 't', 'native_generation': 'g', 'canonical_exit': 0}
                (root / 'canonical-complete.json').write_text(json.dumps(proof))
                with self.assertRaisesRegex(ValueError, 'candidate canonical'):
                    validation.cold('sha256:' + 'a' * 64)
                run.assert_not_called()
                proof['candidate_commit'] = 'c'
                (root / 'canonical-complete.json').write_text(json.dumps(proof))
                validation.cold('sha256:' + 'a' * 64)
                argv, env = run.call_args.args
                self.assertEqual(argv[:3], ['/selected/bin/python', '-B', 'scripts/docker_cold.py'])
                self.assertEqual(env['TMPDIR'], str(validation.STATE))
                self.assertNotIn('native_install.py', str(argv))

    def test_native_diagnostics_keep_primary_error_and_fresh_setup_cannot_reuse(self):
        with scratch_home() as value:
            root = Path(value)
            evidence = root / 'evidence'
            fixture = root / 'atlas-admission-fixture'
            with patch.object(validation, 'STATE', root), patch.object(validation, 'FIXTURE', root / 'fixture.path'), \
                    patch.object(validation, 'EVIDENCE', evidence), patch.object(validation, 'run') as run:
                fixture.mkdir()
                with self.assertRaisesRegex(ValueError, 'fresh'):
                    validation.setup()
                run.assert_not_called()
                fixture.rmdir()
                def fail(*_):
                    fixture.mkdir()
                    (fixture / 'enable.log').write_text('actual diagnostic seam')
                    raise RuntimeError('primary enable error')
                run.side_effect = fail
                with self.assertRaisesRegex(RuntimeError, 'primary enable error'):
                    validation.setup()
                self.assertEqual((evidence / 'enable.log').read_text(), 'actual diagnostic seam')
                self.assertFalse((root / 'fixture.path').exists())

    def test_owned_real_child_failure_and_deadline_are_not_success(self):
        with self.assertRaises(subprocess.CalledProcessError) as context:
            validation.run(['/usr/bin/false'])
        self.assertEqual(context.exception.returncode, 1)
        validation.run(['/usr/bin/true'])
        tree = ast.parse((ROOT / 'scripts/disposable_validation.py').read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
        self.assertIn('start_new_session=True', ast.unparse(function))
        self.assertIn('timeout=1800', ast.unparse(function))
        self.assertIn('os.killpg(process.pid', ast.unparse(function))

    def test_cleanup_is_always_scoped_and_artifacts_never_include_volume_or_core(self):
        steps = self.workflow()['jobs']['offline-verification']['steps']
        cleanup = next(step for step in steps if step.get('name') == 'Retain native readbacks and clean only this run')
        self.assertEqual(cleanup['if'], 'always()')
        for command in ('docker rm "$name"', 'docker volume rm "$ATLAS_CI_PREFIX-state"', 'docker image rm "$ATLAS_CI_PREFIX"'):
            self.assertIn(command, cleanup['run'])
        self.assertNotIn(' -f ', cleanup['run'])
        upload = steps[-1]
        self.assertEqual(upload['if'], 'always()')
        self.assertEqual(upload['with']['path'], '${{ runner.temp }}/atlas-test-scratch/evidence')
        self.assertEqual(upload['with']['if-no-files-found'], 'error')


if __name__ == '__main__':
    unittest.main()
