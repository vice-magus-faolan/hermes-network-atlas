# SPDX-License-Identifier: GPL-3.0-or-later
"""Hosted control/refusal seams only; never execute Docker or native setup locally."""
import copy
import hashlib

import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
from types import ModuleType
import unittest
from unittest.mock import Mock, patch
from helpers import ROOT, scratch_home
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'docker'))
from offline_guard import deny_network
import hosted_contract as policy
import hosted_docker as hosted
import hosted_evidence as export
import hosted_setup as setup

import docker_builder as builder
import docker_contract as contract
import ci_admission


def diagnostics(workspace=ROOT, commit='a' * 40):
    return {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux',
            'RUNNER_ARCH': 'X64', 'GITHUB_REPOSITORY': policy.REPOSITORY, 'GITHUB_EVENT_NAME': 'push',
            'GITHUB_REF': 'refs/heads/feat/6-host-discovery', 'GITHUB_JOB': 'hosted-docker',
            'GITHUB_SHA': commit, 'GITHUB_WORKSPACE': str(workspace), 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}


class HostedDockerTests(unittest.TestCase):
    def test_explicit_hosted_initial_feature_context_and_local_refusal(self):
        valid = diagnostics()
        self.assertEqual(policy.require_hosted(valid, workspace=ROOT, commit='a' * 40), valid)
        for key in valid:
            with self.subTest(key=key), self.assertRaises(ValueError):
                policy.require_hosted(dict(valid, **{key: 'wrong'}), workspace=ROOT, commit='a' * 40)
        for values in ({}, dict(valid, GITHUB_RUN_ATTEMPT='2'), dict(valid, RUNNER_ENVIRONMENT='self-hosted'),
                       dict(valid, GITHUB_EVENT_NAME='pull_request'), dict(valid, GITHUB_REF='refs/heads/main')):
            with self.assertRaises(ValueError):
                policy.require_hosted(values, workspace=ROOT, commit='a' * 40)
        with patch.dict(os.environ, {}, clear=True), patch.object(sys, 'argv', ['hosted_docker.py', '--hermes-source', '/unused',
                     '--admission-mode', 'hosted-ci-caution']), patch.object(hosted, 'Docker') as docker, \
                self.assertRaisesRegex(ValueError, 'local execution'):
            hosted.main()
        docker.assert_not_called()

    def test_real_legacy_prewarm_dispatch_refuses_before_pm_import_or_call(self):
        pm = ModuleType('pm')
        pm.sync_venv = Mock()
        inputs = ModuleType('pm.plugin_inputs')
        inputs.Members = Mock()
        with patch.dict(sys.modules, {'pm': pm, 'pm.plugin_inputs': inputs}), \
                patch.object(sys, 'argv', ['base_setup.py', 'prewarm']), \
                self.assertRaisesRegex(ValueError, 'live build disabled'):
            runpy.run_path(str(ROOT / 'docker/base_setup.py'), run_name='__main__')
        pm.sync_venv.assert_not_called()
        inputs.Members.assert_not_called()

    def test_real_hosted_setup_dispatch_and_warm_refuse_before_pm(self):
        pm = ModuleType('pm')
        pm.sync_venv = Mock()
        with patch.dict(os.environ, {}, clear=True), patch.dict(sys.modules, {'pm': pm}):
            for args in ([], ['warm']):
                with self.subTest(args=args), patch.object(sys, 'argv', ['hosted_setup.py', *args]), \
                        self.assertRaisesRegex(ValueError, 'local execution'):
                    runpy.run_path(str(ROOT / 'docker/hosted_setup.py'), run_name='__main__')
        pm.sync_venv.assert_not_called()
        with patch.dict(os.environ, {}, clear=True), patch.object(sys, 'argv', ['hosted_setup.py', 'inventory']), \
                patch('builtins.print') as output:
            runpy.run_path(str(ROOT / 'docker/hosted_setup.py'), run_name='__main__')
        output.assert_called_once()

    def test_real_prewarm_refusal_normal_and_optimized_children(self):
        for option in ('-B', '-O'):
            result = subprocess.run([sys.executable, option, str(ROOT / 'docker/base_setup.py'), 'prewarm'],
                                    capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'live build disabled', result.stderr)
            result = subprocess.run([sys.executable, option, str(ROOT / 'docker/hosted_setup.py'), 'warm'],
                                    env={'PATH': '/usr/bin:/bin'}, capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'local execution', result.stderr)

    def test_hosted_native_mode_scope_and_force_still_use_original_boundary(self):
        with patch.object(ci_admission, 'git_head', return_value='a' * 40):
            self.assertTrue(ci_admission.select_mode(ci_admission.MODE, diagnostics()))
            self.assertFalse(ci_admission.select_mode('local', diagnostics()))
            for changes in ({'GITHUB_RUN_ATTEMPT': '2'}, {'GITHUB_EVENT_NAME': 'pull_request'}, {'GITHUB_REF': 'refs/heads/main'}):
                with self.assertRaises(ValueError):
                    ci_admission.select_mode(ci_admission.MODE, dict(diagnostics(), **changes))

    def test_hosted_runtime_exact_diagnostics_and_isolation_readback(self):
        from test_docker_acceptance import DockerContractTests
        fixture = DockerContractTests()
        with scratch_home() as directory:
            root = Path(directory)
            (root / 'incoming').mkdir()
            candidate = root / 'candidate'
            candidate.mkdir()
            data = fixture.inspection(candidate)
            values = diagnostics(Path('/candidate'))
            argv = contract.create_command(fixture.identity(), candidate, 'hosted-accept', hosted=values)
            self.assertEqual(argv[argv.index('--network') + 1], 'none')
            self.assertNotIn('--tty', argv)
            self.assertIn('--read-only', argv)
            data['Config']['Cmd'][-1] = 'hosted-accept'
            data['Config']['Env'] = [f'{key}={value}' for key, value in values.items()]
            contract.validate_container(data, fixture.identity(), candidate, 'hosted-accept', hosted=values)
            for mutation in ({'GITHUB_SHA': 'b' * 40}, {'DOCKER_HOST': 'remote'}, {'RUNNER_ARCH': 'ARM64'}):
                changed = copy.deepcopy(data)
                changed['Config']['Env'] = [f'{key}={value}' for key, value in dict(values, **mutation).items()]
                with self.assertRaises(ValueError):
                    contract.validate_container(changed, fixture.identity(), candidate, 'hosted-accept', hosted=values)
            with self.assertRaises(ValueError):
                contract.create_command(fixture.identity(), candidate, 'hosted-accept')
            for key in ('UTSMode', 'UsernsMode'):
                changed = copy.deepcopy(data)
                changed['HostConfig'][key] = 'host'
                with self.assertRaises(ValueError):
                    contract.validate_container(changed, fixture.identity(), candidate, 'hosted-accept', hosted=values)

    def test_hosted_bootstrap_readback_and_commit_clear_attempt_diagnostics(self):
        from test_docker_builder import identity, inspected
        with scratch_home() as directory:
            root = Path(directory)
            values = diagnostics(Path('/opt/inputs'))
            data = inspected(root)
            data['Config']['Cmd'][-1] = '/opt/inputs/hosted_setup.py'
            data['Config']['Env'] = [f'{key}={value}' for key, value in values.items()]
            data['HostConfig'] = builder.bootstrap_host_config(hosted=values)
            builder.validate_bootstrap(data, identity(), root, hosted=values)
            argv = builder.bootstrap_command(identity(), root, hosted=values)
            self.assertNotIn('--cap-drop', argv)
            self.assertNotIn('--cap-add', argv)
            self.assertIn('no-new-privileges=true', argv)
            self.assertFalse(set(argv) & {'--privileged', '--pid', '--device', '--volume', '--publish'})
            self.assertIsNone(data['HostConfig']['CapDrop'])
            self.assertIsNone(data['HostConfig']['CapAdd'])
            for key, bad in (('CapDrop', ['ALL']), ('CapAdd', ['SYS_ADMIN']), ('SecurityOpt', ['seccomp=unconfined']),
                             ('SecurityOpt', ['apparmor=unconfined']), ('Privileged', True), ('PidMode', 'host'),
                             ('IpcMode', 'host'), ('UsernsMode', 'host'), ('UTSMode', 'host'), ('NetworkMode', 'host')):
                changed = copy.deepcopy(data)
                changed['HostConfig'][key] = bad
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'isolation drift'):
                    builder.validate_bootstrap(changed, identity(), root, hosted=values)
            argv = builder.commit_command(data, identity(), root, hosted=values)
            self.assertIn('ENV GITHUB_SHA=', argv)
            self.assertIn('USER 1000:1000', argv)
            with self.assertRaises(ValueError):
                builder.validate_bootstrap(data, identity(), root)
            data['State']['OOMKilled'] = True
            with self.assertRaises(ValueError):
                builder.commit_command(data, identity(), root, hosted=values)

    def test_verified_public_wheel_index_hash_size_type_and_native_tools(self):
        digest = hashlib.sha256(b'tiny mock tool').hexdigest()
        row = {'download_info': {'url': 'https://files.pythonhosted.org/tiny.whl', 'archive_info': {'hashes': {'sha256': digest}}},
               'metadata': {'name': 'tiny', 'version': '1'}}
        metadata = {'urls': [{'url': row['download_info']['url'], 'digests': {'sha256': digest}, 'size': 14,
                              'filename': 'tiny.whl', 'packagetype': 'bdist_wheel', 'yanked': False}]}
        self.assertEqual(setup.wheel_record(row, metadata)['sha256'], digest)
        for key, value in (('yanked', True), ('packagetype', 'sdist'), ('digests', {'sha256': '0' * 64})):
            changed = copy.deepcopy(metadata)
            changed['urls'][0][key] = value
            with self.assertRaises(ValueError):
                setup.wheel_record(row, changed)
        with scratch_home() as directory, patch.object(setup, 'SEED', Path(directory)):
            seed = Path(directory) / 'tools' / ('fetch-' + digest)
            seed.mkdir(parents=True)
            (seed / 'tiny.tar').write_bytes(b'tiny mock tool')
            lock = {'packages': {key: {'artifacts': {'linux-x64': {'url': 'https://github.com/fixture/tiny.tar', 'sha256': digest}}}
                                 for key in ('python', 'uv')}}
            self.assertEqual(len(setup.tool_artifacts(lock)), 2)
            (seed / 'tiny.tar').write_bytes(b'mismatched')
            with self.assertRaises(ValueError):
                setup.tool_artifacts(lock)

    def test_mocked_hosted_sequence_preserves_failure_no_retry_and_owned_cleanup(self):
        with scratch_home() as directory:
            root = Path(directory)
            record = {'image': 'sha256:' + 'a' * 64}
            good = {'cleanup_verified': True, 'base': record}
            for failure in (None, RuntimeError('synthetic failure'), InterruptedError('synthetic interrupt')):
                run = Mock(return_value={'cleanup_verified': True}, side_effect=failure)
                with patch.object(hosted, 'build', return_value=(good, {'Id': 'public'})), \
                        patch.object(hosted, 'run_attempt', run), patch.object(hosted, 'cleanup_image') as cleanup:
                    if failure is None:
                        hosted.exercise(Mock(), root, root, diagnostics(), root, root)
                        self.assertEqual(run.call_count, 5)
                    else:
                        with self.assertRaises(type(failure)):
                            hosted.exercise(Mock(), root, root, diagnostics(), root, root)
                        self.assertEqual(run.call_count, 1)
                    cleanup.assert_called_once()
            with self.assertRaises(RuntimeError):
                hosted.successful({'cleanup_verified': True, 'export_error': 'original failure'})

    def test_compact_export_hashes_refuses_missing_symlink_and_no_context(self):
        import tarfile
        with scratch_home() as directory:
            root = Path(directory) / 'proof'
            root.mkdir()
            with self.assertRaises(ValueError):
                export.pack(root, root.parent / 'empty.tar')
            summary = root / 'summary'
            summary.mkdir()
            (summary / 'outcome.json').write_text('{"failed":true}')
            (root / 'context').mkdir()
            (root / 'context/NEVER_EXPORT').write_text('public but excluded')
            destination = root.parent / 'proof.tar'
            result = export.pack(root, destination)
            self.assertFalse(result['acceptance_inferred'])
            with tarfile.open(destination) as bundle:
                self.assertEqual(bundle.getnames(), ['summary/outcome.json', 'hashes.json'])
            (summary / 'link').symlink_to(summary / 'outcome.json')
            with self.assertRaises(ValueError):
                export.pack(root, root.parent / 'bad.tar')

    def test_workflow_single_initial_vm_job_pins_permissions_and_step_context(self):
        from ruamel.yaml import YAML
        value = YAML(typ='safe').load((ROOT / '.github/workflows/verify.yml').read_text())
        self.assertEqual(value['permissions'], {'contents': 'read'})
        self.assertEqual(value['concurrency'], {'group': 'network-atlas-issue-6-ci', 'cancel-in-progress': False})
        job = value['jobs']['hosted-docker']
        self.assertEqual(job['runs-on'], 'ubuntu-24.04')
        self.assertEqual(job['timeout-minutes'], 60)
        self.assertEqual(job['if'], "github.event_name == 'push' && github.ref == 'refs/heads/feat/6-host-discovery' && needs.feature-phase.outputs.phase == 'acceptance'")
        self.assertEqual(value['jobs']['offline-verification']['if'], "github.event_name != 'push' || github.ref != 'refs/heads/feat/6-host-discovery'")
        self.assertNotIn('strategy', job)
        self.assertNotIn('runner.', str(job.get('env', {})))
        # The actual compiler also validates the complete positive/negative
        # examples in the recorded local read-only actionlint evidence.
        def scope(document):
            envs = [document.get('env', {})]
            envs.extend(item.get('env', {}) for item in document['jobs'].values())
            if any('runner.' in str(env) for env in envs):
                raise ValueError('runner context outside supported step scope')
        scope(value)
        invalid = copy.deepcopy(value)
        invalid['jobs']['hosted-docker']['env'] = {'TMPDIR': '${{ runner.temp }}/invalid'}
        with self.assertRaises(ValueError):
            scope(invalid)
        for step in job['steps']:
            if 'uses' in step:
                self.assertRegex(step['uses'], r'@[0-9a-f]{40}$')
                self.assertNotIn('cache', step['uses'])
                if step['uses'].startswith('actions/checkout@'):
                    self.assertFalse(step['with']['persist-credentials'])
        text = json.dumps(value)
        for token in ('secrets.', 'pull_request_target', 'self-hosted', 'ubuntu-slim', '--privileged'):
            self.assertNotIn(token, text)
        upload = next(step for step in job['steps'] if step.get('uses', '').startswith('actions/upload-artifact@'))
        self.assertEqual(upload['if'], 'always()')
        self.assertEqual(upload['with']['if-no-files-found'], 'error')
        self.assertEqual(upload['with']['retention-days'], 7)


if __name__ == '__main__':
    deny_network()
    unittest.main()
