# SPDX-License-Identifier: GPL-3.0-or-later
"""Permission/error contracts only; no Docker, root setup or native admission."""
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from helpers import ROOT, scratch_home
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'docker'))
import docker_builder as builder
import hosted_contract as policy
import hosted_docker as hosted
import hosted_setup as setup
from test_docker_builder import identity, inspected
from test_hosted_docker import diagnostics


NAMES = ('inventory.json', 'resolved-union.lock', 'verifier-resolution.json', 'union-packages.json', 'apt-diagnostics.json')


def archive(name, payload=b'{}'):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as bundle:
        member = tarfile.TarInfo(name)
        member.size = len(payload)
        bundle.addfile(member, io.BytesIO(payload))
    return output.getvalue()


class ExportDocker:
    """Actual exporter seam with fixed synthetic daemon state/archive bytes."""
    def __init__(self, root, *, failed=True, missing=(), denied=()):
        self.data = inspected(root)
        self.data['State'].update(ExitCode=1 if failed else 0, OOMKilled=False, Error='')
        self.missing, self.denied, self.calls = set(missing), set(denied), []

    def inspect(self, *_args, **_kwargs):
        return self.data

    def run(self, argv, **_kwargs):
        self.calls.append(argv)
        if argv[0] == 'logs':
            return b'primary apt failure: Permission denied\n'
        if argv[0] == 'rm':
            self.data = None
            return b''
        name = argv[1].split('/')[-1]
        if name in self.missing:
            message = f'Error response from daemon: Could not find the file /opt/seed/{name} in container ' + '1' * 64
            raise subprocess.CalledProcessError(1, argv, output=message.encode())
        if name in self.denied:
            raise subprocess.CalledProcessError(1, argv, output=b'permission denied reading archive')
        return archive(name)


class BootstrapRepairTests(unittest.TestCase):
    def test_complete_package_contract_refuses_before_controller_effects(self):
        # Preserve the regression's pre-effect boundary, not its superseded
        # unconditional authority stop: real local/non-hosted calls still refuse.
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'local execution'):
                policy.require_bootstrap_contract(workspace=ROOT, commit='a' * 40)
            with patch.object(hosted, 'context') as context, patch.object(hosted, 'git_head', return_value='a' * 40), \
                    patch.object(hosted, 'upstream') as upstream, patch.object(hosted, 'reject_existing_owned') as owned, \
                    self.assertRaisesRegex(ValueError, 'local execution'):
                hosted.build(Mock(), Path('/unused'), Path('/unused'), {}, Path('/unused'))
        context.assert_not_called()
        upstream.assert_not_called()
        owned.assert_not_called()

    def test_setup_and_apt_refuse_before_filesystem_acquisition_or_pm(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(setup, 'apt') as apt, \
                patch.object(setup.Path, 'mkdir') as mkdir, \
                self.assertRaisesRegex(ValueError, 'local execution'):
            setup.main()
        apt.assert_not_called()
        mkdir.assert_not_called()
        with patch.dict(os.environ, {}, clear=True), patch.object(setup, 'run') as run, patch.object(setup.Path, 'write_text') as write, \
                self.assertRaisesRegex(ValueError, 'local execution'):
            setup.apt({'debian_snapshot': '20260919T000000Z'})
        run.assert_not_called()
        write.assert_not_called()
        with patch.dict(os.environ, {}, clear=True), patch.dict(sys.modules, {'pm': None}), \
                patch.object(setup.Path, 'mkdir') as mkdir, \
                self.assertRaisesRegex(ValueError, 'local execution'):
            setup.warm()
        mkdir.assert_not_called()

    def test_actual_controller_entrypoint_contract_gate_precedes_scratch_and_daemon(self):
        argv = ['hosted_docker.py', '--hermes-source', '/unused', '--admission-mode', 'hosted-ci-caution']
        with patch.object(sys, 'argv', argv), patch.dict(os.environ, {}, clear=True), \
                patch.object(hosted, 'git_head', return_value='a' * 40), \
                patch.object(hosted, 'clean_checkout') as clean, patch.object(hosted.Path, 'mkdir') as mkdir, \
                patch.object(hosted, 'command') as command, patch.object(hosted, 'Docker') as docker, \
                self.assertRaisesRegex(ValueError, 'local execution'):
            hosted.main()
        for effect in (clean, mkdir, command, docker):
            effect.assert_not_called()

    def test_standard_docker_capabilities_and_process_containment_golden_and_drift(self):
        # Docker's standard Linux default set, not a fabricated runtime readback.
        self.assertEqual(policy.BOOTSTRAP_CAP_MASK, 0xa80425fb)
        status = {'CapEff': '00000000a80425fb', 'CapPrm': '00000000a80425fb',
                  'CapBnd': '00000000a80425fb', 'CapInh': '0000000000000000',
                  'CapAmb': '0000000000000000', 'NoNewPrivs': '1', 'Seccomp': '2'}
        text = '\n'.join(f'{key}:\t{value}' for key, value in status.items())
        self.assertEqual(policy.validate_setup_status(text), status)
        policy.validate_setup_inventory({'bootstrap_process': status})
        for inventory in ({}, {'bootstrap_process': None}, {'bootstrap_process': {}},
                          {'bootstrap_process': {**status, 'extra': 'unexpected'}},
                          {'bootstrap_process': {**status, 'NoNewPrivs': 1}}):
            with self.subTest(inventory=inventory), self.assertRaises(ValueError):
                policy.validate_setup_inventory(inventory)
        for key in status:
            for changed in ({**status, key: '0'}, {name: value for name, value in status.items() if name != key}):
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'drift'):
                    policy.validate_setup_status('\n'.join(f'{name}: {value}' for name, value in changed.items()))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            policy.validate_setup_status(text + '\nCapEff: 00000000a80425fb')
        # Additional SYS_ADMIN or a reduced capless set both fail exact admission.
        for mask in ('00000000a82425fb', '0000000000000000'):
            with self.assertRaisesRegex(ValueError, 'drift'):
                policy.validate_setup_status(text.replace('00000000a80425fb', mask))

    def test_real_setup_guard_requires_root_container_and_actual_status_before_effects(self):
        values = diagnostics(Path('/opt/inputs'))
        status = 'CapEff: 00000000a80425fb\nCapPrm: 00000000a80425fb\nCapBnd: 00000000a80425fb\n' \
                 'CapInh: 0000000000000000\nCapAmb: 0000000000000000\nNoNewPrivs: 1\nSeccomp: 2\n'
        with patch.dict(os.environ, values, clear=True), patch.object(policy.os, 'getuid', return_value=0), \
                patch.object(policy.os, 'geteuid', return_value=0), patch.object(policy.os, 'getgid', return_value=0), \
                patch.object(policy.os, 'getegid', return_value=0), patch.object(policy.Path, 'is_file', return_value=True), \
                patch.object(policy.Path, 'read_text', return_value=status) as read:
            self.assertEqual(policy.container_setup_guard()['NoNewPrivs'], '1')
            read.assert_called_once()
            with patch.object(policy.os, 'getuid', return_value=1000), self.assertRaisesRegex(ValueError, 'private hosted'):
                policy.container_setup_guard()
            with patch.object(policy.Path, 'is_file', return_value=False), self.assertRaisesRegex(ValueError, 'private hosted'):
                policy.container_setup_guard()
            for key in ('getuid', 'geteuid', 'getgid', 'getegid'):
                with patch.object(policy.os, key, return_value=1000), self.assertRaisesRegex(ValueError, 'private hosted'):
                    policy.container_setup_guard()
            with patch.object(policy.Path, 'read_text', return_value=status.replace('00000000a80425fb', '0000000000000000')), \
                    patch.object(setup, 'run') as run, patch.object(setup.Path, 'write_text') as write, \
                    self.assertRaisesRegex(ValueError, 'drift'):
                setup.apt({'debian_snapshot': '20260919T000000Z'})
            run.assert_not_called()
            write.assert_not_called()

    def test_hosted_apt_permits_normal_authenticated_provisioning_not_script_bypass(self):
        # Detailed real production acquisition/binding seams are mandatory in
        # AptProofTests; this inherited ID preserves the guarded setup dispatch.
        with patch.object(setup, 'container_setup_guard'), \
                patch.object(setup, 'provision', return_value={'success': True}) as provision:
            result = setup.apt({'debian_snapshot': '20260919T000000Z'})
            self.assertTrue(result['success'])
            provision.assert_called_once_with('20260919T000000Z', setup.SEED, setup.CORE)
            provision.reset_mock()
            with self.assertRaisesRegex(ValueError, 'exact Debian snapshot'):
                setup.apt({'debian_snapshot': 'wrong'})
            provision.assert_not_called()

    @patch('hosted_docker.export_git_preparation', new=lambda *args: None)
    @patch('hosted_docker.export_retention', new=lambda *args: None)
    def test_hosted_build_success_crosschecks_process_proof_before_commit_and_owned_cleanup(self):
        # Actual controller/export/commit/readback functions; only external
        # daemon/acquisition/waiting are synthetic. Not an actual container run.
        status = {'CapEff': '00000000a80425fb', 'CapPrm': '00000000a80425fb',
                  'CapBnd': '00000000a80425fb', 'CapInh': '0000000000000000',
                  'CapAmb': '0000000000000000', 'NoNewPrivs': '1', 'Seccomp': '2'}
        for proof in (status, None):
            with self.subTest(proof=proof), scratch_home() as directory:
                root = Path(directory)
                (root / 'context').mkdir()
                registry = root / 'registry'
                registry.mkdir()
                fake = ExportDocker(root, failed=False)
                fake.daemon = identity().daemon
                mapped = diagnostics(Path('/opt/inputs'))
                fake.data['HostConfig'] = builder.bootstrap_host_config(hosted=mapped)
                fake.data['Config']['Env'] = [f'{key}={value}' for key, value in mapped.items()]
                fake.data['Config']['Cmd'][-1] = '/opt/inputs/hosted_setup.py'
                fake.data['Mounts'][0]['Source'] = str(root / 'context')
                image = 'sha256:' + 'b' * 64
                final = {'Id': image, 'Size': 123, 'Config': {'Labels': dict(identity().labels(), **{'org.network-atlas.acceptance.kind': 'base'}),
                         'User': '1000:1000', 'WorkingDir': '/work', 'Volumes': None, 'Entrypoint': [], 'Cmd': ['/usr/bin/true']},
                         'RootFS': {'Layers': ['sha256:' + 'c' * 64, 'sha256:' + 'd' * 64]}}
                fake.json = Mock(return_value=[final])
                original_run = fake.run
                commits = []
                def run(argv, **kwargs):
                    if argv[0] in {'create', 'start'}:
                        fake.calls.append(argv)
                        return b''
                    if argv[0] == 'commit':
                        commits.append(argv)
                        return image.encode()
                    if argv[0] == 'cp' and argv[1].endswith('/inventory.json'):
                        return archive('inventory.json', json.dumps({'bootstrap_process': proof}).encode())
                    return original_run(argv, **kwargs)
                fake.run = run
                with patch.dict(os.environ, diagnostics(), clear=True), patch.object(hosted, 'git_head', return_value='a' * 40), \
                        patch.object(hosted, 'context', return_value=identity().base_key), \
                        patch.object(hosted, 'upstream', return_value={'Id': identity().image, 'RootFS': {'Layers': final['RootFS']['Layers'][:-1]}}), \
                        patch.object(hosted, 'BootstrapIdentity', return_value=identity()), \
                        patch.object(hosted, 'reject_existing_owned', return_value={}), \
                        patch.object(hosted, 'wait_setup', return_value=fake.data):
                    result, _ = hosted.build(fake, root, root, diagnostics(), registry)
                self.assertTrue(result['cleanup_verified'])
                self.assertIsNone(fake.data)
                if proof is None:
                    self.assertIn('inventory absent', result['error'])
                    self.assertFalse(commits)
                    self.assertNotIn('base', result)
                else:
                    hosted.successful(result)
                    self.assertEqual(len(commits), 1)
                    self.assertIn('USER 1000:1000', commits[0])
                    self.assertEqual(result['base']['image'], image)
                    self.assertEqual(set(result['export_hashes']), set(NAMES))
                    self.assertEqual(json.loads((registry / 'base.json').read_text())['image'], image)

    def test_final_diagnostic_error_is_secondary_unless_no_primary(self):
        original = RuntimeError('actual primary setup failure')
        with scratch_home() as directory, patch.object(hosted, 'diagnostic', side_effect=OSError('readback failed')):
            hosted.export_after(Mock(), Path(directory), original)
            self.assertIn('final diagnostic export failed: OSError', original.__notes__[0])
            with self.assertRaisesRegex(OSError, 'readback failed'):
                hosted.export_after(Mock(), Path(directory), None)

    def test_failed_export_preserves_stopped_logs_and_all_missing_members(self):
        with scratch_home() as directory:
            root = Path(directory)
            fake = ExportDocker(root, missing=NAMES)
            result = builder.export_bootstrap(fake, root, identity(), provenance=True)
            self.assertEqual(result, {})
            self.assertEqual(json.loads((root / 'stopped.json').read_text())['State']['ExitCode'], 1)
            self.assertIn(b'primary apt failure', (root / 'bootstrap.log').read_bytes())
            manifest = json.loads((root / 'export-members.json').read_text())
            self.assertFalse(manifest['setup_success'])
            self.assertEqual({key: row['status'] for key, row in manifest['members'].items()}, dict.fromkeys(NAMES, 'missing'))
            self.assertFalse(any((root / name).exists() for name in NAMES))
            self.assertEqual([argv[0] for argv in fake.calls], ['logs', 'cp', 'cp', 'cp', 'cp', 'cp'])

    def test_success_requires_every_inventory_and_provenance_member(self):
        for missing in NAMES:
            with self.subTest(missing=missing), scratch_home() as directory:
                root = Path(directory)
                fake = ExportDocker(root, failed=False, missing=(missing,))
                with self.assertRaisesRegex(ValueError, 'required bootstrap evidence'):
                    builder.export_bootstrap(fake, root, identity(), provenance=True)
                manifest = json.loads((root / 'export-members.json').read_text())
                self.assertTrue(manifest['setup_success'])
                self.assertEqual(manifest['members'][missing]['status'], 'missing')
                self.assertEqual(len(manifest['members']), 5)
        with scratch_home() as directory:
            result = builder.export_bootstrap(ExportDocker(Path(directory), failed=False), Path(directory), identity(), provenance=True)
            self.assertEqual(set(result), set(NAMES))

    def test_permission_archive_and_output_failures_are_not_missing(self):
        with scratch_home() as directory:
            root = Path(directory)
            fake = ExportDocker(root, denied=('inventory.json',), missing=NAMES[1:])
            with self.assertRaisesRegex(ValueError, 'bootstrap evidence export'):
                builder.export_bootstrap(fake, root, identity(), provenance=True)
            manifest = json.loads((root / 'export-members.json').read_text())
            self.assertEqual(manifest['members']['inventory.json']['status'], 'error')
            self.assertIn('permission denied', manifest['members']['inventory.json']['error'])
            self.assertEqual(manifest['members'][NAMES[-1]]['status'], 'missing')
            self.assertIn(b'primary apt failure', (root / 'bootstrap.log').read_bytes())
        with scratch_home() as directory:
            fake = ExportDocker(Path(directory))
            original = fake.run
            def malformed(argv, **kwargs):
                return archive('wrong.json') if argv[0] == 'cp' else original(argv, **kwargs)
            fake.run = malformed
            with self.assertRaisesRegex(ValueError, 'bootstrap evidence export'):
                builder.export_bootstrap(fake, Path(directory), identity())
            self.assertFalse((Path(directory) / 'inventory.json').exists())

    def test_reinspection_ownership_drift_never_reads_logs_or_members(self):
        with scratch_home() as directory:
            root = Path(directory)
            data = inspected(root, running=True)
            wrong = copy.deepcopy(data)
            wrong['Id'] = '2' * 64
            wrong['State']['Running'] = False
            fake = SimpleNamespace(inspect=Mock(side_effect=[data, wrong]), run=Mock())
            with self.assertRaisesRegex(ValueError, 'identity'):
                builder.export_bootstrap(fake, root, identity())
            self.assertEqual(fake.run.call_args_list[0].args[0][0], 'stop')
            self.assertEqual(fake.run.call_count, 1)
            self.assertFalse((root / 'stopped.json').exists())

    def test_stopped_failure_is_primary_before_success_only_exports_or_commit(self):
        with scratch_home() as directory:
            root = Path(directory)
            fake = ExportDocker(root, missing=NAMES)
            fake.daemon = identity().daemon
            fake.data['Config']['Cmd'][-1] = '/opt/inputs/hosted_setup.py'
            mapped = diagnostics(Path('/opt/inputs'))
            fake.data['Config']['Env'] = [f'{key}={value}' for key, value in mapped.items()]
            fake.data['HostConfig'] = builder.bootstrap_host_config(hosted=mapped)
            fake.data['Mounts'][0]['Source'] = str(root / 'context')
            real_run = fake.run
            with patch.dict(os.environ, diagnostics(), clear=True), patch.object(hosted, 'git_head', return_value='a' * 40), \
                    patch.object(hosted, 'reject_existing_owned', return_value={}), \
                    patch.object(hosted, 'context', return_value=identity().base_key), \
                    patch.object(hosted, 'upstream', return_value={'Id': identity().image}), \
                    patch.object(hosted, 'BootstrapIdentity', return_value=identity()), \
                    patch.object(hosted, 'bootstrap_command', return_value=['create']), \
                    patch.object(hosted, 'wait_setup', return_value=fake.data), \
                    patch.object(fake, 'run') as run, \
                    patch.object(hosted, 'commit_command') as commit:
                # Creation/start return no payload; subsequent exporter is real.
                run.side_effect = lambda argv, **kwargs: b'' if argv[0] in {'create', 'start'} else real_run(argv, **kwargs)
                outcome, _ = hosted.build(fake, root, root, diagnostics(), root)
            self.assertIn('public bootstrap failed', outcome['error'])
            self.assertIn('exit=1', outcome['error'])
            self.assertNotIn('CalledProcessError', outcome['error'])
            self.assertTrue(outcome['cleanup_verified'])
            self.assertEqual(outcome['export_hashes'], {})
            self.assertNotIn('base', outcome)
            commit.assert_not_called()

    def test_primary_failure_survives_secondary_cleanup_evidence_write(self):
        with scratch_home() as directory:
            failure = RuntimeError('original setup failure')
            with patch.object(hosted, 'build', return_value=({'error': str(failure)}, {})), \
                    patch.object(hosted, 'cleanup_image') as cleanup, \
                    patch.object(hosted, 'BoundedDirectory') as budget:
                budget.return_value.json.side_effect = [None, OSError('secondary evidence write failed')]
                with self.assertRaisesRegex(RuntimeError, 'owned phase FAILED') as caught:
                    hosted.exercise(Mock(), Path(directory), Path(directory), {}, Path(directory), Path(directory))
            cleanup.assert_not_called()
            self.assertIn('owned image cleanup failed', ' '.join(caught.exception.__notes__))

    def test_all_stopped_failure_kinds_refuse_before_rootfs_commit(self):
        for mutation in ({'ExitCode': 1}, {'OOMKilled': True}, {'Status': 'created'}, {'Error': 'start failed'}, {'Running': True}):
            data = inspected(Path('/synthetic'))
            data['State'].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(RuntimeError, 'public bootstrap failed'):
                builder.require_bootstrap_success(data)
        builder.require_bootstrap_success(inspected(Path('/synthetic')))


if __name__ == '__main__':
    from offline_guard import deny_network
    deny_network()
    unittest.main()
