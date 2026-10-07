# SPDX-License-Identifier: GPL-3.0-or-later
"""Permission/error contracts only; no Docker, root setup or native admission."""
import copy
import io
import json
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


NAMES = ('inventory.json', 'resolved-union.lock', 'verifier-resolution.json', 'union-packages.json')


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
        with self.assertRaisesRegex(RuntimeError, 'BOOTSTRAP_CONTRACT_AUTHORITY_REQUIRED.*openssh-client'):
            policy.require_bootstrap_contract()
        with patch.object(hosted, 'require_hosted'), patch.object(hosted, 'context') as context, \
                patch.object(hosted, 'upstream') as upstream, patch.object(hosted, 'reject_existing_owned') as owned, \
                self.assertRaisesRegex(RuntimeError, 'BOOTSTRAP_CONTRACT_AUTHORITY_REQUIRED'):
            hosted.build(Mock(), Path('/unused'), Path('/unused'), {}, Path('/unused'))
        context.assert_not_called()
        upstream.assert_not_called()
        owned.assert_not_called()

    def test_setup_and_apt_refuse_before_filesystem_acquisition_or_pm(self):
        with patch.object(setup, 'container_setup_guard'), patch.object(setup, 'apt') as apt, \
                patch.object(setup.Path, 'mkdir') as mkdir, \
                self.assertRaisesRegex(RuntimeError, 'BOOTSTRAP_CONTRACT_AUTHORITY_REQUIRED'):
            setup.main()
        apt.assert_not_called()
        mkdir.assert_not_called()
        with patch.object(setup, 'run') as run, patch.object(setup.Path, 'write_text') as write, \
                self.assertRaisesRegex(RuntimeError, 'BOOTSTRAP_CONTRACT_AUTHORITY_REQUIRED'):
            setup.apt({'debian_snapshot': '20260919T000000Z'})
        run.assert_not_called()
        write.assert_not_called()
        with patch.object(setup, 'container_setup_guard'), patch.dict(sys.modules, {'pm': None}), \
                patch.object(setup.Path, 'mkdir') as mkdir, \
                self.assertRaisesRegex(RuntimeError, 'BOOTSTRAP_CONTRACT_AUTHORITY_REQUIRED'):
            setup.warm()
        mkdir.assert_not_called()

    def test_actual_controller_entrypoint_contract_gate_precedes_scratch_and_daemon(self):
        argv = ['hosted_docker.py', '--hermes-source', '/unused', '--admission-mode', 'hosted-ci-caution']
        with patch.object(sys, 'argv', argv), patch.object(hosted, 'require_hosted'), \
                patch.object(hosted, 'git_head', return_value='a' * 40), \
                patch.object(hosted, 'clean_checkout') as clean, patch.object(hosted.Path, 'mkdir') as mkdir, \
                patch.object(hosted, 'command') as command, patch.object(hosted, 'Docker') as docker, \
                self.assertRaisesRegex(RuntimeError, 'BOOTSTRAP_CONTRACT_AUTHORITY_REQUIRED'):
            hosted.main()
        for effect in (clean, mkdir, command, docker):
            effect.assert_not_called()

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
            self.assertEqual([argv[0] for argv in fake.calls], ['logs', 'cp', 'cp', 'cp', 'cp'])

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
                self.assertEqual(len(manifest['members']), 4)
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
            fake.data['Mounts'][0]['Source'] = str(root / 'context')
            real_run = fake.run
            with patch.object(hosted, 'require_hosted'), patch.object(hosted, 'require_bootstrap_contract'), \
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
