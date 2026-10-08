# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact inert default contract; actual historical evidence, modeled Docker merge.

These tests do not run Docker or claim the successor has hosted acceptance.
"""
import copy
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from helpers import ROOT, scratch_home
sys.path.insert(0, str(ROOT / 'scripts'))
import docker_builder as builder
import docker_acceptance as acceptance
import hosted_docker as hosted
import base_setup
from offline_guard import deny_network
from test_docker_builder import identity, inspected
from test_docker_image_readback import image_data
from test_hosted_docker import diagnostics

DEFAULT = ['/usr/bin/true']


def actual_records():
    hashes = {'committed-image': 'b5249049e14b59f1a13a58d74ea79eca3d7a8e1bc7923c33dfa3a4bc1695d33a',
              'stopped': '25a313646c2905e086f120bdb589b7c88881d4901b635aeced0323292cd34049'}
    records = {}
    for name, expected in hashes.items():
        data = (ROOT / 'tests/fixtures' / ('run37704198046-' + name + '.json')).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('actual historical fixture hash drift')
        records[name] = json.loads(data)
    return records['committed-image'][0], records['stopped']


def command_merge(argv, inherited):
    """ONLY Moby v28.0.4 Cmd/Entrypoint merge rule, not an executed daemon."""
    changes = [argv[index + 1] for index, item in enumerate(argv) if item == '--change']
    cmd = json.loads(next(value[4:] for value in changes if value.startswith('CMD ')))
    entrypoint = json.loads(next(value[11:] for value in changes if value.startswith('ENTRYPOINT ')))
    if not entrypoint and not cmd:
        cmd = inherited
    return cmd, entrypoint


class DefaultCommandTests(unittest.TestCase):
    def test_both_production_commit_callers_model_exact_nonbootstrap_default(self):
        with scratch_home() as directory:
            root = Path(directory)
            for mode in ('legacy', 'hosted'):
                data = inspected(root)
                mapped = None
                if mode == 'hosted':
                    mapped = diagnostics(Path('/opt/inputs'))
                    data['Config']['Cmd'][-1] = '/opt/inputs/hosted_setup.py'
                    data['Config']['Env'] = [f'{key}={value}' for key, value in mapped.items()]
                    data['HostConfig'] = builder.bootstrap_host_config(hosted=mapped)
                argv = builder.commit_command(data, identity(), root, hosted=mapped)
                with self.subTest(mode=mode):
                    self.assertEqual(command_merge(argv, data['Config']['Cmd']), (DEFAULT, []))
                    self.assertIn('CMD ["/usr/bin/true"]', argv)
                    self.assertIn('ENTRYPOINT []', argv)
                    self.assertIn('USER 1000:1000', argv)
                    self.assertIn('WORKDIR /work', argv)
                    self.assertNotIn('CMD []', argv)

    def test_actual_failed_image_and_stopped_data_remain_rejected(self):
        image, stopped = actual_records()
        labels = stopped['Config']['Labels']
        ident = builder.BootstrapIdentity(labels[builder.BASE_LABEL], labels['org.network-atlas.acceptance.daemon'],
                                          stopped['Image'], labels['org.network-atlas.acceptance.plan'])
        mapped = dict(value.split('=', 1) for value in stopped['Config']['Env'] if value.startswith(('GITHUB_', 'RUNNER_')))
        context = Path(stopped['Mounts'][0]['Source'])
        with patch.object(builder, 'source_path', return_value=context):
            argv = builder.commit_command(stopped, ident, context, hosted=mapped)
        self.assertEqual(stopped['State']['ExitCode'], 0)
        self.assertEqual(image['DockerVersion'], '28.0.4')
        self.assertEqual(image['Config']['Cmd'], stopped['Config']['Cmd'])
        audit = builder.image_validation(image, ident, image['Id'], image['RootFS']['Layers'][:-1])
        self.assertEqual(audit['mismatches'], ['Config.Cmd'])
        self.assertEqual(audit['expected']['Config.Cmd'], DEFAULT)
        with self.assertRaisesRegex(ValueError, 'Config.Cmd'):
            builder.verify_final_image(image, ident)
        self.assertEqual(command_merge(argv, stopped['Config']['Cmd']), (DEFAULT, []))
        # Changing a COPY of the captured config models the proposed result only.
        modeled = copy.deepcopy(image)
        modeled['Config']['Cmd'], modeled['Config']['Entrypoint'] = command_merge(argv, stopped['Config']['Cmd'])
        self.assertTrue(builder.image_validation(modeled, ident, image['Id'], image['RootFS']['Layers'][:-1])['verified'])
        self.assertEqual(image['Config']['Cmd'], ['python3', '/opt/inputs/hosted_setup.py'])

    def test_exact_default_and_empty_entrypoint_required_by_all_consumers(self):
        data = image_data()
        data['Config']['Cmd'] = DEFAULT.copy()
        record = builder.verify_final_image(data, identity())
        acceptance.validate_base(data, record, identity().daemon)
        for field, bad in [('Cmd', value) for value in (None, [], ' /usr/bin/true', ['/bin/true'], ['true'],
                           ['/usr/bin/true', 'extra'], ['/bin/sh', '-c', 'true'], ['python3', '/opt/inputs/base_setup.py'],
                           ['python3', '/opt/inputs/hosted_setup.py'])] + [('Entrypoint', ['/bin/sh'])]:
            with self.subTest(field=field, bad=bad):
                mutated = copy.deepcopy(data)
                mutated['Config'][field] = bad
                with self.assertRaisesRegex(ValueError, 'Config.' + field):
                    builder.verify_final_image(mutated, identity())
                with self.assertRaises(ValueError):
                    acceptance.validate_base(mutated, record, identity().daemon)
                docker = Mock(json=Mock(return_value=[mutated]))
                with self.assertRaises(ValueError):
                    hosted.cleanup_image(docker, record)
                docker.run.assert_not_called()
        docker = Mock(json=Mock(return_value=[data]), run=Mock(return_value=b''))
        with patch.object(hosted, 'resource_ids', return_value={'images': [], 'containers': []}):
            hosted.cleanup_image(docker, record)
        self.assertEqual(docker.run.call_args_list[1].args[0], ['image', 'rm', data['Id']])
        for mode in ('smoke', 'fail', 'interrupt', 'refusal', 'accept', 'hosted-accept'):
            from docker_contract import Identity, create_command
            ident = Identity('a' * 40, 'b' * 40, data['Id'], identity().daemon)
            with scratch_home() as directory:
                root = Path(directory)
                argv = create_command(ident, root, mode, root, hosted=diagnostics(Path('/candidate')) if mode == 'hosted-accept' else None)
            self.assertEqual(argv[-4:], [data['Id'], 'python3', '/candidate/scripts/docker_inside.py', mode])

    def test_default_executable_availability_is_guarded_audited_and_output_free(self):
        good = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        with patch.object(Path, 'lstat', return_value=good), patch.object(base_setup, 'run', return_value='') as run:
            base_setup.check_default_command()
        run.assert_called_once_with(DEFAULT)
        for info in (SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0),
                     SimpleNamespace(st_mode=stat.S_IFREG | 0o777, st_uid=0),
                     SimpleNamespace(st_mode=stat.S_IFREG | 0o4755, st_uid=0),
                     SimpleNamespace(st_mode=stat.S_IFREG | 0o750, st_uid=0),
                     SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=1000)):
            with patch.object(Path, 'lstat', return_value=info), patch.object(base_setup, 'run') as run, self.assertRaises(ValueError):
                base_setup.check_default_command()
            run.assert_not_called()
        for error in (OSError('missing executable'), RuntimeError('exit=17')):
            with patch.object(Path, 'lstat', return_value=good), patch.object(base_setup, 'run', side_effect=error), self.assertRaises(type(error)):
                base_setup.check_default_command()
        with patch.object(Path, 'lstat', return_value=good), patch.object(base_setup, 'run', return_value='unexpected'), self.assertRaises(ValueError):
            base_setup.check_default_command()
        with patch.object(Path, 'lstat', side_effect=FileNotFoundError('no default')), patch.object(base_setup, 'run') as run, self.assertRaises(FileNotFoundError):
            base_setup.check_default_command()
        run.assert_not_called()
        # Both actual entrypoints require availability before success inventory.
        import ast
        for name in ('base_setup.py', 'hosted_setup.py'):
            tree = ast.parse((ROOT / 'docker' / name).read_text())
            main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
            calls = [node for node in ast.walk(main) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'check_default_command']
            self.assertEqual(len(calls), 1)
            export = next(node for node in ast.walk(main) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'write_bytes')
            self.assertLess(calls[0].lineno, export.lineno)

    def test_real_noop_child_uses_existing_audit_and_unverified_cleanup_stays_closed(self):
        # This is the local public no-op, NOT availability proof of the pinned image.
        import acquisition_support as acquisition
        with scratch_home() as directory:
            root = Path(directory)
            captured = io.StringIO()
            log = acquisition.CommandLog()
            with patch.object(base_setup, 'CORE', root), patch.object(acquisition, 'COMMAND_LOG', log), redirect_stdout(captured):
                base_setup.check_default_command()
            rows = [json.loads(line) for line in captured.getvalue().splitlines()]
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[-1]['public_command'], DEFAULT)
            self.assertEqual(rows[-1]['exit_code'], 0)
            self.assertEqual(rows[-1]['output_bytes'], 0)
            self.assertEqual(rows[-1]['output_sha256'], hashlib.sha256(b'').hexdigest())
            self.assertEqual(log.commands, 1)
            data = image_data()
            data['Config']['Cmd'] = DEFAULT.copy()
            record = builder.verify_final_image(data, identity())
            data['Config']['Cmd'] = ['python3', '/opt/inputs/hosted_setup.py']
            docker = Mock(json=Mock(return_value=[data]))
            original = ValueError('primary acceptance failure')
            hosted.finish_image(docker, record, {'Id': 'upstream'}, root, original)
            docker.run.assert_not_called()
            self.assertEqual(str(original), 'primary acceptance failure')
            self.assertTrue(any('Config.Cmd' in note for note in original.__notes__))
            self.assertIn('Config.Cmd', json.loads((root / 'base-cleanup-error.json').read_text())['error'])


if __name__ == '__main__':
    deny_network()
    unittest.main()
