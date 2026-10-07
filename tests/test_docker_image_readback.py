# SPDX-License-Identifier: GPL-3.0-or-later
"""Actual production readback/export seams; synthetic daemon, no Docker execution."""

import json
from pathlib import Path
import sys
import tarfile
import unittest
from unittest.mock import Mock, patch

from helpers import ROOT, scratch_home
sys.path.insert(0, str(ROOT / 'scripts'))
import docker_builder as builder
import docker_evidence as evidence
import hosted_docker as hosted
import hosted_evidence
from offline_guard import deny_network
from test_docker_builder import identity, inspected

IMAGE = 'sha256:' + '2' * 64
LAYERS = ['sha256:' + 'b' * 64]


def image_data():
    return {'Id': IMAGE, 'Size': 123, 'Config': {
        'Labels': dict(identity().labels(), **{'org.network-atlas.acceptance.kind': 'base'}),
        'User': '1000:1000', 'WorkingDir': '/work', 'Cmd': [], 'Entrypoint': [],
        'Volumes': None, 'ExposedPorts': None},
        'RootFS': {'Layers': [*LAYERS, 'sha256:' + '3' * 64]}}


def proof_dirs(directory):
    root = Path(directory) / 'bootstrap'
    registry = Path(directory) / 'registry'
    root.mkdir()
    registry.mkdir()
    return root, registry


class ImageReadbackTests(unittest.TestCase):
    def test_each_safety_mismatch_names_precise_field_without_relaxation(self):
        mutations = {'Labels': {}, 'User': '0:0', 'Volumes': {'/state': {}},
                     'Entrypoint': ['unsafe'], 'Cmd': ['python3', '/opt/inputs/hosted_setup.py'],
                     'ExposedPorts': {'80/tcp': {}}, 'WorkingDir': '/'}
        for field, bad in mutations.items():
            data = image_data()
            data['Config'][field] = bad
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'Config.' + field):
                builder.verify_final_image(data, identity())
        for field, bad in (('Id', 'short'), ('RootFS', {'Layers': []})):
            data = image_data()
            data[field] = bad
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                builder.verify_final_image(data, identity())

    def test_empty_commit_command_merge_is_source_hypothesis_not_hosted_proof(self):
        # Moby v28.0.4 daemon/commit.go merge restores container Cmd when both
        # changed Cmd and Entrypoint have length zero. This models ONLY that
        # source rule, not the unexported run81 committed image or real Docker.
        with scratch_home() as directory:
            data = inspected(Path(directory))
            data['Config']['Cmd'] = ['python3', '/opt/inputs/hosted_setup.py']
            from test_hosted_docker import diagnostics
            mapped = diagnostics(Path('/opt/inputs'))
            data['Config']['Env'] = [f'{k}={v}' for k, v in mapped.items()]
            data['HostConfig'] = builder.bootstrap_host_config(hosted=mapped)
            argv = builder.commit_command(data, identity(), Path(directory), hosted=mapped)
            self.assertIn('CMD []', argv)
            self.assertIn('ENTRYPOINT []', argv)
            committed = image_data()
            if not committed['Config']['Cmd'] and not committed['Config']['Entrypoint']:
                committed['Config']['Cmd'] = data['Config']['Cmd']
            with self.assertRaisesRegex(ValueError, 'Config.Cmd'):
                builder.verify_final_image(committed, identity())
            self.assertEqual(builder.verify_final_image(image_data(), identity())['image'], IMAGE)

    def test_actual_readback_journal_mismatch_and_compact_export_survive_refusal(self):
        with scratch_home() as directory:
            root = Path(directory)
            proof = root / 'bootstrap'
            registry = root / 'registry'
            proof.mkdir()
            registry.mkdir()
            data = image_data()
            data['Config']['Cmd'] = ['python3', '/opt/inputs/hosted_setup.py']
            def inspect(argv):
                self.assertEqual(argv, ['image', 'inspect', IMAGE])
                journal = json.loads((registry / 'bootstrap.json').read_text())
                self.assertEqual(journal['returned_image'], IMAGE)
                self.assertEqual(journal['status'], 'commit-returned-awaiting-readback')
                return [data]
            docker = Mock(json=Mock(side_effect=inspect))
            with self.assertRaisesRegex(ValueError, 'Config.Cmd'):
                builder.read_final_image(docker, IMAGE, identity(), proof, registry, LAYERS)
            self.assertEqual(json.loads((proof / 'committed-image.json').read_text()), [data])
            audit = json.loads((proof / 'image-validation.json').read_text())
            self.assertEqual(audit['mismatches'], ['Config.Cmd'])
            self.assertEqual(audit['observed']['Config.Cmd'], data['Config']['Cmd'])
            self.assertEqual(audit['expected']['Config.Cmd'], 'empty')
            self.assertFalse(audit['verified'])
            self.assertFalse((registry / 'base.json').exists())
            archive = root / 'evidence.tar'
            hosted_evidence.pack(root, archive)
            with tarfile.open(archive) as bundle:
                self.assertIn('bootstrap/committed-image.json', bundle.getnames())
                self.assertIn('bootstrap/image-validation.json', bundle.getnames())

    def test_returned_identity_and_exact_upstream_layers_must_match(self):
        for kind in ('Id', 'RootFS.Layers', 'malformed-layer'):
            with self.subTest(kind=kind), scratch_home() as directory:
                root, registry = proof_dirs(directory)
                data = image_data()
                if kind == 'Id':
                    data['Id'] = 'sha256:' + '4' * 64
                else:
                    data['RootFS']['Layers'][0] = 'short' if kind == 'malformed-layer' else 'sha256:' + '4' * 64
                with self.assertRaises(ValueError):
                    builder.read_final_image(Mock(json=Mock(return_value=[data])), IMAGE, identity(), root, registry, LAYERS)
                audit = json.loads((root / 'image-validation.json').read_text())
                self.assertFalse(audit['verified'])
        with scratch_home() as directory:
            root, registry = proof_dirs(directory)
            record = builder.read_final_image(Mock(json=Mock(return_value=[image_data()])), IMAGE, identity(), root, registry, LAYERS)
            self.assertEqual(record['rootfs_layers'], image_data()['RootFS']['Layers'])
            self.assertTrue(json.loads((root / 'image-validation.json').read_text())['verified'])

    def test_readback_command_shape_bound_and_export_errors_never_fabricate_success(self):
        cases = (RuntimeError('daemon inspect failed'), [], [image_data(), image_data()],
                 [{'Id': IMAGE}], [dict(image_data(), extra='x' * (512 * 1024))])
        for result in cases:
            with self.subTest(result_type=type(result).__name__), scratch_home() as directory:
                root, registry = proof_dirs(directory)
                docker = Mock(json=Mock(side_effect=result)) if isinstance(result, Exception) else Mock(json=Mock(return_value=result))
                with self.assertRaises((ValueError, RuntimeError)):
                    builder.read_final_image(docker, IMAGE, identity(), root, registry, LAYERS)
                journal = json.loads((root / 'image-commit.json').read_text())
                self.assertEqual(journal['returned_image'], IMAGE)
                self.assertFalse(journal['verified'])
                self.assertFalse((registry / 'base.json').exists())
        with scratch_home() as directory:
            root = Path(directory)
            data = image_data()
            data['Config']['User'] = '0:0'
            with patch.object(evidence.BoundedDirectory, 'json', side_effect=OSError('export denied')), \
                    self.assertRaisesRegex(ValueError, 'Config.User') as failure:
                builder.read_final_image(Mock(json=Mock(return_value=[data])), IMAGE, identity(), root, root, LAYERS)
            self.assertTrue(any('OSError' in note for note in failure.exception.__notes__))
            with patch.object(builder, 'registry_budget', side_effect=ValueError('registry drift')), \
                    self.assertRaisesRegex(ValueError, 'Config.User') as failure:
                builder.read_final_image(Mock(json=Mock(return_value=[data])), IMAGE, identity(), root, root, LAYERS)
            self.assertTrue(any('registry drift' in note for note in failure.exception.__notes__))
            with patch.object(evidence.BoundedDirectory, 'json', side_effect=OSError('export denied')), \
                    self.assertRaisesRegex(OSError, 'export denied'):
                builder.read_final_image(Mock(json=Mock(return_value=[image_data()])), IMAGE, identity(), root, root, LAYERS)

    def test_unverified_image_cleanup_refuses_and_preserves_primary_on_export_failure(self):
        with scratch_home() as directory:
            docker = Mock()
            primary = ValueError('Config.Cmd drift')
            with patch.object(evidence.BoundedDirectory, 'json', side_effect=OSError('export denied')):
                hosted.finish_image(docker, None, {'Id': 'upstream'}, Path(directory), primary)
            docker.json.assert_not_called()
            docker.run.assert_not_called()
            self.assertIn('Config.Cmd', str(primary))
            self.assertTrue(any('no verified base identity' in note for note in primary.__notes__))
            self.assertTrue(any('export failed' in note for note in primary.__notes__))


    def test_hosted_failed_image_retains_proofs_and_never_registers_or_deletes_base(self):
        from test_docker_bootstrap_repair import ExportDocker, archive, NAMES
        from test_hosted_docker import diagnostics
        status = {'CapEff': '00000000a80425fb', 'CapPrm': '00000000a80425fb',
                  'CapBnd': '00000000a80425fb', 'CapInh': '0000000000000000',
                  'CapAmb': '0000000000000000', 'NoNewPrivs': '1', 'Seccomp': '2'}
        with scratch_home() as directory:
            root = Path(directory)
            (root / 'context').mkdir()
            registry = root / 'registry'
            registry.mkdir()
            fake = ExportDocker(root, failed=False)
            fake.daemon = identity().daemon
            mapped = diagnostics(Path('/opt/inputs'))
            fake.data['HostConfig'] = builder.bootstrap_host_config(hosted=mapped)
            fake.data['Config']['Env'] = [f'{k}={v}' for k, v in mapped.items()]
            fake.data['Config']['Cmd'][-1] = '/opt/inputs/hosted_setup.py'
            fake.data['Mounts'][0]['Source'] = str(root / 'context')
            final = image_data()
            final['Config']['Cmd'] = fake.data['Config']['Cmd']
            fake.json = Mock(return_value=[final])
            original_run = fake.run
            def run(argv, **kwargs):
                if argv[0] in {'create', 'start', 'commit'}:
                    fake.calls.append(argv)
                    return IMAGE.encode() if argv[0] == 'commit' else b''
                if argv[0] == 'cp' and argv[1].endswith('/inventory.json'):
                    return archive('inventory.json', json.dumps({'bootstrap_process': status}).encode())
                return original_run(argv, **kwargs)
            fake.run = run
            with patch.dict(hosted.os.environ, diagnostics(), clear=True), \
                    patch.object(hosted, 'git_head', return_value='a' * 40), \
                    patch.object(hosted, 'context', return_value=identity().base_key), \
                    patch.object(hosted, 'upstream', return_value={'Id': identity().image, 'RootFS': {'Layers': LAYERS}}), \
                    patch.object(hosted, 'BootstrapIdentity', return_value=identity()), \
                    patch.object(hosted, 'reject_existing_owned', return_value={}), \
                    patch.object(hosted, 'wait_setup', return_value=fake.data):
                result, _ = hosted.build(fake, root, root, diagnostics(), registry)
            self.assertIn('Config.Cmd', result['error'])
            self.assertEqual(result['returned_image'], IMAGE)
            self.assertTrue(result['cleanup_verified'])
            self.assertIsNone(fake.data)
            self.assertNotIn('base', result)
            self.assertFalse((registry / 'base.json').exists())
            self.assertEqual(set(result['export_hashes']), set(NAMES))
            self.assertEqual(json.loads((root / 'bootstrap/committed-image.json').read_text()), [final])
            self.assertIn('Config.Cmd', json.loads((root / 'bootstrap/outcome.json').read_text())['error'])
            self.assertFalse(any(argv[:2] == ['image', 'rm'] for argv in fake.calls))


if __name__ == '__main__':
    deny_network()
    unittest.main()
