# SPDX-License-Identifier: GPL-3.0-or-later
"""Actual base proof plus MODELED label inheritance; never real Docker admission."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
sys.path.insert(0, str(ROOT / 'scripts'))
from offline_guard import deny_network
deny_network()
import docker_acceptance as harness
import docker_builder as builder
import docker_contract as contract
from docker_evidence import BoundedDirectory, json_bytes
import hosted_evidence
import test_docker_acceptance as legacy

FIXTURES = ROOT / 'tests/fixtures'
CID = 'd' * 64


def proof():
    payload = (FIXTURES / 'run37707667589-committed-image.json').read_bytes()
    if hashlib.sha256(payload).hexdigest() != '69ed2298c400e69c89f8c2fcbe134f957a37362f8531a7d973364fd46d10296f':
        raise ValueError('actual public image fixture drift')
    record = (FIXTURES / 'run37707667589-base-identity.json').read_bytes()
    if hashlib.sha256(record).hexdigest() != '3064177868f2ccd6cb1ecb057846529d986cf1b4d52953cc591a91c2f606d2ec':
        raise ValueError('actual public base identity projection drift')
    return json.loads(payload)[0], json.loads(record)


def attempt_identity(record, *, bound=True):
    return contract.Identity('a' * 40, 'b' * 40, record['image'], record['daemon'],
                             base_labels=tuple(sorted(record['labels'].items())), container_id=CID if bound else None)


def model(candidate, identity, mode='smoke'):
    data = legacy.DockerContractTests().inspection(candidate)
    data.update(Id=CID, Image=identity.image)
    # Moby v28.0.4 daemon/commit.go merge: explicit keys win; only absent keys
    # inherit image values. This is a model, NOT run37707667589 container data.
    user = identity.labels()
    for key, value in dict(identity.base_labels).items():
        if key not in user:
            user[key] = value
    data['Config'].update(Labels=user, Cmd=['python3', '/candidate/scripts/docker_inside.py', mode])
    data['State'].update(ExitCode=0, OOMKilled=False)
    return data


class ContainerReadbackTests(unittest.TestCase):
    def test_predecessor_rejects_modeled_inheritance_from_actual_verified_base(self):
        image, record = proof()
        harness.validate_base(image, record, record['daemon'])
        identity = contract.Identity('a' * 40, 'b' * 40, record['image'], record['daemon'])
        with scratch_home() as directory:
            candidate = Path(directory)
            data = legacy.DockerContractTests().inspection(candidate)
            data['Image'] = identity.image
            data['Config']['Labels'] = dict(record['labels'], **identity.labels())
            # Production preflight must bind the immutable verified base, rather
            # than treating the five caller labels as the full container config.
            registry = candidate / 'registry'
            registry.mkdir()
            BoundedDirectory(registry).json('base.json', dict(record, consumers=[], dependency_inventory={}))
            fake = SimpleNamespace(daemon=identity.daemon, json=lambda _args: [image],
                                   run=lambda _args: b'', inspect=lambda _name: None)
            with patch.object(harness, 'clean_checkout', return_value=(identity.commit, identity.tree)):
                actual, _attempt = harness.attempt_preflight(fake, candidate, identity.image, 'smoke', registry)
            actual = replace(actual, container_id=data['Id'])
            self.assertTrue(contract.cleanup_allowed(data, actual))
            self.assertEqual(actual.container_labels(), data['Config']['Labels'])

    def test_exact_composition_base_drift_and_all_modes_preserve_isolation(self):
        image, record = proof()
        identity = attempt_identity(record)
        self.assertEqual(len(identity.container_labels()), 11)
        self.assertEqual(identity.container_labels(), dict(record['labels'], **identity.labels()))
        for labels in (record['labels'], list(record['labels'].items()), tuple(record['labels'].items())[:7],
                       tuple([('duplicate', 'value')] * 8), tuple([['mutable', 'value']] * 8)):
            with self.assertRaises(ValueError):
                replace(identity, base_labels=labels)
        with scratch_home() as directory:
            candidate = Path(directory)
            for mode in contract.MODES:
                hosted = {'GITHUB_WORKSPACE': '/candidate'} if mode == 'hosted-accept' else None
                argv = contract.create_command(identity, candidate, mode, candidate, hosted=hosted)
                labels = dict(argv[i + 1].split('=', 1) for i, v in enumerate(argv) if v == '--label')
                self.assertEqual(labels, identity.container_labels())
                self.assertEqual(argv[-4:], [identity.image, 'python3', '/candidate/scripts/docker_inside.py', mode])
                self.assertIn('--read-only', argv)
                self.assertIn('ALL', argv)
                data = model(candidate, identity, mode)
                data['Mounts'][1]['Source'] = str(candidate)
                data['Config']['Env'] = [k + '=' + v for k, v in (hosted or {}).items()]
                self.assertEqual(contract.validate_container(data, identity, candidate, mode, candidate, hosted=hosted), CID)
            for field in ('base_key', 'core_commit', 'core_tree', 'daemon', 'image', 'plan_hash', 'upstream_digest'):
                changed = dict(record, **{field: 'wrong'})
                with self.subTest(field=field), self.assertRaises((ValueError, KeyError)):
                    harness.validate_base(image, changed, record['daemon'])
            for key in record['labels']:
                changed = json.loads(json.dumps(record))
                changed['labels'][key] = 'wrong'
                changed_image = json.loads(json.dumps(image))
                changed_image['Config']['Labels'] = changed['labels']
                with self.subTest(label=key), self.assertRaises(ValueError):
                    harness.validate_base(changed_image, changed, record['daemon'])
            changed = json.loads(json.dumps(record))
            changed['labels']['arbitrary'] = 'extra'
            changed_image = json.loads(json.dumps(image))
            changed_image['Config']['Labels'] = changed['labels']
            with self.assertRaises(ValueError):
                harness.validate_base(changed_image, changed, record['daemon'])
            for key in ('User', 'WorkingDir', 'Cmd', 'Entrypoint', 'Volumes', 'ExposedPorts'):
                changed = json.loads(json.dumps(image))
                changed['Config'][key] = 'wrong'
                with self.subTest(config=key), self.assertRaises(ValueError):
                    harness.validate_base(changed, record, record['daemon'])

    def test_initial_raw_readback_precedes_each_identity_and_isolation_refusal(self):
        _image, record = proof()
        identity = attempt_identity(record)
        with scratch_home() as directory:
            root = Path(directory)
            candidate = root / 'candidate'
            candidate.mkdir()
            baseline = model(candidate, identity)
            cases = [('Name', '/unrelated'), ('Image', 'sha256:' + 'f' * 64), ('Id', 'e' * 64), ('Id', 'short')]
            for key in identity.container_labels():
                cases.append(('Config.Labels.' + key, 'wrong'))
            cases.extend([('Config.Labels.extra', 'unexpected'), ('HostConfig.NetworkMode', 'bridge')])
            for index, (field, value) in enumerate(cases):
                archive_root = root / str(index)
                attempt = archive_root / 'evidence/attempt'
                attempt.mkdir(parents=True)
                data = json.loads(json.dumps(baseline))
                target = data
                parts = field.split('.') if not field.startswith('Config.Labels.') else ['Config', 'Labels', field.removeprefix('Config.Labels.')]
                for part in parts[:-1]:
                    target = target[part]
                target[parts[-1]] = value
                calls = []
                fake = SimpleNamespace(inspect=lambda name: data, run=lambda argv, **kw: calls.append(argv))
                validator = lambda current: contract.validate_container(current, identity, candidate, 'smoke')
                with self.subTest(field=field), self.assertRaises(ValueError):
                    harness.read_container(fake, identity, attempt, 'created', validator=validator)
                raw = json.loads((attempt / 'metadata/created.json').read_text())
                audit = json.loads((attempt / 'metadata/created-validation.json').read_text())
                self.assertEqual(raw, data)
                self.assertFalse(audit['verified'])
                if field != 'HostConfig.NetworkMode':
                    self.assertIn('Config.Labels' if field.startswith('Config.Labels.') else field, audit['mismatches'])
                if field.startswith('Config.Labels.'):
                    self.assertIn(field.removeprefix('Config.Labels.'), audit['label_mismatches'])
                self.assertEqual(audit['readback_sha256'], hashlib.sha256(json_bytes(data)).hexdigest())
                self.assertEqual(calls, [])
                bundle = archive_root / 'compact.tar'
                result = hosted_evidence.pack(archive_root, bundle)
                self.assertGreater(result['members'], 0)
                with tarfile.open(bundle) as archive:
                    member = archive.extractfile('evidence/attempt/metadata/created.json')
                    if member is None:
                        self.fail('actual inspect export member absent')
                    self.assertEqual(json.loads(member.read()), data)

    def test_export_cleanup_revalidate_full_labels_and_returned_id_without_unsafe_effects(self):
        _image, record = proof()
        identity = attempt_identity(record)
        with scratch_home() as directory:
            root = Path(directory)
            for stage in ('export', 'cleanup'):
                attempt = root / stage
                attempt.mkdir()
                data = model(root, identity)
                data['Config']['Labels']['extra'] = 'untrusted'
                calls = []
                fake = SimpleNamespace(inspect=lambda name: data, run=lambda argv, **kw: calls.append(argv))
                with self.assertRaises(ValueError):
                    if stage == 'export':
                        harness.collect_export(fake, attempt, identity)
                    else:
                        harness.teardown(fake, identity, attempt=attempt)
                self.assertEqual(calls, [])
                self.assertEqual(json.loads((attempt / f'metadata/{stage}.json').read_text()), data)
            attempt = root / 'changed-id'
            attempt.mkdir()
            first = model(root, identity)
            first['State']['Running'] = True
            other = json.loads(json.dumps(first))
            other['Id'] = 'e' * 64
            other['State']['Running'] = False
            calls = []
            fake = SimpleNamespace(inspect=iter((first, other)).__next__)
            fake.inspect = lambda name, read=fake.inspect: read()
            fake.run = lambda argv, **kw: calls.append(argv) or b''
            with self.assertRaises(ValueError):
                harness.teardown(fake, identity, attempt=attempt)
            self.assertEqual(calls, [['stop', '--time', '5', CID]])
            self.assertEqual(json.loads((attempt / 'metadata/cleanup-stopped-validation.json').read_text())['mismatches'], ['Id'])
            calls.clear()
            fake.inspect = lambda name: other
            with self.assertRaises(ValueError):
                harness.wait_container(fake, CID, harness.time.monotonic() + 1, identity=identity)
            self.assertEqual(calls, [])

    def test_diagnostic_shape_bound_absence_error_and_failure_precedence(self):
        _image, record = proof()
        identity = attempt_identity(record)
        with scratch_home() as directory:
            root = Path(directory)
            for index, data in enumerate((None, ['malformed'], {'Id': 'short'}, dict(model(root, identity), huge='x' * (512 * 1024)))):
                attempt = root / str(index)
                attempt.mkdir()
                fake = SimpleNamespace(inspect=lambda name, value=data: value)
                with self.assertRaises((ValueError, RuntimeError)):
                    harness.read_container(fake, identity, attempt, 'created', required=True)
                audit = json.loads((attempt / 'metadata/created-validation.json').read_text())
                self.assertFalse(audit['verified'])
                self.assertLess((attempt / 'metadata/created-validation.json').stat().st_size, 8192)
            attempt = root / 'write-error'
            attempt.mkdir()
            bad = model(root, identity)
            bad['Name'] = '/unrelated'
            fake = SimpleNamespace(inspect=lambda name: bad)
            with patch.object(BoundedDirectory, 'json', side_effect=OSError('diagnostic disk failure')):
                with self.assertRaisesRegex(ValueError, 'Name') as caught:
                    harness.read_container(fake, identity, attempt, 'created')
            self.assertTrue(any('diagnostic disk failure' in note for note in caught.exception.__notes__))
            fake.inspect = lambda name: model(root, identity)
            with patch.object(BoundedDirectory, 'json', side_effect=OSError('diagnostic disk failure')):
                with self.assertRaisesRegex(OSError, 'diagnostic disk failure'):
                    harness.read_container(fake, identity, attempt, 'created')
            fake.inspect = lambda name: None
            self.assertIsNone(harness.read_container(fake, identity, attempt, 'cleanup'))
            fake.inspect = lambda name: (_ for _ in ()).throw(OSError('daemon failed'))
            with self.assertRaisesRegex(OSError, 'daemon failed'):
                harness.read_container(fake, identity, attempt, 'cleanup')
            # Exercise the actual fixed-name list/inspect adapter, not just the
            # convenient fake.inspect seam. Missing Id must reach raw export.
            adapter = harness.Docker.__new__(harness.Docker)
            calls = []
            adapter.run = lambda argv: calls.append(argv) or (CID + '\n').encode()
            adapter.json = lambda argv: [{}]
            with self.assertRaisesRegex(ValueError, 'Id'):
                harness.read_container(adapter, identity, attempt, 'created')
            self.assertEqual(json.loads((attempt / 'metadata/created.json').read_text()), {})
            self.assertEqual(calls, [['ps', '-aq', '--no-trunc', '--filter', 'name=^/' + contract.NAME + '$']])
            adapter.run = lambda argv: b''
            self.assertIsNone(harness.read_container(adapter, identity, attempt, 'cleanup'))
            adapter.run = lambda argv: (_ for _ in ()).throw(OSError('actual adapter daemon read failed'))
            with self.assertRaisesRegex(OSError, 'actual adapter daemon read failed'):
                harness.read_container(adapter, identity, attempt, 'cleanup')

    def test_run_attempt_binds_create_id_and_keeps_consumers_and_primary_failure(self):
        _image, record = proof()
        with scratch_home() as directory:
            root = Path(directory)
            registry = root / 'registry'
            registry.mkdir()
            BoundedDirectory(registry).json('base.json', dict(record, consumers=[], dependency_inventory={}))
            attempt = root / 'evidence/attempt'
            attempt.mkdir(parents=True)
            (attempt / 'incoming').mkdir()
            identity = attempt_identity(record, bound=False)
            builder.register_consumer(registry, identity, attempt, 'active')
            calls = []
            data = None
            def run(argv, **kw):
                nonlocal data
                calls.append(argv)
                if argv[0] == 'create':
                    data = model(root / 'candidate', replace(identity, container_id=CID))
                    data['Mounts'][1]['Source'] = str(attempt / 'incoming')
                    data['Id'] = 'e' * 64  # Replacement with otherwise perfect labels.
                    return (CID + '\n').encode()
                self.fail('effects on unverified replacement: ' + repr(argv))
            fake = SimpleNamespace(daemon=identity.daemon, run=run, inspect=lambda name: data)
            def snapshot(source, commit, destination):
                destination.mkdir()
            with patch.object(harness, 'attempt_preflight', return_value=(identity, attempt)), patch.object(harness, 'snapshot', side_effect=snapshot):
                outcome = harness.run_attempt(fake, root, identity.image, 'smoke', registry)
            self.assertIn('Id', outcome['error'])
            self.assertIn('Id', outcome['cleanup_error'])
            self.assertIn('Id', outcome['export_error'])
            self.assertNotIn('cleanup_verified', outcome)
            self.assertFalse(outcome['native_acceptance'])
            self.assertEqual(outcome['container_id'], CID)
            self.assertEqual([argv[0] for argv in calls], ['create'])
            self.assertTrue((root / 'candidate').exists())
            consumer = json.loads((registry / 'base.json').read_text())['consumers'][0]
            self.assertEqual(consumer['container_id'], CID)
            self.assertEqual(consumer['labels'], identity.container_labels())
            self.assertEqual(consumer['status'], 'retained-awaiting-review')
            self.assertEqual(json.loads((attempt / 'metadata/created.json').read_text()), data)
            self.assertEqual(len(json.loads((registry / 'base.json').read_text())['consumers']), 1)

    def test_owned_export_cleanup_success_and_create_failure_never_claim_absence(self):
        _image, record = proof()
        identity = attempt_identity(record)
        with scratch_home() as directory:
            root = Path(directory)
            incoming = root / 'incoming'
            incoming.mkdir()
            (incoming / 'result.json').write_text('{}')
            data = model(root, identity)
            calls = []
            def run(argv, **kw):
                nonlocal data
                calls.append(argv)
                if argv[0] == 'rm':
                    data = None
                return b''
            fake = SimpleNamespace(inspect=lambda name: data, run=run)
            result = harness.collect_export(fake, root, identity)
            self.assertIn('result.json', result['export_hashes'])
            harness.teardown(fake, identity, attempt=root)
            self.assertEqual(calls, [['logs', CID], ['rm', CID]])
            self.assertIsNone(data)
            self.assertIsNone(json.loads((root / 'metadata/cleanup-absent.json').read_text()))
            data = model(root, identity)
            calls.clear()
            with self.assertRaises(ValueError):
                harness.teardown(fake, replace(identity, container_id=None), attempt=root)
            self.assertEqual(calls, [])

    def test_create_return_failure_retains_actual_residue_without_deletion(self):
        _image, record = proof()
        identity = attempt_identity(record, bound=False)
        with scratch_home() as directory:
            root = Path(directory)
            for index, returned in enumerate((b'', b'short\n', ('e' * 64 + '\n').encode(), OSError('create failed'))):
                work = root / str(index)
                work.mkdir()
                registry = work / 'registry'
                registry.mkdir()
                BoundedDirectory(registry).json('base.json', dict(record, consumers=[], dependency_inventory={}))
                attempt = work / 'evidence/attempt'
                attempt.mkdir(parents=True)
                (attempt / 'incoming').mkdir()
                data = model(work / 'candidate', replace(identity, container_id=CID))
                data['Mounts'][1]['Source'] = str(attempt / 'incoming')
                calls = []
                def run(argv, **kw):
                    calls.append(argv)
                    if argv[0] != 'create':
                        self.fail('unverified resource mutation: ' + repr(argv))
                    if isinstance(returned, OSError):
                        raise returned
                    return returned
                fake = SimpleNamespace(run=run, inspect=lambda name: data)
                with patch.object(harness, 'attempt_preflight', return_value=(identity, attempt)), patch.object(harness, 'snapshot', side_effect=lambda source, commit, dest: dest.mkdir()):
                    outcome = harness.run_attempt(fake, work, identity.image, 'smoke', registry)
                self.assertIn('error', outcome)
                self.assertIn('cleanup_error', outcome)
                self.assertNotIn('cleanup_verified', outcome)
                self.assertEqual([argv[0] for argv in calls], ['create'])
                self.assertEqual(json.loads((attempt / 'metadata/cleanup.json').read_text()), data)
                self.assertTrue((work / 'candidate').exists())
                self.assertEqual(len(json.loads((registry / 'base.json').read_text())['consumers']), 1)

    def test_consumer_retention_survives_outcome_error_and_provenance_drift_refuses(self):
        _image, record = proof()
        identity = attempt_identity(record)
        with scratch_home() as directory:
            root = Path(directory)
            registry = root / 'registry'
            registry.mkdir()
            BoundedDirectory(registry).json('base.json', dict(record, consumers=[], dependency_inventory={}))
            fake = SimpleNamespace(inspect=lambda name: None)
            outcome = {'error': 'primary unchanged', 'mode': 'smoke'}
            with patch.object(harness, 'collect_export', side_effect=OSError('export error')), patch.object(harness, 'teardown', side_effect=OSError('cleanup error')), patch.object(harness, 'export_attempt_outcome', side_effect=OSError('outcome error')):
                harness.finish_attempt(fake, root, root, identity, outcome, registry)
            self.assertEqual(outcome['error'], 'primary unchanged')
            self.assertIn('outcome error', outcome['outcome_export_error'])
            saved = json.loads((registry / 'base.json').read_text())
            self.assertEqual(saved['consumers'][0]['container_id'], CID)
            self.assertEqual(saved['consumers'][0]['status'], 'retained-awaiting-review')
            saved['labels']['org.network-atlas.acceptance.plan'] = 'e' * 64
            BoundedDirectory(registry).json('base.json', saved)
            before = (registry / 'base.json').read_bytes()
            with self.assertRaisesRegex(ValueError, 'provenance'):
                builder.register_consumer(registry, identity, root, 'active')
            self.assertEqual(before, (registry / 'base.json').read_bytes())

    def test_production_smoke_sequence_uses_exact_model_and_full_owned_lifecycle(self):
        image, record = proof()
        with scratch_home() as directory:
            root = Path(directory)
            registry = root / 'registry'
            registry.mkdir()
            BoundedDirectory(registry).json('base.json', dict(record, consumers=[], dependency_inventory={}))
            data = None
            calls = []
            def run(argv, **kw):
                nonlocal data
                calls.append(argv)
                if argv[0] == 'create':
                    labels = dict(argv[i + 1].split('=', 1) for i, value in enumerate(argv) if value == '--label')
                    self.assertEqual(labels, dict(record['labels'], **attempt_identity(record).labels()))
                    data = model(root / 'candidate', attempt_identity(record))
                    incoming = root / 'evidence' / ('a' * 40 + '-smoke') / 'incoming'
                    data['Mounts'][1]['Source'] = str(incoming)
                    (incoming / 'result.json').write_text(json.dumps({'native_acceptance': False, 'packet_denial_smoke': True}))
                    return (CID + '\n').encode()
                if argv[0] == 'rm':
                    self.assertEqual(argv[1], CID)
                    data = None
                return b''
            fake = SimpleNamespace(daemon=record['daemon'], json=lambda argv: [image],
                                   inspect=lambda name: data, run=run)
            with patch.object(harness, 'clean_checkout', return_value=('a' * 40, 'b' * 40)), patch.object(harness, 'snapshot', side_effect=lambda source, commit, dest: dest.mkdir()):
                result = harness.run_attempt(fake, root, record['image'], 'smoke', registry)
            self.assertEqual(result['canary_verified'], True)
            self.assertEqual(result['cleanup_verified'], True)
            self.assertEqual(result['identity'], attempt_identity(record).container_labels())
            self.assertFalse(result['native_acceptance'])
            self.assertIsNone(data)
            self.assertFalse((root / 'candidate').exists())
            self.assertEqual([argv[0] for argv in calls], ['ps', 'create', 'start', 'logs', 'rm'])
            self.assertEqual(calls[2], ['start', CID])
            self.assertEqual(calls[3], ['logs', CID])


if __name__ == '__main__':
    unittest.main()
