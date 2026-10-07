# SPDX-License-Identifier: GPL-3.0-or-later
"""Tiny socket-denied APT/diagnostic seams, never real package provisioning."""
import hashlib
from contextlib import nullcontext
import json
from pathlib import Path
import subprocess
import shutil
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from helpers import ROOT, scratch_home
sys.path.insert(0, str(ROOT / 'docker'))
sys.path.insert(0, str(ROOT / 'scripts'))
import hosted_apt as apt
import acquisition_support as acquisition
import docker_builder as builder
import hosted_evidence
import hosted_setup as setup
from test_docker_bootstrap_repair import ExportDocker, NAMES, archive
from test_docker_builder import identity


class AptFixture:
    def __init__(self, root, *, fail=None, empty=None, drift=None):
        self.seed = root / 'seed'
        self.seed.mkdir()
        self.config = root / 'apt'
        (self.config / 'apt.conf.d').mkdir(parents=True)
        (self.config / 'sources.list.d').mkdir()
        self.hook = self.config / 'apt.conf.d/docker-clean'
        self.hook.write_text('DPkg::Post-Invoke { "rm -f /var/cache/apt/archives/*.deb"; };\n')
        self.lists, self.cache = root / 'lists', root / 'cache'
        self.lists.mkdir()
        self.cache.mkdir()
        (self.cache / 'partial').mkdir()
        self.fail, self.empty, self.drift = fail, empty, drift
        self.calls = []
        self.before = {'base:amd64': '1', 'ca-certificates:all': '2'}
        self.after = {**self.before, 'git:amd64': '3', 'openssh-client:amd64': '4'}
        self.payloads = {'git.deb': b'tiny authenticated acquisition seam git',
                         'ssh.deb': b'tiny authenticated acquisition seam ssh'}

    def run(self, argv, cwd, *, audit, **kwargs):
        stage = audit['stage']
        self.calls.append((stage, argv))
        output = stage + ' actual mocked command output\n'
        audit.update(output=output, output_bytes=len(output), output_truncated=False,
                     output_sha256=hashlib.sha256(output.encode()).hexdigest(), exit_code=1 if stage == self.fail else 0)
        if stage == self.fail:
            raise RuntimeError(stage + ' primary failure')
        if stage in {'installed-before', 'installed-after'}:
            rows = self.before if stage == 'installed-before' else self.after
            return ''.join(f'{key.split(":")[0]}\t{key.split(":")[1]}\t{version}\tinstall ok installed\n' for key, version in rows.items())
        if stage == 'update' and self.empty != 'indexes':
            (self.lists / 'snapshot_InRelease').write_bytes(b'tiny signed-index seam')
            (self.lists / 'snapshot_Packages.lz4').write_bytes(b'tiny authenticated-list seam')
            if self.drift == 'no-release':
                (self.lists / 'snapshot_InRelease').unlink()
        if stage == 'download' and self.empty != 'archives':
            for name, data in self.payloads.items():
                (self.cache / name).write_bytes(data)
        if stage == 'archive-identity':
            if self.drift == 'control':
                return 'Package: broken\n'
            name = 'git' if argv[2].endswith('git.deb') else 'openssh-client'
            if self.drift == 'duplicate':
                name = 'git'
            if self.drift == 'archive':
                (self.cache / 'git.deb').write_bytes(b'drifted cache')
            return f'Package: {name}\nArchitecture: amd64\nVersion: {"3" if name == "git" else "4"}\n'
        if stage == 'install':
            # Exercise the real production post-install collection/binding,
            # with precisely the cache removal that broke the predecessor.
            for name in self.payloads:
                (self.cache / name).unlink()
            if self.drift == 'installed':
                self.after['git:amd64'] = 'wrong'
            if self.drift == 'unacquired':
                self.after['unacquired:amd64'] = '1'
            if self.drift == 'index':
                (self.lists / 'snapshot_InRelease').write_bytes(b'drift')
        return output

    def provision(self):
        with patch.object(apt, 'container_setup_guard'), patch.object(apt, 'bounded_run', side_effect=self.run):
            return apt.provision('20260919T000000Z', self.seed, self.seed,
                                 apt_root=self.config, lists=self.lists, cache=self.cache)

    def diagnostic(self):
        return json.loads((self.seed / 'apt-diagnostics.json').read_text())


class AptProofTests(unittest.TestCase):
    def test_native_tool_hashes_captured_before_publication_removes_fetch_cache(self):
        with scratch_home() as directory:
            root = Path(directory)
            (root / 'pm').mkdir()
            data = b'tiny actual fixture archive'
            digest = hashlib.sha256(data).hexdigest()
            lock = {'packages': {name: {'artifacts': {'linux-x64': {'url': 'https://github.com/fixture/tool.tar', 'sha256': digest}}}
                                 for name in ('python', 'uv')}}
            (root / 'pm/lock.json').write_text(json.dumps(lock))
            calls = []
            def fetch(items, scratch, *, progress):
                calls.append(items)
                progress(len(data), len(data), {})
                target = root / 'tools' / ('fetch-' + digest)
                target.mkdir(parents=True)
                (target / 'tool.tar').write_bytes(data)
            store = SimpleNamespace(install_lock=lambda: nullcontext(), scratch=lambda: nullcontext(root), fetch_many=fetch)
            with patch.object(setup, 'container_setup_guard'), patch.object(setup, 'SEED', root), \
                    patch.object(setup, 'CORE', root), \
                    patch.dict(sys.modules, {'pm.store': SimpleNamespace(Store=lambda path: store)}):
                setup.fetch_tools()
            shutil.rmtree(root / 'tools')  # Simulated native post-publication deletion.
            records = json.loads((root / 'tool-archives.json').read_text())
            self.assertEqual(len(calls), 1)
            self.assertEqual(len(records), 2)
            self.assertTrue(all(row['sha256'] == digest and row['bytes'] == len(data) for row in records))

    def test_native_fetch_tools_local_guard_precedes_import_and_files(self):
        with patch.dict(setup.os.environ, {}, clear=True), patch.object(setup.Path, 'read_text') as read, \
                self.assertRaisesRegex(ValueError, 'local execution'):
            setup.fetch_tools()
        read.assert_not_called()
        with patch.dict(setup.os.environ, {}, clear=True), patch.object(apt.Path, 'write_bytes') as write, \
                self.assertRaisesRegex(ValueError, 'local execution'):
            apt.provision('20260919T000000Z', Path('/unused'), Path('/unused'))
        write.assert_not_called()

    def test_normal_cache_cleanup_keeps_genuine_preinstall_hashes_and_base_versions(self):
        with scratch_home() as directory:
            fake = AptFixture(Path(directory))
            hook = fake.hook.read_bytes()
            result = fake.provision()
            self.assertTrue(result['success'])
            self.assertEqual(result['archive_count'], 2)
            self.assertEqual(result['index_count'], 2)
            self.assertEqual(result['unchanged_base_packages'], fake.before)
            self.assertEqual(fake.hook.read_bytes(), hook)
            self.assertEqual(list(fake.cache.glob('*.deb')), [])
            for name, data in fake.payloads.items():
                self.assertEqual(result['archives'][name]['sha256'], hashlib.sha256(data).hexdigest())
                self.assertEqual(result['archives'][name]['bytes'], len(data))
            self.assertEqual(result, fake.diagnostic())
            self.assertIn('docker-clean', result['hooks'])
            stages = dict(fake.calls)
            self.assertIn('--download-only', stages['download'])
            self.assertIn('--no-download', stages['install'])
            self.assertEqual(stages['install'][-3:], list(apt.ROOTS))
            self.assertIn('--no-install-recommends', stages['install'])
            self.assertIn('APT::Get::AllowUnauthenticated=false', stages['install'])
            self.assertFalse(any('--allow-unauthenticated' in command for _, command in fake.calls))
            self.assertIn('APT::Update::Error-Mode=any', stages['update'])
            self.assertIn('Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg',
                          (fake.config / 'sources.list.d/debian.sources').read_text())

    def test_empty_index_and_archive_refuse_with_distinct_incremental_counts(self):
        for empty, counts, stage in [('indexes', (0, None), 'index-proof'), ('archives', (2, 0), 'archive-proof')]:
            with self.subTest(empty=empty), scratch_home() as directory:
                fake = AptFixture(Path(directory), empty=empty)
                with self.assertRaisesRegex(ValueError, 'proof absent'):
                    fake.provision()
                record = fake.diagnostic()
                self.assertEqual((record['index_count'], record['archive_count']), counts)
                self.assertEqual(record['stage'], stage)
                self.assertFalse(record['success'])
                self.assertNotIn('install', dict(fake.calls))

    def test_index_archive_control_and_installed_drift_refuse_not_success(self):
        for drift in ('control', 'installed', 'unacquired', 'index', 'archive', 'duplicate', 'no-release'):
            with self.subTest(drift=drift), scratch_home() as directory:
                fake = AptFixture(Path(directory), drift=drift)
                with self.assertRaises(ValueError):
                    fake.provision()
                self.assertFalse(fake.diagnostic()['success'])
                self.assertEqual(fake.diagnostic()['archive_count'], None if drift == 'no-release' else 2)
                self.assertIn('error', fake.diagnostic())

    def test_each_command_failure_retains_stage_output_exit_and_primary(self):
        for stage in ('config-before', 'installed-before', 'update', 'download', 'archive-identity', 'install', 'installed-after'):
            with self.subTest(stage=stage), scratch_home() as directory:
                fake = AptFixture(Path(directory), fail=stage)
                with self.assertRaisesRegex(RuntimeError, stage + ' primary failure'):
                    fake.provision()
                record = fake.diagnostic()
                self.assertFalse(record['success'])
                self.assertEqual(record['stage'], stage)
                command = record['commands'][-1]
                self.assertEqual(command['state'], 'failed')
                self.assertEqual(command['exit_code'], 1)
                self.assertIn('actual mocked command output', command['output'])

    def test_already_installed_base_is_explicit_not_fabricated_archive_success(self):
        with scratch_home() as directory:
            fake = AptFixture(Path(directory), empty='archives')
            fake.before = fake.after.copy()
            with self.assertRaisesRegex(ValueError, 'no new archives acquired'):
                fake.provision()
            record = fake.diagnostic()
            self.assertEqual(record['installed_before'], fake.before)
            self.assertEqual(record['archives'], {})
            self.assertEqual(record['archive_count'], 0)
            self.assertNotIn('install', dict(fake.calls))

    def test_malformed_nonregular_empty_or_overbound_proof_refuses(self):
        for kind in ('empty', 'symlink', 'size', 'count', 'unexpected'):
            with self.subTest(kind=kind), scratch_home() as directory:
                root = Path(directory)
                (root / 'one.deb').write_bytes(b'' if kind == 'empty' else b'fixture')
                if kind == 'symlink':
                    (root / 'two.deb').symlink_to(root / 'one.deb')
                if kind == 'unexpected':
                    (root / 'not-an-archive').write_bytes(b'x')
                with patch.object(apt, 'MAX_BYTES', 1 if kind == 'size' else apt.MAX_BYTES), \
                        patch.object(apt, 'MAX_FILES', 0 if kind == 'count' else apt.MAX_FILES), self.assertRaises(ValueError):
                    apt.file_records(root, archives=True)
        for text in ('', 'bad', 'pkg\tamd64\t1\tinstall ok installed\npkg\tamd64\t1\tinstall ok installed',
                     'bad name\tamd64\t1\tinstall ok installed'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                apt.installed_packages(text)
        with self.assertRaisesRegex(ValueError, 'removal'):
            apt.bind_installed({'gone:amd64': '1'}, {}, {})

    def test_actual_owned_command_failure_output_deadline_limit_and_resource_audit(self):
        # Only a tiny local Python child; no acquisition, root setup or Docker.
        with scratch_home() as directory:
            for code, timeout, limit, poll, error in [
                ('print("primary real output", flush=True); raise SystemExit(7)', 5, 1024, None, RuntimeError),
                ('import time; print("before deadline", flush=True); time.sleep(10)', .1, 1024, None, TimeoutError),
                ('print("x"*2000)', 5, 1024, None, ValueError),
                ('import time; time.sleep(10)', 5, 1024, lambda: (_ for _ in ()).throw(ValueError('resource bound')), ValueError),
            ]:
                audit = {}
                with self.subTest(error=error), self.assertRaises(error):
                    acquisition.bounded_run([sys.executable, '-c', code], Path(directory), timeout=timeout,
                                            limit=limit, audit=audit, poll=poll)
                self.assertIsInstance(audit['exit_code'], int)
                self.assertLessEqual(audit['output_bytes'], limit)
                if audit['exit_code'] == 7:
                    self.assertIn('primary real output', audit['output'])
            audit = {}
            acquisition.bounded_run([sys.executable, '-c', 'print("x"*40000)'], Path(directory), limit=50000, audit=audit)
            self.assertTrue(audit['output_truncated'])
            self.assertEqual(len(audit['output']), 32768)
            self.assertEqual(audit['output_sha256'], hashlib.sha256(('x'*40000 + '\n').encode()).hexdigest())

    def test_diagnostic_write_failure_is_secondary_to_command_failure(self):
        with scratch_home() as directory:
            root = Path(directory)
            proof = apt.AptProof(root, root, root)
            failure = RuntimeError('actual command failure')
            with patch.object(proof, 'save', side_effect=[None, OSError('export failed')]), \
                    patch.object(apt, 'bounded_run', side_effect=failure), \
                    self.assertRaisesRegex(RuntimeError, 'actual command failure') as caught:
                proof.command('update', ['unused'])
            self.assertIn('diagnostic save failed', ' '.join(caught.exception.__notes__))

    def test_failed_bootstrap_exports_diagnostics_without_success_inventory_and_compact_pack(self):
        with scratch_home() as directory:
            root = Path(directory)
            target = root / 'bootstrap'
            target.mkdir()
            fake = ExportDocker(root, missing=NAMES[:-1])
            original = fake.run
            payload = b'{"success":false,"stage":"archive-proof","index_count":2,"archive_count":0}'
            fake.run = lambda argv, **kwargs: archive('apt-diagnostics.json', payload) if argv[0] == 'cp' and argv[1].endswith('/apt-diagnostics.json') else original(argv, **kwargs)
            result = builder.export_bootstrap(fake, target, identity(), provenance=True)
            self.assertEqual(result, {'apt-diagnostics.json': hashlib.sha256(payload).hexdigest()})
            manifest = json.loads((target / 'export-members.json').read_text())
            self.assertFalse(manifest['setup_success'])
            self.assertEqual(manifest['members']['inventory.json']['status'], 'missing')
            packed = hosted_evidence.pack(root, root / 'proof.tar')
            self.assertFalse(packed['acceptance_inferred'])
            self.assertEqual(json.loads((target / 'apt-diagnostics.json').read_text())['archive_count'], 0)


if __name__ == '__main__':
    from offline_guard import deny_network
    deny_network()
    unittest.main()
