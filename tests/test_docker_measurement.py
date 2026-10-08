# SPDX-License-Identifier: GPL-3.0-or-later
"""Measurement-only routing and tiny genuine Git; never full-core/native fixtures."""
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'docker'))
from offline_guard import deny_network
import measurement_route as routing
import packing_measurement as measurement
import acquisition_support as acquisition
import hosted_retention as retention
from core_identity import source_manifest, manifest_digest
from docker_evidence import BoundedDirectory
import test_docker_retention


class MeasurementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deny_network()

    def git(self, root, *args):
        return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.STDOUT, timeout=20).decode().strip()

    def test_feature_phase_gates_measurement_separately_from_native_acceptance(self):
        from ruamel.yaml import YAML
        value = YAML(typ='safe').load((ROOT / '.github/workflows/verify.yml').read_text())
        jobs = value['jobs']
        self.assertIn('feature-phase', jobs, 'predecessor feature push unconditionally reruns known failed acceptance')
        self.assertEqual(jobs['hosted-docker']['needs'], 'feature-phase')
        self.assertIn("needs.feature-phase.outputs.phase == 'acceptance'", jobs['hosted-docker']['if'])
        self.assertEqual(jobs['packing-measurement']['needs'], 'feature-phase')
        self.assertEqual(jobs['packing-measurement']['if'], "needs.feature-phase.outputs.phase == 'measurement'")
        self.assertEqual(jobs['offline-verification']['if'], "github.event_name != 'push' || github.ref != 'refs/heads/feat/6-host-discovery'")
        self.assertEqual(value['concurrency'], {'group': 'network-atlas-issue-6-ci', 'cancel-in-progress': False})
        self.assertEqual(value['permissions'], {'contents': 'read'})
        for name in ('feature-phase', 'packing-measurement'):
            job = jobs[name]
            self.assertEqual(job['runs-on'], 'ubuntu-24.04')
            self.assertLessEqual(job['timeout-minutes'], 30)
            for step in job['steps']:
                if 'uses' in step:
                    self.assertRegex(step['uses'], r'@[0-9a-f]{40}$')
                    if step['uses'].startswith('actions/checkout@'):
                        self.assertIs(step['with']['persist-credentials'], False)
        text = json.dumps(jobs['packing-measurement'])
        for forbidden in ('hosted_docker.py', 'prepare_acceptance.py', 'secrets.', 'docker ', 'pip ', 'sudo '):
            self.assertNotIn(forbidden, text)
        self.assertNotIn('workflow_dispatch', value['on'])
        gate_checkouts = [step for step in jobs['feature-phase']['steps'] if 'uses' in step]
        self.assertEqual(len(gate_checkouts), 1)
        self.assertNotIn('repository', gate_checkouts[0]['with'])
        self.assertNotIn('path', gate_checkouts[0]['with'])
        upload = jobs['packing-measurement']['steps'][-1]
        self.assertEqual(upload['if'], 'always()')
        self.assertEqual(upload['with']['if-no-files-found'], 'error')
        self.assertIn('packing-measurement', upload['with']['name'])

    def repository(self, root):
        repo = root / 'repo'
        repo.mkdir()
        self.git(repo, 'init', '-q')
        (repo / 'product.py').write_text('production unchanged\n')
        self.commit(repo)
        base = self.git(repo, 'rev-parse', 'HEAD')
        paths = {'docs/measure.md', 'scripts/measure.py'}
        for path in paths:
            target = repo / path
            target.parent.mkdir(exist_ok=True)
            target.write_text('source-only measurement\n')
        marker = {'schema': 1, 'phase': 'exact-core-packing-measurement-only', 'base': base,
                  'files': {name: hashlib.sha256((repo / name).read_bytes()).hexdigest() for name in paths}}
        target = repo / routing.MARKER
        target.parent.mkdir(exist_ok=True)
        target.write_text(json.dumps(marker))
        self.commit(repo)
        return repo, base, paths, marker

    def commit(self, repo):
        self.git(repo, 'add', '-A')
        self.git(repo, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 '-c', 'commit.gpgsign=false', 'commit', '-qm', 'tiny measurement fixture')

    def test_real_git_exact_marker_routes_and_normal_main_pr_without_message_skip(self):
        with scratch_home() as directory:
            repo, base, files, _ = self.repository(Path(directory))
            sha = self.git(repo, 'rev-parse', 'HEAD')
            with patch.object(routing, 'BASE', base), patch.object(routing, 'FILES', files):
                self.assertEqual(routing.route(repo, 'push', routing.FEATURE, sha), 'measurement')
                self.assertEqual(routing.route(repo, 'push', 'refs/heads/main', sha), 'acceptance')
                self.assertEqual(routing.route(repo, 'pull_request', 'refs/pull/3/merge', sha), 'acceptance')
                (repo / routing.MARKER).unlink()
                with self.assertRaises(ValueError): routing.route(repo, 'push', routing.FEATURE, sha)
                self.commit(repo)
                sha = self.git(repo, 'rev-parse', 'HEAD')
                self.assertEqual(routing.route(repo, 'push', routing.FEATURE, sha), 'acceptance')
            for event, ref, value in [('workflow_dispatch', routing.FEATURE, sha), ('push', 'refs/tags/phase', sha),
                                      ('pull_request', 'refs/pull/3/head', sha), ('push', routing.FEATURE, '0' * 40)]:
                with self.assertRaises(ValueError): routing.route(repo, event, ref, value)

    def test_malformed_hash_symlink_dirty_parent_and_mixed_product_refuse(self):
        modes = ('malformed', 'duplicate', 'boolean', 'hash', 'symlink', 'dirty', 'parent', 'product')
        for mode in modes:
            with self.subTest(mode=mode), scratch_home() as directory:
                repo, base, files, marker = self.repository(Path(directory))
                target = repo / routing.MARKER
                if mode == 'malformed': target.write_text('{')
                if mode == 'duplicate': target.write_text(json.dumps(marker)[:-1] + ',"schema":1}')
                if mode == 'boolean':
                    marker['schema'] = True
                    target.write_text(json.dumps(marker))
                if mode == 'hash':
                    marker['files'][next(iter(files))] = '0' * 64
                    target.write_text(json.dumps(marker))
                if mode == 'symlink':
                    target.unlink()
                    target.symlink_to('../product.py')
                if mode == 'dirty': (repo / next(iter(files))).write_text('uncommitted drift')
                if mode == 'parent':
                    (repo / next(iter(files))).write_text('second phase')
                    self.commit(repo)
                if mode == 'product':
                    (repo / 'product.py').write_text('mixed production change')
                    self.git(repo, 'add', '-A')
                    self.git(repo, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                             '-c', 'commit.gpgsign=false', 'commit', '--amend', '--no-edit', '-q')
                with patch.object(routing, 'BASE', base), patch.object(routing, 'FILES', files), self.assertRaises((ValueError, OSError)):
                    routing.route(repo, 'push', routing.FEATURE, self.git(repo, 'rev-parse', 'HEAD'))

    def test_hosted_local_guard_refuses_before_any_full_source_or_work_effect(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(measurement, 'authenticate_source') as auth, self.assertRaises(ValueError):
            measurement.main()
        auth.assert_not_called()
        for job in ('hosted-docker', 'offline-verification', 'packing-measurement'):
            env = {'GITHUB_JOB': job, 'GITHUB_ACTIONS': 'true'}
            with self.assertRaises(ValueError): measurement.require_host(ROOT, env)

    def test_real_tiny_two_fixed_variants_preserve_all_source_objects_shallow_and_dispose(self):
        with scratch_home() as directory:
            root = Path(directory)
            _seed, source, commit, tree, parent, unreachable = test_docker_retention.RetentionTests().fixture(root)
            expected = source_manifest(source)
            summary = root / 'summary'
            summary.mkdir()
            evidence = BoundedDirectory(summary)
            env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
            with patch.dict(os.environ, env, clear=True):
                results = [measurement.run_variant(source, root, name, expected, evidence, commit, tree) for name in measurement.RECIPES]
            for row in results:
                self.assertEqual(row['stage'], 'complete')
                self.assertTrue(row['cleanup_verified'])
                self.assertEqual(row['objects_before'], row['objects_after'])
                self.assertEqual(row['source_digest'], manifest_digest(expected))
                self.assertFalse(row['native_acceptance'])
                self.assertFalse((root / row['variant']).exists())
                audit = (summary / (row['variant'] + '-audit.log')).read_text()
                self.assertIn('"state": "complete"', audit)
                self.assertIn('prune-packed', audit)
            self.assertEqual(results[0]['objects_before'], results[1]['objects_before'])
            self.assertNotEqual(measurement.CURRENT, measurement.TUNED)
            with self.assertRaises(ValueError):
                measurement.packed(source, commit, tree, ('git', 'gc'), {}, evidence, 'unknown')
            # The original source's real unreachable object is untouched. Native
            # archive reconstruction intentionally recreates exact source-only
            # objects, so add an unreachable object at the pack boundary separately.
            self.assertEqual(self.git(source, 'cat-file', 'blob', unreachable), 'unreachable fixture')
            self.assertNotEqual(subprocess.run(['git', '-C', str(source), 'cat-file', '-e', parent], capture_output=True).returncode, 0)

    def test_pack_boundary_keeps_unreachable_objects_and_detects_source_drift(self):
        with scratch_home() as directory:
            root = Path(directory)
            _seed, core, commit, tree, _, unreachable = test_docker_retention.RetentionTests().fixture(root)
            expected = source_manifest(core)
            summary = root / 'summary'
            summary.mkdir()
            env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
            with patch.dict(os.environ, env, clear=True), patch.object(acquisition, 'COMMAND_LOG', acquisition.CommandLog()), redirect_stdout(io.StringIO()):
                report = {'stage': 'started'}
                measurement.variant(core, commit, tree, 'tuned', expected, BoundedDirectory(summary), report)
            self.assertEqual(self.git(core, 'cat-file', 'blob', unreachable), 'unreachable fixture')
            self.assertEqual(report['objects_before'], report['objects_after'])
            with self.assertRaises(ValueError):
                measurement.variant(core, commit, tree, 'current', {}, BoundedDirectory(summary), {})

    def test_failure_stops_variants_retains_primary_audit_and_real_disposal(self):
        with scratch_home() as directory:
            root = Path(directory)
            summary = root / 'summary'
            summary.mkdir()
            evidence = BoundedDirectory(summary)
            with patch.object(measurement, 'prepare', side_effect=RuntimeError('primary native refusal')), self.assertRaisesRegex(RuntimeError, 'primary native refusal'):
                measurement.run_variant(root, root, 'current', {}, evidence)
            report = json.loads((summary / 'current.json').read_text())
            self.assertEqual(report['stage'], 'failed')
            self.assertTrue(report['cleanup_verified'])
            self.assertFalse((root / 'current').exists())
            self.assertFalse((root / 'tuned').exists())
            with patch.object(measurement, 'prepare', side_effect=RuntimeError('primary')), patch.object(measurement, 'dispose', side_effect=OSError('secondary')), self.assertRaisesRegex(RuntimeError, 'primary'):
                measurement.run_variant(root, root, 'tuned', {}, evidence)
            self.assertIn('cleanup_error', json.loads((summary / 'tuned.json').read_text()))

    def test_projection_requires_completed_identical_full_measurements_and_explicit_reserve(self):
        anchor = measurement.anchor()
        obj = {'count': 20, 'sha256': 'a' * 64}
        current = {'stage': 'complete', 'objects_before': obj, 'objects_after': obj, 'source_digest': 'b' * 64,
                   'after': {'bytes': 84408010}}
        tuned = copy.deepcopy(current)
        for size, interpretation in [(84408010, 'insufficient'), (40 * 1024 ** 2, 'sufficient-for-projected-prerequisite')]:
            tuned['after']['bytes'] = size
            proof = measurement.projection(current, tuned, anchor)
            self.assertEqual(proof['interpretation'], interpretation)
            self.assertEqual(proof['headroom_reserve_bytes'], 8 * 1024 ** 2)
            for key in ('whole_seed_fit_proven', 'native_acceptance', 'full_canonical', 'final_approval'):
                self.assertIs(proof[key], False)
        tuned['stage'] = 'failed'
        with self.assertRaises(ValueError): measurement.projection(current, tuned, anchor)
        tuned['stage'] = 'complete'
        tuned['source_digest'] = 'c' * 64
        with self.assertRaises(ValueError): measurement.projection(current, tuned, anchor)

    def test_resource_output_evidence_bounds_and_cleanup_scope_refuse(self):
        with scratch_home() as directory:
            root = Path(directory)
            summary = root / 'summary'
            summary.mkdir()
            evidence = BoundedDirectory(summary)
            sink = measurement.AuditSink(evidence, 'audit.log')
            try:
                sink.write('actual terminal\n')
                with self.assertRaises(ValueError): sink.write('x' * (acquisition.COMMAND_LOG_LIMIT + 1))
            finally:
                sink.close()
            self.assertEqual((summary / 'audit.log').read_text(), 'actual terminal\n')
            foreign = root / 'foreign'
            foreign.mkdir()
            with self.assertRaises(ValueError): measurement.dispose(foreign, root)
            self.assertTrue(foreign.exists())
        self.assertEqual((retention.BYTE_LIMIT, retention.FILE_LIMIT), (1073741824, 100000))
        self.assertEqual(measurement.CURRENT, ('git', '-c', 'pack.threads=1', '-c', 'pack.windowMemory=16m', 'repack', '-a', '-n', '--no-write-bitmap-index'))


    def test_actual_measurement_child_bounds_terminal_failure_and_source_guard(self):
        actual = acquisition.bounded_run
        observed = []
        def bounded(argv, cwd, **kwargs):
            observed.append((kwargs['timeout'], kwargs['limit']))
            kwargs['timeout'] = min(kwargs['timeout'], 0.5)
            return actual(argv, cwd, **kwargs)
        with scratch_home() as directory:
            root = Path(directory)
            audit = io.StringIO()
            with patch.object(acquisition, 'bounded_run', side_effect=bounded), redirect_stdout(audit):
                with self.assertRaises(ValueError):
                    measurement.version_run([sys.executable, '-c', 'import os; os.write(1,b"x"*(4*1024**2+1))'], root)
                with self.assertRaises(TimeoutError):
                    measurement.version_run([sys.executable, '-c', 'import time; time.sleep(10)'], root)
            rows = [json.loads(line) for line in audit.getvalue().splitlines()]
            terminals = [row for row in rows if row['state'] == 'failed']
            self.assertEqual(len(terminals), 2)
            self.assertTrue(all('exit_code' in row and 'output_sha256' in row for row in terminals))
            self.assertEqual(observed, [(60, 4 * 1024 ** 2)] * 2)
            source = root / 'foreign'
            source.mkdir()
            self.git(source, 'init', '-q')
            with self.assertRaises((RuntimeError, ValueError)): measurement.authenticate_source(source)
            with patch.object(measurement, 'ANCHOR_HASH', '0' * 64), self.assertRaises(ValueError): measurement.anchor()


if __name__ == '__main__':
    deny_network()
    unittest.main()
