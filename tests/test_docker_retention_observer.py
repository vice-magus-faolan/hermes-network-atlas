# SPDX-License-Identifier: GPL-3.0-or-later
"""Deterministic tiny live-prune races; no Docker, admission or acquisition."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from contextlib import redirect_stdout
import io
from unittest.mock import patch

from helpers import scratch_home
import test_docker_retention as fixtures
import acquisition_support as acquisition
import hosted_retention as retention


class ObserverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from offline_guard import deny_network
        deny_network()

    def prune_race(self, core, callback):
        """Remove one actual packed loose duplicate AFTER its walk enumeration."""
        actual_run, actual_walk = retention.bounded_run, os.walk
        removed = []
        ready = core.parent / 'observer-ready'
        child = core.parent / 'prune-child.py'
        child.write_text('import os, time\nfrom pathlib import Path\n'
                         f'ready = Path({str(ready)!r})\n'
                         'deadline = time.monotonic() + 5\n'
                         'while not ready.exists():\n'
                         '    if time.monotonic() >= deadline: raise SystemExit(9)\n'
                         '    time.sleep(0.01)\n'
                         'os.execvp("git", ["git", "prune-packed"])\n')
        def walk(*args, **kwargs):
            for directory, dirs, files in actual_walk(*args, **kwargs):
                path = Path(directory)
                if not removed and path.parent == core / '.git/objects' and len(path.name) == 2 and files:
                    leaf = path / sorted(files)[0]
                    leaf.unlink()
                    removed.append(str(leaf.relative_to(core / '.git')))
                yield directory, dirs, files
            ready.write_text('sample finished')
        def run(argv, cwd, **kwargs):
            if argv == ['git', 'prune-packed']:
                # Runner's strict pre-spawn sample has completed. Advance beyond
                # the inherited one-second interval before the REAL child poll.
                time.sleep(1.01)
                with patch.object(retention.os, 'walk', side_effect=walk):
                    # A barrier, not timing, prevents Git from racing the test
                    # seam itself. The owned child then execs the REAL prune.
                    return actual_run([sys.executable, '-B', str(child)], cwd, **kwargs)
            return actual_run(argv, cwd, **kwargs)
        with patch.object(retention, 'bounded_run', side_effect=run):
            result = callback()
        self.assertEqual(len(removed), 1)
        return result, removed

    def test_real_runner_enumerate_stat_prune_race_preserves_objects(self):
        fixture = fixtures.RetentionTests()
        with scratch_home() as directory:
            seed, core, commit, tree, parent, unreachable = fixture.fixture(Path(directory))
            subprocess.check_output(['git', '-C', str(core), 'repack', '-a', '-n', '--no-write-bitmap-index'])
            argv = ['git', '-C', str(core), 'cat-file', '--batch-all-objects', '--batch-check=%(objectname) %(objecttype) %(objectsize)']
            before = retention.object_rows(subprocess.check_output(argv).decode())
            output = io.StringIO()
            with patch.object(acquisition, 'COMMAND_LOG', acquisition.CommandLog()), redirect_stdout(output):
                result, removed = self.prune_race(core, lambda: retention.runner(core)(['git', 'prune-packed']))
            self.assertEqual(result, '')
            self.assertEqual(before, retention.object_rows(subprocess.check_output(argv).decode()))
            terminal = json.loads(output.getvalue().splitlines()[-1])
            self.assertEqual((terminal['state'], terminal['exit_code']), ('complete', 0))
            print('Actual observer race GREEN: ' + json.dumps({'removed_duplicate': removed, 'objects': before, 'terminal': terminal}, sort_keys=True))

    def test_full_compaction_race_keeps_strict_final_source_objects_and_budget(self):
        fixture = fixtures.RetentionTests()
        with scratch_home() as directory:
            seed, core, commit, tree, parent, unreachable = fixture.fixture(Path(directory))
            report, removed = self.prune_race(core, lambda: fixture.compact(seed, core, commit, tree))
            self.assertEqual(report['stage'], 'complete')
            self.assertEqual(report['objects_before'], report['objects_after'])
            self.assertTrue(report['before']['complete'])
            self.assertTrue(report['after']['complete'])
            self.assertGreaterEqual(report['observation']['missing_loose_entries'], 1)
            self.assertGreaterEqual(report['observation']['incomplete_samples'], 1)
            self.assertEqual((core / '.git/shallow').read_text(), commit + '\n')
            self.assertEqual(subprocess.check_output(['git', '-C', str(core), 'cat-file', 'blob', unreachable]), b'unreachable fixture\n')
            verifier = Path(directory) / 'verifier'
            verifier.mkdir()
            with patch.object(retention, 'owned_layout'), patch.object(retention, 'BYTE_LIMIT', 200000):
                proof = retention.retained_inventory(seed, verifier, report)
            self.assertTrue(proof['seed']['complete'])
            self.assertLess(proof['seed']['bytes'], 200000)
            print('Full tiny compaction observer proof: ' + json.dumps(report, sort_keys=True))

    def git_root(self, root):
        git = root / '.git'
        (git / 'objects/ab').mkdir(parents=True)
        return git

    def missing_walk(self, root, relative, *, error=False):
        def walk(*args, **kwargs):
            path = root / relative
            if error:
                kwargs['onerror'](FileNotFoundError(2, 'removed', str(path)))
            else:
                yield str(path.parent), [], [path.name]
        return patch.object(retention.os, 'walk', side_effect=walk)

    def test_missing_tolerance_only_prune_loose_leaves_and_empty_fanouts(self):
        with scratch_home() as directory:
            root = self.git_root(Path(directory))
            for relative in ('objects/ab/' + 'c' * 38, 'objects/ab'):
                for error in (False, True):
                    with self.subTest(relative=relative, error=error), self.missing_walk(root, relative, error=error):
                        if relative == 'objects/ab': (root / relative).rmdir()
                        row = {}
                        retention.measure(root, row, pruning=True)
                        self.assertFalse(row['complete'])
                        self.assertEqual(row['missing_loose_entries'], 1)
                        self.assertEqual(row['entries'], 1)
                        with self.assertRaises(ValueError): retention.require_accounting(row)
                        (root / 'objects/ab').mkdir(exist_ok=True)
            for relative in ('missing-config', 'missing-shallow', 'objects/pack/file', 'objects/zz/' + 'a' * 38, '../outside'):
                with self.subTest(relative=relative), self.missing_walk(root, relative), self.assertRaises((FileNotFoundError, ValueError)):
                    retention.measure(root, {}, pruning=True)

    def test_quiescent_missing_permission_and_partial_final_proofs_refuse(self):
        with scratch_home() as directory:
            root = self.git_root(Path(directory))
            for error in (False, True):
                with self.missing_walk(root, 'objects/ab/' + 'c' * 38, error=error), self.assertRaises(FileNotFoundError):
                    retention.measure(root, {})
            actual = Path.lstat
            target = root / 'objects/ab'
            def denied(path, *args, **kwargs):
                if path == target: raise PermissionError('actual stat boundary')
                return actual(path, *args, **kwargs)
            with patch.object(Path, 'lstat', denied), self.assertRaises(PermissionError):
                retention.measure(root, {}, pruning=True)
            def unreadable(*args, **kwargs):
                kwargs['onerror'](PermissionError(13, 'directory denied', str(target)))
                yield from ()
            with patch.object(retention.os, 'walk', side_effect=unreadable), self.assertRaises(PermissionError):
                retention.measure(root, {}, pruning=True)
            row = {}
            retention.measure(root, row, pruning=True)
            self.assertFalse(row['complete'])  # even a stable LIVE sample is not final
            with self.assertRaises(ValueError): retention.require_accounting(row)
            retention.measure(root, row)
            retention.require_accounting(row)

    def test_links_special_missing_ancestors_and_escape_are_not_tolerated(self):
        with scratch_home() as directory:
            root = self.git_root(Path(directory))
            link = root / 'objects/ab' / ('c' * 38)
            link.symlink_to(Path(directory) / 'foreign')
            with self.assertRaisesRegex(ValueError, 'symlink'): retention.measure(root, {}, pruning=True)
            link.unlink()
            os.mkfifo(link)
            with self.assertRaisesRegex(ValueError, 'special'): retention.measure(root, {}, pruning=True)
            link.unlink()
            (root / 'objects/ab').rmdir()
            (root / 'objects/ab').symlink_to(Path(directory) / 'foreign')
            with self.missing_walk(root, 'objects/ab/' + 'c' * 38), self.assertRaisesRegex(ValueError, 'fanout'):
                retention.measure(root, {}, pruning=True)
            (root / 'objects/ab').unlink()
            (root / 'objects').rmdir()
            with self.missing_walk(root, 'objects/ab/' + 'c' * 38), self.assertRaises(FileNotFoundError):
                retention.measure(root, {}, pruning=True)
            with self.assertRaises(ValueError): retention.measure(Path(directory), {}, pruning=True)

    def test_missing_entries_still_consume_entry_time_and_transient_byte_bounds(self):
        with scratch_home() as directory:
            core = Path(directory)
            root = self.git_root(core)
            relative = 'objects/ab/' + 'c' * 38
            with self.missing_walk(root, relative), patch.object(retention.time, 'monotonic', side_effect=[0, 11]), self.assertRaisesRegex(ValueError, 'deadline'):
                retention.measure(root, {}, pruning=True)
            row = {'entries': 100000}
            with self.assertRaisesRegex(ValueError, 'entry'): retention.visit(row, time.monotonic() + 10)
            def large(root, row, **kwargs):
                row.update(bytes=2 * 1024 ** 3 + 1, complete=False)
            with patch.object(retention, 'measure', side_effect=large), patch.object(retention, 'bounded_run') as spawn, redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, 'transient'):
                retention.runner(core)(['git', 'prune-packed'])
            spawn.assert_not_called()

    def test_nonprune_command_and_postfailure_sampler_never_gain_tolerance(self):
        with scratch_home() as directory:
            core = Path(directory)
            root = self.git_root(core)
            actual = retention.bounded_run
            phases = []
            poll_saved = None
            def measure(root, row, *, pruning=False):
                phases.append(pruning)
                row.update(bytes=0, complete=not pruning)
            def child(argv, cwd, **kwargs):
                nonlocal poll_saved
                poll_saved = kwargs['poll']
                time.sleep(1.01)
                return actual([sys.executable, '-c', 'raise SystemExit(7)'], cwd, **kwargs)
            with patch.object(retention, 'measure', side_effect=measure), patch.object(retention, 'bounded_run', side_effect=child), redirect_stdout(io.StringIO()):
                run = retention.runner(core)
                with self.assertRaises(RuntimeError): run(['git', 'prune-packed'])
                time.sleep(1.01)
                if poll_saved is None: self.fail('owned child did not retain actual poll')
                poll_saved()
                self.assertEqual(phases, [False, True, False])
                with self.assertRaises(RuntimeError): run(['git', 'fsck'])
                self.assertFalse(phases[-1])

    def test_final_stat_race_refuses_compaction_success_and_retains_failure(self):
        fixture = fixtures.RetentionTests()
        with scratch_home() as directory:
            seed, core, commit, tree, _, _ = fixture.fixture(Path(directory))
            actual_pack, actual_measure = retention.pack_objects, retention.measure
            packed = False
            def pack(*args):
                nonlocal packed
                actual_pack(*args)
                packed = True
            def measure(root, row, **kwargs):
                if packed:
                    with self.missing_walk(root, 'objects/ab/' + 'c' * 38):
                        return actual_measure(root, row, **kwargs)
                return actual_measure(root, row, **kwargs)
            with patch.object(retention, 'pack_objects', side_effect=pack), patch.object(retention, 'measure', side_effect=measure), self.assertRaises(FileNotFoundError):
                fixture.compact(seed, core, commit, tree)
            proof = json.loads((seed / 'retained-inventory.json').read_text())
            self.assertEqual(proof['stage'], 'failed')
            self.assertEqual(proof['compaction']['error'], 'FileNotFoundError')
            self.assertFalse(proof['compaction']['after']['complete'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
