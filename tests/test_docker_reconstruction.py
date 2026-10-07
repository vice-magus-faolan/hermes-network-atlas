# SPDX-License-Identifier: GPL-3.0-or-later
"""Real child diagnostics at the public Git reconstruction boundary; no acquisition."""
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from helpers import scratch_home
from test_docker_command_logs import EXPORT_LIMIT, capture_failure, rows, setup
from test_docker_bootstrap_repair import ExportDocker, NAMES
from test_docker_builder import identity
from offline_guard import deny_network
import acquisition_support as acquisition
import docker_builder as builder
import base_setup


def reconstruction_probe(root, stage, output):
    """Substitute real small children for Git, retaining the production fixed argv."""
    child = root / 'git-child.py'
    expression = f'b"x" * {len(output)}' if stage == 'add' else f'bytes.fromhex({output.hex()!r})'
    child.write_text(
        'import os, sys\nfrom pathlib import Path\n'
        'stage = sys.argv[1]\n'
        f'if stage == {stage!r}:\n    os.write(1, {expression})\n    raise SystemExit(17)\n'
        'if stage == "init": Path(".git").mkdir()\n'
        'if stage == "write-tree": print("t" * 40)\n'
        'if stage == "hash-object": print("c" * 40)\n')
    return (
        'import acquisition_support as acquisition\nfrom unittest.mock import patch\n'
        'spawn = acquisition.subprocess.Popen\n'
        f'def real_child(argv, **kwargs): return spawn([sys.executable, {str(child)!r}, argv[1]], **kwargs)\n'
        'with patch.object(acquisition.subprocess, "Popen", side_effect=real_child):\n'
        f'    acquisition.reconstruct_public_core(setup.CORE, Path({str(root / "public.commit")!r}), "c" * 40, "t" * 40)\n')


def export_payload(root, payload):
    """Read back actual production export through the synthetic daemon seam."""
    fake = ExportDocker(root, missing=NAMES)
    original = fake.run
    def read(argv, **kwargs):
        if argv[0] == 'logs':
            if kwargs['limit'] != EXPORT_LIMIT:
                raise ValueError('export limit drift')
            return payload
        return original(argv, **kwargs)
    target = root / 'export'
    target.mkdir()
    with patch.object(fake, 'run', side_effect=read):
        builder.export_bootstrap(fake, target, identity(), provenance=True)
    return target


class ReconstructionLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deny_network()

    def setUp(self):
        # The production boundary refuses ambient Git control variables. Fixtures
        # remove those variables rather than weakening that guard.
        environment = patch.dict(os.environ, {key: value for key, value in os.environ.items()
                                              if not key.startswith('GIT_')}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def test_each_failed_git_stage_retains_real_child_evidence_in_export(self):
        stages = ['init', 'add', 'write-tree', 'hash-object', 'update-ref', 'status']
        for index, stage in enumerate(stages):
            with self.subTest(stage=stage), scratch_home() as directory:
                root = Path(directory)
                # A tiny script emits near-cap output; do not allocate a huge fixture script.
                output = b'x' * (EXPORT_LIMIT - 2048) if stage == 'add' else b'\xff\x00"\\\n' * 8000
                source = reconstruction_probe(root, stage, output)
                payload = capture_failure(root, source)
                audit = rows(payload)
                self.assertEqual(len(audit), 2 * (index + 1))
                terminal = audit[-1]
                self.assertEqual(terminal['public_command'][0:2], ['git', stage])
                self.assertEqual(terminal['state'], 'failed')
                self.assertEqual(terminal['error'], 'RuntimeError')
                self.assertEqual(terminal['exit_code'], 17)
                self.assertEqual(terminal['output_bytes'], len(output))
                self.assertEqual(terminal['output_sha256'], hashlib.sha256(output).hexdigest())
                self.assertEqual(terminal['output'], (output[:16384] + output[-16384:]).decode(errors='replace'))
                self.assertTrue(terminal['output_truncated'])
                self.assertIn(b'public setup command failed: exit=17', payload)
                self.assertLess(len(payload), EXPORT_LIMIT)
                target = export_payload(root, payload)
                self.assertEqual((target / 'bootstrap.log').read_bytes(), payload)
                self.assertFalse(json.loads((target / 'export-members.json').read_text())['setup_success'])
                print('Reconstruction failure probe: ' + json.dumps({
                    'stage': stage, 'child_bytes': len(output), 'aggregate_export_bytes': len(payload),
                    'export_limit': EXPORT_LIMIT, 'actual_export_preserved': True}))

    def test_success_outputs_and_hosted_phases_share_existing_budget(self):
        self.assertIs(setup.COMMAND_LOG, acquisition.COMMAND_LOG)
        with scratch_home() as directory:
            root = Path(directory)
            (root / 'public.txt').write_text('tiny public fixture\n')
            for argv in (['git', 'init', '--quiet'], ['git', 'add', '--all']):
                subprocess.run(argv, cwd=root, check=True, capture_output=True)
            tree = subprocess.check_output(['git', 'write-tree'], cwd=root).decode().strip()
            commit = root / '.git/public.commit'
            commit.write_text(f'tree {tree}\nauthor Fixture <fixture@example.invalid> 0 +0000\n'
                              'committer Fixture <fixture@example.invalid> 0 +0000\n\nfixture\n')
            sha = subprocess.check_output(['git', 'hash-object', '-t', 'commit', str(commit)], cwd=root).decode().strip()
            destination = root / 'reconstructed'
            destination.mkdir()
            (destination / 'public.txt').write_bytes((root / 'public.txt').read_bytes())
            log = setup.CommandLog()
            captured = io.StringIO()
            with patch.object(acquisition, 'COMMAND_LOG', log), patch.object(setup, 'COMMAND_LOG', log), \
                    patch.object(setup, 'CORE', destination), patch.object(base_setup, 'CORE', destination), \
                    redirect_stdout(captured):
                acquisition.reconstruct_public_core(destination, commit, sha, tree)
                # Six Git stages plus five ordinary parent provisioning commands.
                for _ in range(5):
                    self.assertEqual(setup.run([sys.executable, '-c', 'pass']), '')
                self.assertEqual(base_setup.run([sys.executable, '-c', 'pass']), '')
            audit = rows(captured.getvalue().encode())
            self.assertEqual(log.commands, 12)
            self.assertEqual(len(audit), 24)
            self.assertEqual([row['state'] for row in audit], ['started', 'complete'] * 12)
            self.assertEqual(audit[5]['output'].strip(), tree)
            self.assertEqual(audit[7]['output'].strip(), sha)
            self.assertEqual(audit[11]['output'], '')
            self.assertEqual((destination / '.git/shallow').read_text(), sha + '\n')
            self.assertLess(log.bytes + setup.TERMINAL_ROW_LIMIT, setup.COMMAND_LOG_LIMIT)

    def test_budget_refuses_before_git_or_log_effects(self):
        for exhausted in ('commands', 'bytes'):
            with self.subTest(exhausted=exhausted), scratch_home() as directory:
                root = Path(directory)
                log = setup.CommandLog()
                if exhausted == 'commands':
                    log.commands = setup.COMMAND_COUNT_LIMIT
                else:
                    log.bytes = setup.COMMAND_LOG_LIMIT - setup.TERMINAL_ROW_LIMIT
                with patch.object(acquisition, 'COMMAND_LOG', log), \
                        patch.object(acquisition.subprocess, 'Popen') as spawn, patch('builtins.print') as emit, \
                        self.assertRaisesRegex(ValueError, 'diagnostic budget exhausted'):
                    acquisition.reconstruct_public_core(root, root / 'unused.commit', 'c' * 40, 't' * 40)
                spawn.assert_not_called()
                emit.assert_not_called()
                self.assertFalse((root / '.git').exists())

    def test_terminal_write_failure_preserves_real_primary_exit(self):
        with scratch_home() as directory:
            root = Path(directory)
            child = root / 'failure.py'
            child.write_text('print("direct caller raw output")\nraise SystemExit(17)\n')
            spawn = subprocess.Popen
            def real_child(argv, **kwargs):
                return spawn([sys.executable, str(child)], **kwargs)
            with patch.object(acquisition.subprocess, 'Popen', side_effect=real_child), \
                    patch.object(acquisition, 'COMMAND_LOG', setup.CommandLog()), \
                    patch('builtins.print', side_effect=[None, OSError('terminal write failed')]), \
                    self.assertRaisesRegex(RuntimeError, 'public setup command failed: exit=17') as raised:
                acquisition.reconstruct_public_core(root, root / 'unused.commit', 'c' * 40, 't' * 40)
            self.assertNotIn('direct caller raw output', str(raised.exception))
            self.assertIsNone(raised.exception.__cause__)
            self.assertIn('command diagnostic failed: OSError', raised.exception.__notes__)

    def test_deadline_reaps_owned_child_and_preserves_terminal_audit(self):
        with scratch_home() as directory:
            root = Path(directory)
            child = root / 'deadline.py'
            child.write_text('import os, time\nprint(os.getpid(), flush=True)\ntime.sleep(30)\n')
            spawn = subprocess.Popen
            unrelated = spawn([sys.executable, str(child)], stdout=subprocess.DEVNULL)
            children = []
            def real_child(argv, **kwargs):
                process = spawn([sys.executable, str(child)], **kwargs)
                children.append(process)
                return process
            original = acquisition.bounded_run
            def short_deadline(argv, cwd, **kwargs):
                kwargs['timeout'] = 0.3
                return original(argv, cwd, **kwargs)
            captured = io.StringIO()
            try:
                with patch.object(acquisition.subprocess, 'Popen', side_effect=real_child), \
                        patch.object(acquisition, 'bounded_run', side_effect=short_deadline), \
                        patch.object(acquisition, 'COMMAND_LOG', setup.CommandLog()), redirect_stdout(captured), \
                        self.assertRaisesRegex(TimeoutError, 'public setup command deadline'):
                    acquisition.reconstruct_public_core(root, root / 'unused.commit', 'c' * 40, 't' * 40)
                audit = rows(captured.getvalue().encode())
                self.assertEqual(len(children), 1)
                self.assertEqual(audit[-1]['state'], 'failed')
                self.assertEqual(audit[-1]['error'], 'TimeoutError')
                self.assertEqual(audit[-1]['exit_code'], -9)
                self.assertEqual(audit[-1]['output'].strip(), str(children[0].pid))
                self.assertEqual(audit[-1]['output_sha256'], hashlib.sha256(audit[-1]['output'].encode()).hexdigest())
                self.assertIsNone(unrelated.poll())
                self.assertFalse(Path(f'/proc/{children[0].pid}').exists())
            finally:
                unrelated.terminate()
                unrelated.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
