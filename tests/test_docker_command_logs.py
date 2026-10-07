# SPDX-License-Identifier: GPL-3.0-or-later
"""Real bounded failed children and aggregate export; never Docker or acquisition."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'docker'))
import hosted_setup as setup
from docker_acceptance import command
from offline_guard import deny_network
from test_docker_bootstrap_repair import ExportDocker, NAMES
from test_docker_builder import identity
import docker_builder as builder

EXPORT_LIMIT = 4 * 1024 ** 2


def capture_failure(root, source):
    """Use the exporter's real aggregate reader, including an uncaught traceback."""
    driver = root / 'driver.py'
    driver.write_text(
        f'import sys\nfrom pathlib import Path\nsys.path[:0] = { [str(ROOT / "scripts"), str(ROOT / "docker")]!r}\n'
        'from offline_guard import deny_network\ndeny_network()\n'
        f'import hosted_setup as setup\nsetup.CORE = Path({str(root)!r})\n' + source)
    argv = [sys.executable, '-B'] + (['-O'] if sys.flags.optimize else []) + [str(driver)]
    try:
        command(argv, timeout=30, limit=EXPORT_LIMIT)
    except subprocess.CalledProcessError as exc:
        if exc.returncode != 1:
            raise ValueError('unexpected probe exit') from exc
        return exc.output
    raise ValueError('probe must fail honestly')


def rows(payload):
    return [json.loads(line) for line in payload.decode().splitlines() if line.startswith('{')]


class CommandLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deny_network()

    def test_near_limit_failed_child_traceback_and_actual_export_preserve_primary(self):
        with scratch_home() as directory:
            root = Path(directory)
            child = root / 'failed.py'
            size = EXPORT_LIMIT - 2048
            child.write_text(f'import os\nos.write(1, b"x" * {size})\nraise SystemExit(7)\n')
            payload = capture_failure(root, f'setup.run([sys.executable, {str(child)!r}])\n')
            audit = rows(payload)
            self.assertEqual([row['state'] for row in audit], ['started', 'failed'])
            self.assertEqual(audit[1]['exit_code'], 7)
            self.assertEqual(audit[1]['output_bytes'], size)
            self.assertEqual(audit[1]['output_sha256'], hashlib.sha256(b'x' * size).hexdigest())
            self.assertTrue(audit[1]['output_truncated'])
            self.assertEqual(audit[1]['output'], 'x' * 32768)
            self.assertIn(b'public setup command failed: exit=7', payload)
            self.assertLess(len(payload), EXPORT_LIMIT)
            # Real production exporter, synthetic daemon seam: no Docker executed.
            fake = ExportDocker(root, missing=NAMES)
            original = fake.run
            def read(argv, **kwargs):
                if argv[0] == 'logs':
                    self.assertEqual(kwargs['limit'], EXPORT_LIMIT)
                    return payload
                return original(argv, **kwargs)
            target = root / 'export'
            target.mkdir()
            with patch.object(fake, 'run', side_effect=read):
                builder.export_bootstrap(fake, target, identity(), provenance=True)
            self.assertEqual((target / 'bootstrap.log').read_bytes(), payload)
            self.assertEqual(json.loads((target / 'stopped.json').read_text())['State']['ExitCode'], 1)
            self.assertFalse(json.loads((target / 'export-members.json').read_text())['setup_success'])
            print('Command log near-limit probe: ' + json.dumps({
                'child_bytes': size, 'aggregate_export_bytes': len(payload),
                'export_limit': EXPORT_LIMIT, 'actual_export_preserved': True}))

    def test_repeated_hostile_rows_reserve_terminal_before_spawn_under_aggregate_cap(self):
        with scratch_home() as directory:
            root = Path(directory)
            pattern = b'\xff\x00"\\\n' + '\u2603\U0001f600'.encode()
            output = pattern * 4000
            child = root / 'hostile.py'
            ledger = root / 'spawned'
            child.write_text(f'import os\nfrom pathlib import Path\n'
                             f'with Path({str(ledger)!r}).open("ab") as f: f.write(b"x")\n'
                             f'os.write(1, bytes.fromhex({output.hex()!r}))\nraise SystemExit(7)\n')
            source = f'argv = [sys.executable, {str(child)!r}]\ncompleted = 0\n' \
                'while True:\n' \
                '    try:\n        setup.run(argv)\n' \
                '    except RuntimeError as exc:\n' \
                '        if "public setup command failed: exit=7" not in str(exc): raise\n' \
                '        completed += 1\n' \
                '    except ValueError as exc:\n' \
                '        if str(exc) != "public command diagnostic budget exhausted": raise\n' \
                f'        if Path({str(ledger)!r}).stat().st_size != completed: raise RuntimeError("spawn after refusal")\n' \
                '        break\n' \
                'raise RuntimeError("aggregate probe primary") from None\n'
            payload = capture_failure(root, source)
            audit = rows(payload)
            terminal = [row for row in audit if row['state'] == 'failed']
            self.assertGreater(len(terminal), 3)
            self.assertEqual(len(audit), 2 * len(terminal))
            self.assertEqual(ledger.stat().st_size, len(terminal))
            for row in terminal:
                self.assertEqual(row['exit_code'], 7)
                self.assertEqual(row['output_bytes'], len(output))
                self.assertEqual(row['output_sha256'], hashlib.sha256(output).hexdigest())
                self.assertTrue(row['output_truncated'])
                self.assertIn('\ufffd', row['output'])
                self.assertIn('\u2603', row['output'])
            serialized = sum(len(line) + 1 for line in payload.splitlines() if line.startswith(b'{'))
            self.assertLessEqual(serialized, setup.COMMAND_LOG_LIMIT)
            self.assertIn(b'RuntimeError: aggregate probe primary', payload)
            self.assertLess(len(payload), EXPORT_LIMIT)
            print('Command log cumulative probe: ' + json.dumps({
                'failed_children': len(terminal), 'encoded_diagnostic_bytes': serialized,
                'command_log_limit': setup.COMMAND_LOG_LIMIT, 'aggregate_export_bytes': len(payload),
                'export_limit': EXPORT_LIMIT, 'no_spawn_after_budget_refusal': True}))

    def test_command_metadata_and_count_refuse_before_child_or_log_effects(self):
        with patch.object(setup, 'COMMAND_LOG', setup.CommandLog()), patch.object(setup, 'bounded_run') as run, \
                patch('builtins.print') as emit:
            for argv in ([], ['x' * 9000], ['\u2603' * 9000], ['x'] * 65):
                with self.subTest(argv_length=len(argv)), self.assertRaises(ValueError):
                    setup.run(argv)
            run.assert_not_called()
            emit.assert_not_called()
        with patch.object(setup, 'COMMAND_LOG', setup.CommandLog()), patch.object(setup, 'bounded_run', return_value=''), \
                patch('builtins.print'):
            for _ in range(setup.COMMAND_COUNT_LIMIT):
                setup.run(['synthetic-not-executed'])
            with patch.object(setup, 'bounded_run') as refused, self.assertRaisesRegex(ValueError, 'diagnostic budget exhausted'):
                setup.run(['synthetic-not-executed'])
            refused.assert_not_called()

    def test_real_nonzero_command_survives_terminal_emission_error_without_output_chain(self):
        with scratch_home() as directory:
            root = Path(directory)
            child = root / 'failure.py'
            child.write_text('print("raw child text")\nraise SystemExit(9)\n')
            with patch.object(setup, 'CORE', root), patch.object(setup, 'COMMAND_LOG', setup.CommandLog()), \
                    patch('builtins.print', side_effect=[None, OSError('terminal write failed')]), \
                    self.assertRaisesRegex(RuntimeError, 'public setup command failed: exit=9') as raised:
                setup.run([sys.executable, str(child)])
            self.assertNotIn('raw child text', str(raised.exception))
            self.assertIsNone(raised.exception.__cause__)
            self.assertIn('command diagnostic failed: OSError', raised.exception.__notes__)


if __name__ == '__main__':
    unittest.main()
