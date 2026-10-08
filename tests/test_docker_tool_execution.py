# SPDX-License-Identifier: GPL-3.0-or-later
"""Tiny actual native-selection/file/child seams; no Docker, tool fetch or admission."""
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
from test_runtime import runtime_root
sys.path.insert(0, str(ROOT / 'scripts'))
import native_tool_execution as probe
import docker_inside as inside
from offline_guard import deny_network


class ToolExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deny_network()
        cls.core = runtime_root()
        from acceptance_support import HERMES_COMMIT, git_head
        if git_head(cls.core) != HERMES_COMMIT:
            raise ValueError('actual pinned native source required')
        sys.path.insert(0, str(cls.core))
        import pm.install
        import pm.packages
        cls.install = pm.install

    def fixture(self, directory):
        root = Path(directory)
        source, tools, export = root / 'source', root / 'tools', root / 'export'
        (source / 'pm').mkdir(parents=True)
        tools.mkdir()
        export.mkdir()
        shutil.copyfile(self.core / 'pm/lock.json', source / 'pm/lock.json')
        lock = json.loads((source / 'pm/lock.json').read_text())['packages']
        facts = {}
        for name, rel in (('uv', 'uv'), ('python', 'bin/python3')):
            version = lock[name]['version']
            entry = f'{name}-{version}-linux-x64'
            binary = tools / entry / rel
            binary.parent.mkdir(parents=True)
            # Existing public ELF only: a tiny real child at the actual PM path,
            # not a downloaded native tool or fabricated native-version result.
            shutil.copyfile('/usr/bin/true', binary)
            binary.chmod(0o755)
            facts[name] = {'entry': entry, 'version': version, 'target': 'linux-x64',
                           'artifacts': [lock[name]['artifacts']['linux-x64']['sha256']], 'env': {}}
        (tools / 'facts.json').write_text(json.dumps({'schema': 1, 'packages': facts}))
        return source, tools, export, facts

    def test_actual_pinned_selection_uses_binary_definition_without_healing_or_acquisition(self):
        from pm.store import Store
        with scratch_home() as directory:
            source, tools, _export, facts = self.fixture(directory)
            before = (tools / 'facts.json').read_bytes()
            with patch.dict(os.environ, {'HERMES_RUNTIME_DIR': str(tools)}), \
                    patch.object(self.install, '_heal_exec_bit', side_effect=AssertionError('healing forbidden')), \
                    patch.object(Store, 'fetch_many', side_effect=AssertionError('acquisition forbidden')):
                for name, rel in (('uv', 'uv'), ('python', 'bin/python3')):
                    binary, row = probe.selection(source, tools, name)
                    self.assertEqual(binary, tools / facts[name]['entry'] / rel)
                    self.assertEqual(row['archive_sha256'], facts[name]['artifacts'])
                    self.assertEqual(row['version'], facts[name]['version'])
            self.assertEqual((tools / 'facts.json').read_bytes(), before)

    def test_selection_version_target_artifact_entry_and_store_drift_refuse(self):
        with scratch_home() as directory:
            source, tools, _export, facts = self.fixture(directory)
            for field, value in [('entry', '../elsewhere'), ('version', '0'), ('target', 'linux-arm64'),
                                 ('artifacts', ['0' * 64])]:
                bad = json.loads(json.dumps(facts))
                bad['uv'][field] = value
                (tools / 'facts.json').write_text(json.dumps({'schema': 1, 'packages': bad}))
                with patch.dict(os.environ, {'HERMES_RUNTIME_DIR': str(tools)}), self.assertRaises(ValueError):
                    probe.selection(source, tools, 'uv')
            (tools / 'facts.json').write_text('{not json')
            with patch.dict(os.environ, {'HERMES_RUNTIME_DIR': str(tools)}), self.assertRaises(ValueError):
                probe.selection(source, tools, 'uv')
            self.assertFalse((tools / 'facts.corrupt').exists())
            with patch.dict(os.environ, {'HERMES_RUNTIME_DIR': str(source)}), self.assertRaises(ValueError):
                probe.selection(source, tools, 'uv')
            with self.assertRaises(ValueError):
                probe.selection(source, tools, 'arbitrary')

    def test_real_contained_elf_and_symlink_metadata_hash_and_permission_errno(self):
        with scratch_home() as directory:
            source, tools, _export, facts = self.fixture(directory)
            binary = tools / facts['uv']['entry'] / 'uv'
            link = binary.parent / 'internal-link'
            link.symlink_to('uv')
            resolved, row = probe.executable_record(link, tools)
            self.assertEqual(resolved, binary)
            self.assertEqual(row['sha256'], hashlib.sha256(binary.read_bytes()).hexdigest())
            self.assertEqual(row['ancestors'][-1]['symlink'], 'uv')
            self.assertEqual(row['resolved_ancestors'][-1]['mode'], '0o755')
            self.assertEqual(row['resolved_ancestors'][-1]['uid'], os.getuid())
            self.assertTrue(row['loader']['path'].startswith('/lib'))
            env = {'PATH': '/usr/bin:/bin'}
            result = probe.version_probe(link, env)
            self.assertEqual(result['exit_code'], 0)
            self.assertIn('GNU coreutils', result['output_head'])
            binary.chmod(0o600)
            result = probe.version_probe(binary, env)
            self.assertEqual((result['error'], result['errno']), ('PermissionError', errno.EACCES))
            self.assertEqual(binary.stat().st_mode & 0o777, 0o600)
            self.assertNotIn('exit_code', result)

    def test_escape_loop_missing_special_and_oversized_paths_never_execute(self):
        with scratch_home() as directory:
            source, tools, export, facts = self.fixture(directory)
            binary = tools / facts['uv']['entry'] / 'uv'
            binary.unlink()
            for target in ('/usr/bin/true', 'uv', 'missing'):
                binary.symlink_to(target)
                with self.assertRaises((ValueError, OSError)):
                    probe.executable_record(binary, tools)
                binary.unlink()
            os.mkfifo(binary)
            with self.assertRaises(ValueError):
                probe.executable_record(binary, tools)
            binary.unlink()
            binary.write_bytes(b'\x7fELF' + b'x' * 32)
            with patch.object(probe, 'FILE_LIMIT', 4), self.assertRaises(ValueError):
                probe.executable_record(binary, tools)
            binary.write_text('not an ELF')
            with self.assertRaises(ValueError):
                probe.executable_record(binary, tools)
            with self.assertRaises(ValueError):
                probe.ancestors(Path('relative'))
            # Actual ELF header, then bounded malformed/escaping loader records.
            shutil.copyfile('/usr/bin/true', binary)
            with binary.open('rb') as stream:
                header = stream.read(64)
                self.assertIsNotNone(probe.elf_loader(stream.fileno(), header, binary.stat().st_size))
                with self.assertRaises(ValueError):
                    probe.elf_loader(stream.fileno(), header, 64)
            for data in (b'/arbitrary/loader\0', b'/lib/../outside\0', b'/lib/not-terminated', b'/lib/x\0suffix\0'):
                binary.write_bytes(data)
                with binary.open('rb') as stream, self.assertRaises(ValueError):
                    probe.loader_record(stream.fileno(), 0, len(data), len(data))
            binary.unlink()
            binary.symlink_to('/usr/bin/true')
            with patch.dict(os.environ, {'HERMES_RUNTIME_DIR': str(tools)}), \
                    patch.object(probe, 'version_probe', side_effect=AssertionError('escape executed')):
                # Python is missing too: neither selected path may execute.
                (tools / facts['python']['entry'] / 'bin/python3').unlink()
                result = probe.collect(source, tools, {}, export)
            self.assertIn('error', result['tools']['uv'])
            self.assertIn('error', result['tools']['python'])
            self.assertFalse(result['native_acceptance'])

    def test_effective_mount_projection_and_statvfs_not_hostconfig(self):
        payload = (b'1 0 0:1 / / ro - overlay host-secret unrelated-secret\n'
                   b'2 1 0:2 / /work rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=2g\n'
                   b'3 2 0:3 / /work/nested rw - tmpfs tmpfs rw\n'
                   b'4 1 0:4 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n')
        rows = probe.mount_rows(payload)
        with scratch_home() as directory:
            actual = probe.filesystem_record(Path(directory), probe.mount_rows(Path('/proc/self/mountinfo').read_bytes()))
            self.assertEqual(actual['statvfs_flags'], os.statvfs(directory).f_flag)
        with patch.object(os, 'statvfs', return_value=type('Flags', (), {'f_flag': os.ST_NOEXEC | os.ST_NOSUID})()):
            work = probe.filesystem_record(Path('/work/tool'), rows)
            nested = probe.filesystem_record(Path('/work/nested/tool'), rows)
        self.assertEqual(work['mount']['mountpoint'], '/work')
        self.assertTrue(work['noexec'])
        self.assertTrue(work['nosuid'])
        self.assertEqual(nested['mount']['mountpoint'], '/work/nested')
        self.assertNotIn('host-secret', json.dumps(rows))
        for payload in (b'broken', b'x' * (probe.MOUNT_LIMIT + 1)):
            with self.assertRaises(ValueError):
                probe.mount_rows(payload)

    def test_incremental_report_precedes_probe_and_export_refuses_bounds(self):
        with scratch_home() as directory:
            source, tools, export, _facts = self.fixture(directory)
            def observe(binary, env):
                retained = json.loads((export / 'tool-execution.json').read_text())
                name = 'uv' if binary.name == 'uv' else 'python'
                row = retained['tools'][name]
                self.assertIn('sha256', row)
                self.assertIn('filesystem', row)
                self.assertNotIn('probe', row)
                return {'error': 'PermissionError', 'errno': 13}
            with patch.dict(os.environ, {'HERMES_RUNTIME_DIR': str(tools)}), patch.object(probe, 'version_probe', side_effect=observe):
                result = probe.collect(source, tools, {}, export)
            self.assertEqual(result['tools']['uv']['probe']['errno'], 13)
            self.assertFalse(result['permission_repair'])
            self.assertEqual((export / 'tool-execution.json').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                probe.persist({'over': 'x' * probe.REPORT_LIMIT}, export)
            # Generic exporter really includes this new flat evidence member.
            import hosted_evidence
            root = Path(directory) / 'bundle'
            group = root / 'evidence' / 'attempt' / 'export'
            group.mkdir(parents=True)
            shutil.copyfile(export / 'tool-execution.json', group / 'tool-execution.json')
            archive = Path(directory) / 'proof.tar'
            self.assertEqual(hosted_evidence.pack(root, archive)['members'], 1)

    def test_real_probe_failure_output_deadline_and_owned_child_cleanup(self):
        from docker_acceptance import command
        with scratch_home() as directory:
            script = Path(directory) / 'probe-child'
            script.write_text(f'#!{sys.executable}\nimport sys\nprint("actual failure")\nsys.exit(9)\n')
            script.chmod(0o755)
            result = probe.version_probe(script, {'PATH': '/usr/bin:/bin'})
            self.assertEqual(result['exit_code'], 9)
            self.assertEqual(result['output_head'], 'actual failure\n')
            script.write_text(f'#!{sys.executable}\nprint("x" * 70000)\n')
            self.assertEqual(probe.version_probe(script, {})['error'], 'RuntimeError')
            pidfile = Path(directory) / 'pid'
            script.write_text(f'#!{sys.executable}\nimport os,time\nopen({str(pidfile)!r},"w").write(str(os.getpid()))\ntime.sleep(10)\n')
            def bounded(argv, **kwargs):
                kwargs['timeout'] = 0.2
                return command(argv, **kwargs)
            unrelated = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(10)'])
            try:
                with patch('docker_acceptance.command', side_effect=bounded):
                    result = probe.version_probe(script, {})
                self.assertEqual(result['error'], 'TimeoutError')
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(pidfile.read_text()), 0)
                self.assertIsNone(unrelated.poll())
            finally:
                unrelated.terminate()
                unrelated.wait(timeout=5)

    def test_hosted_installer_primary_survives_diagnostic_failure_without_isolation_changes(self):
        import hosted_contract
        import prepare_acceptance
        calls = []
        def execute(argv, env, name, **kwargs):
            calls.append((argv, name))
            if name == 'tool-probe.log':
                raise PermissionError(13, 'secondary export refusal')
            return 1, 'original genuine installer EACCES'
        with patch.object(hosted_contract, 'require_hosted', return_value={}), \
                patch.object(inside, 'git_head', return_value='a' * 40), \
                patch.object(inside, 'execute', side_effect=execute), \
                patch.object(prepare_acceptance, 'enable', side_effect=AssertionError('enable forbidden')):
            with self.assertRaisesRegex(RuntimeError, '^real hosted native admission failed$') as caught:
                inside.hosted_install(['/opt/verifier/bin/python', '/candidate/scripts/native_install.py', '/work/fixture/hermes-source'],
                                      Path('/work/fixture/candidate'), Path('/work/fixture/hermes-source'), {})
        self.assertEqual([name for _argv, name in calls], ['tool-probe.log', 'install.log'])
        self.assertEqual(calls[0][0], ['/opt/verifier/bin/python', str(ROOT / 'scripts/native_tool_execution.py')])
        self.assertIn('PermissionError', caught.exception.__notes__[0])
        from docker_contract import TMPFS
        self.assertEqual(TMPFS, {'/work': 'rw,nosuid,nodev,size=2g,uid=1000,gid=1000,mode=0700',
                                '/tmp': 'rw,nosuid,nodev,noexec,size=64m,uid=1000,gid=1000,mode=0700'})
        # Effect-free ordinary invocation refuses before native imports/collection.
        with patch.object(sys, 'argv', ['probe', 'arbitrary']), patch.object(probe, 'collect') as collect:
            with self.assertRaises(ValueError):
                probe.main()
        collect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
