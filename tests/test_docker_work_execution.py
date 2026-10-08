# SPDX-License-Identifier: GPL-3.0-or-later
"""Work-exec policy and observed noexec refusal; no Docker or native admission."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
import test_docker_acceptance as fixtures
sys.path.insert(0, str(ROOT / 'scripts'))
import docker_contract as contract
import docker_inside as inside
import native_tool_execution as probe
from offline_guard import deny_network

WORK = 'rw,nosuid,nodev,exec,size=2g,uid=1000,gid=1000,mode=0700'
TMP = 'rw,nosuid,nodev,noexec,size=64m,uid=1000,gid=1000,mode=0700'


def filesystem(path, point, *, readonly=False, noexec=False, tmpfs=False):
    """Explicit synthetic kernel seam, not actual hosted or host mount proof."""
    flags = (os.ST_RDONLY if readonly else 0) | (os.ST_NOEXEC if noexec else 0)
    options = ['ro' if readonly else 'rw']
    if tmpfs:
        flags |= os.ST_NOSUID | os.ST_NODEV
        options += ['nosuid', 'nodev']
    if noexec:
        options += ['noexec']
    return {'path': path, 'mount': {'mountpoint': point, 'options': options,
                                  'filesystem': 'tmpfs' if tmpfs else 'synthetic'},
            'statvfs_flags': flags, 'readonly': readonly, 'noexec': noexec, 'nosuid': tmpfs}


def report_fixture():
    """A prospective report model; never labeled real native tool versions."""
    report: dict = {key: 1000 for key in ('uid', 'euid', 'gid', 'egid')}
    report.update(native_acceptance=False, filesystems=[
        filesystem('/', '/', readonly=True), filesystem('/candidate', '/candidate', readonly=True),
        filesystem('/opt', '/', readonly=True), filesystem('/work', '/work', tmpfs=True),
        filesystem('/tmp', '/tmp', noexec=True, tmpfs=True)], tools={})
    for name, version, rel in [('uv', 'fixture-uv', 'uv'), ('python', '3.0+fixture', 'bin/python3')]:
        binary = '/work/fixture/tools/' + name + '-fixture/' + rel
        text = 'uv ' + version + '\n' if name == 'uv' else 'Python 3.0\n'
        report['tools'][name] = {'requested_path': binary, 'resolved_path': binary, 'target': 'linux-x64',
                                 'elf': True, 'version': version,
                                 'filesystem': filesystem(binary, '/work', tmpfs=True),
                                 'probe': {'argv': [binary, '--version'], 'exit_code': 0,
                                           'output_complete': True, 'output_captured_bytes': len(text),
                                           'output_head': text}}
    return report


class WorkExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deny_network()

    def test_all_modes_create_exec_only_work_and_exact_isolation(self):
        reference = fixtures.DockerContractTests()
        self.assertEqual(contract.TMPFS, {'/work': WORK, '/tmp': TMP})
        with scratch_home() as directory:
            root = Path(directory)
            for mode in contract.MODES:
                hosted = {'GITHUB_WORKSPACE': '/candidate'} if mode == 'hosted-accept' else None
                argv = contract.create_command(reference.identity(), root, mode, root, hosted=hosted)
                values = [argv[index + 1] for index, value in enumerate(argv) if value == '--tmpfs']
                self.assertEqual(values, ['/work:' + WORK, '/tmp:' + TMP])
                self.assertEqual(argv.count('--tmpfs'), 2)
                self.assertIn('--read-only', argv)
                for key, value in [('--network', 'none'), ('--user', '1000:1000'), ('--cap-drop', 'ALL'),
                                   ('--security-opt', 'no-new-privileges=true'), ('--memory', str(contract.MEMORY)),
                                   ('--memory-swap', str(contract.MEMORY)), ('--cpus', '2'), ('--pids-limit', '256')]:
                    self.assertEqual(argv[argv.index(key) + 1], value)
                self.assertEqual(argv.count('--mount'), 2)
                self.assertEqual(argv[-4:], [reference.identity().image, 'python3', '/candidate/scripts/docker_inside.py', mode])
                self.assertFalse(set(argv) & {'--privileged', '--cap-add', '--pid', '--device', '--volume'})

    def test_exact_inspect_rejects_options_resource_uid_and_mount_drift(self):
        reference = fixtures.DockerContractTests()
        with scratch_home() as directory:
            root = Path(directory)
            actual = copy.deepcopy(reference.inspection(root))
            self.assertEqual(contract.validate_container(actual, reference.identity(), root, 'smoke'), 'd' * 64)
            for old, new in [('exec,', ''), ('exec,', 'noexec,'), ('nosuid,', ''), ('nodev,', ''),
                             ('size=2g', 'size=3g'), ('uid=1000', 'uid=0'), ('gid=1000', 'gid=0'),
                             ('mode=0700', 'mode=0777')]:
                bad = copy.deepcopy(actual)
                bad['HostConfig']['Tmpfs']['/work'] = WORK.replace(old, new)
                with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                    contract.validate_container(bad, reference.identity(), root, 'smoke')
            bad = copy.deepcopy(actual)
            bad['HostConfig']['Tmpfs']['/tmp'] = TMP.replace('noexec', 'exec')
            with self.assertRaises(ValueError):
                contract.validate_container(bad, reference.identity(), root, 'smoke')
            for index, key, value in [(0, 'RW', True), (0, 'Source', '/home'), (1, 'Source', '/var/run/docker.sock'),
                                      (1, 'Destination', '/arbitrary')]:
                bad = copy.deepcopy(actual)
                bad['Mounts'][index][key] = value
                with self.subTest(index=index, key=key), self.assertRaises(ValueError):
                    contract.validate_container(bad, reference.identity(), root, 'smoke')
            for section, key, value in [('Config', 'User', '0:0'), ('HostConfig', 'ReadonlyRootfs', False),
                                        ('HostConfig', 'Memory', 0), ('HostConfig', 'CapAdd', ['SYS_ADMIN'])]:
                bad = copy.deepcopy(actual)
                bad[section][key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    contract.validate_container(bad, reference.identity(), root, 'smoke')

    def test_actual_hosted_noexec_and_eacces_remain_refused(self):
        payload = (ROOT / 'tests/fixtures/run37724779987-tool-execution.json').read_bytes()
        self.assertEqual(hashlib.sha256(payload).hexdigest(),
                         'eb660986a0be44f1a0275d033601ca9b235c7724713cd97c7e2360eac8af23df')
        historical = json.loads(payload)
        work = next(row for row in historical['filesystems'] if row['path'] == '/work')
        self.assertEqual(work['statvfs_flags'], 4110)
        self.assertIn('noexec', work['mount']['options'])
        with self.assertRaisesRegex(ValueError, 'filesystem flags drift'):
            probe.require_filesystem(work, '/work', readonly=False, noexec=False, tmpfs=True)
        for name, row in historical['tools'].items():
            self.assertEqual(row['probe']['errno'], 13)
            self.assertEqual(row['resolved_ancestors'][-1]['mode'], '0o755')
            with self.subTest(name=name), self.assertRaises(ValueError):
                probe.require_tool(row, name)
        self.assertFalse(historical['native_acceptance'])
        # Do not manufacture a successful historical report from intended exec.
        self.assertEqual(hashlib.sha256(payload).hexdigest(), hashlib.sha256(
            (ROOT / 'tests/fixtures/run37724779987-tool-execution.json').read_bytes()).hexdigest())

    def test_effective_kernel_protection_flags_and_coverage_refuse(self):
        good = report_fixture()
        probe.require_execution(good)  # synthetic model only
        for index in range(len(good['filesystems'])):
            for field, value in [('statvfs_flags', None), ('mount', {}), ('readonly', None), ('noexec', None)]:
                bad = copy.deepcopy(good)
                bad['filesystems'][index][field] = value
                with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                    probe.require_execution(bad)
        for flag, option in [(os.ST_NOSUID, 'nosuid'), (os.ST_NODEV, 'nodev')]:
            for path in ('/work', '/tmp'):
                bad = copy.deepcopy(good)
                row = next(row for row in bad['filesystems'] if row['path'] == path)
                row['statvfs_flags'] &= ~flag
                row['mount']['options'].remove(option)
                with self.subTest(path=path, flag=flag), self.assertRaises(ValueError):
                    probe.require_execution(bad)
        for path, flags in [('/work', os.ST_NOEXEC), ('/tmp', 0), ('/', 0), ('/candidate', 0)]:
            bad = copy.deepcopy(good)
            next(row for row in bad['filesystems'] if row['path'] == path)['statvfs_flags'] = flags
            with self.subTest(path=path), self.assertRaises(ValueError):
                probe.require_execution(bad)
        for field, value in [('filesystems', good['filesystems'][:-1]), ('uid', 0), ('tools', {})]:
            bad = copy.deepcopy(good)
            bad[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                probe.require_execution(bad)
        bad = copy.deepcopy(good)
        bad['filesystems'].append(copy.deepcopy(bad['filesystems'][0]))
        with self.assertRaises(ValueError):
            probe.require_execution(bad)

    def test_native_probe_version_containment_and_denial_never_pass(self):
        good = report_fixture()
        for name in ('uv', 'python'):
            for field, value in [('exit_code', 1), ('error', 'PermissionError'), ('output_complete', False),
                                 ('output_captured_bytes', 0), ('output_captured_bytes', 65537),
                                 ('output_head', 'unrelated version\n'), ('argv', ['/opt/tool', '--version'])]:
                bad = copy.deepcopy(good)
                bad['tools'][name]['probe'][field] = value
                with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                    probe.require_execution(bad)
            for field, value in [('requested_path', '/opt/tool'), ('resolved_path', '/usr/bin/python'),
                                 ('target', 'linux-arm64'), ('elf', False), ('error', 'ValueError')]:
                bad = copy.deepcopy(good)
                bad['tools'][name][field] = value
                with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                    probe.require_execution(bad)
            bad = copy.deepcopy(good)
            bad['tools'][name]['filesystem']['statvfs_flags'] |= os.ST_NOEXEC
            with self.assertRaises(ValueError):
                probe.require_execution(bad)

    def test_contract_persistence_failure_refuses_and_preserves_primary(self):
        with scratch_home() as directory:
            export = Path(directory)
            good = report_fixture()
            probe.check_execution(good, export)
            retained = json.loads((export / 'tool-execution.json').read_text())
            self.assertEqual(retained['execution_contract'], {'verified': True, 'native_acceptance': False})
            self.assertFalse(retained['native_acceptance'])
            bad = report_fixture()
            bad['uid'] = 0
            with self.assertRaisesRegex(ValueError, 'UID/GID drift'):
                probe.check_execution(bad, export)
            self.assertFalse(json.loads((export / 'tool-execution.json').read_text())['execution_contract']['verified'])
            with patch.object(probe, 'persist', side_effect=PermissionError('secondary')):
                with self.assertRaisesRegex(ValueError, 'UID/GID drift') as caught:
                    probe.check_execution(bad, export)
                self.assertIn('PermissionError', caught.exception.__notes__[0])
                with self.assertRaises(PermissionError):
                    probe.check_execution(report_fixture(), export)

    def test_real_entrypoint_checks_collected_report_before_exit(self):
        import acceptance_support
        import caution_confirmation
        import hosted_contract
        with scratch_home() as directory:
            fixture = Path(directory) / 'fixture'
            export = Path(directory) / 'export'
            fixture.mkdir()
            export.mkdir()
            for good in (True, False):
                report = report_fixture()
                if not good:
                    report['uid'] = 0
                with patch.object(sys, 'argv', ['probe']), patch.object(os, 'getuid', return_value=1000), \
                        patch.object(os, 'getgid', return_value=1000), \
                        patch.object(probe, 'FIXTURE', fixture), patch.object(probe, 'EXPORT', export), \
                        patch.dict(os.environ, {'HERMES_RUNTIME_DIR': str(fixture / 'tools')}), \
                        patch.object(acceptance_support, 'git_head', return_value='a' * 40), \
                        patch.object(hosted_contract, 'require_hosted'), \
                        patch.object(caution_confirmation, 'verify_core'), patch.object(probe, 'collect', return_value=report):
                    if good:
                        self.assertEqual(probe.main(), 0)
                    else:
                        with self.assertRaisesRegex(ValueError, 'UID/GID drift'):
                            probe.main()
                self.assertEqual(json.loads((export / 'tool-execution.json').read_text())['execution_contract']['verified'], good)

    def test_installer_runs_but_failed_execution_blocks_enable_and_acceptance(self):
        import hosted_contract
        import prepare_acceptance
        for install_code in (0, 1):
            calls = []
            def execute(argv, env, name, **kwargs):
                calls.append(name)
                return (1, 'effective execution refused') if name == 'tool-probe.log' else (install_code, 'installer')
            with patch.object(hosted_contract, 'require_hosted', return_value={}), \
                    patch.object(inside, 'git_head', return_value='a' * 40), \
                    patch.object(inside, 'execute', side_effect=execute), \
                    patch.object(prepare_acceptance, 'enable') as enable, patch.object(inside, 'canonical') as canonical:
                message = '^real hosted native admission failed$' if install_code else 'tool diagnostic collection failed'
                with self.assertRaisesRegex(RuntimeError, message) as caught:
                    inside.hosted_install(['/opt/verifier/bin/python', '/candidate/scripts/native_install.py', '/work/fixture/hermes-source'],
                                          Path('/work/fixture/candidate'), Path('/work/fixture/hermes-source'), {})
                self.assertEqual(calls, ['tool-probe.log', 'install.log'])
                enable.assert_not_called()
                canonical.assert_not_called()
                if install_code:
                    self.assertIn('exit=1', caught.exception.__notes__[0])


if __name__ == '__main__':
    unittest.main()
