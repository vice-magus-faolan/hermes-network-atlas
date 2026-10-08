# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit contained dependency policy; no native acquisition or admission."""

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from helpers import ROOT, scratch_home
from test_runtime import runtime_root
sys.path.insert(0, str(ROOT / 'scripts'))
from acceptance_support import fixture_environment, git_head, git_tree
from offline_guard import deny_network
import docker_inside as inside
import native_install as native

CORE_COMMIT = '5645275e50d66dca04c9565634f9b5207a38aef5'
CORE_TREE = '85282aca9d246911005dba7adbdf3ca3ddd04df5'
CORE_DIGEST = '6c136cc4cf643181091c0077b85ff1fc86615cd841425e91ae1269f951137c79'


class OfflineConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deny_network()
        core = runtime_root()
        if (git_head(core), git_tree(core)) != (CORE_COMMIT, CORE_TREE):
            raise ValueError('authenticated offline-capable core source required')
        sys.path.insert(0, str(core))
        from hermes_cli import plugins_cmd
        if Path(plugins_cmd.__file__).resolve() != core / 'hermes_cli/plugins_cmd.py':
            raise ValueError('actual pinned native API required')
        cls.plugins = plugins_cmd

    def entry(self, root, *flags):
        source = root / 'source'
        source.mkdir()
        (root / 'synthetic-atlas-home').touch()
        result = {'action': 'enable', 'enabled': True, 'plugin': 'intercepted-readback'}
        with patch.dict(os.environ, dict(fixture_environment(root), UV_OFFLINE='1'), clear=True), \
                patch.object(sys, 'argv', ['native_install.py', str(source), 'enable', *flags]), \
                patch.object(native, 'readback', return_value=result), redirect_stdout(io.StringIO()):
            return native.main()

    def test_atlas_enable_flag_reaches_actual_native_keyword_contract(self):
        with scratch_home() as directory, patch.object(self.plugins, 'cmd_enable', autospec=True) as enable:
            self.assertEqual(self.entry(Path(directory), '--offline-enable'), 0)
        enable.assert_called_once_with('network-atlas', offline=True)

    def test_default_online_enable_ignores_ambient_policy(self):
        with scratch_home() as directory, patch.object(self.plugins, 'cmd_enable', autospec=True) as enable:
            self.assertEqual(self.entry(Path(directory)), 0)
        enable.assert_called_once_with('network-atlas')
        import inspect
        self.assertIs(inspect.signature(self.plugins.cmd_enable).parameters['offline'].default, False)

    def test_offline_flag_refuses_other_actions_before_mode_or_filesystem(self):
        for action in ('scan', 'install'):
            with self.subTest(action=action), \
                    patch.object(sys, 'argv', ['native_install.py', '/absent', action, '--offline-enable']), \
                    patch.object(native, 'select_mode') as select, \
                    patch.object(native.Path, 'resolve') as resolve, \
                    patch.object(self.plugins, 'cmd_install') as install, self.assertRaises((ValueError, SystemExit)):
                native.main()
            select.assert_not_called()
            resolve.assert_not_called()
            install.assert_not_called()

    def test_network_none_call_requests_offline_only_after_install(self):
        stop = RuntimeError('stop at intercepted enable boundary')
        env = {'retained-diagnostic': 'literal'}
        with patch('hosted_contract.require_hosted', return_value={}), \
                patch.object(inside, 'git_head', return_value='a'*40), \
                patch.object(inside, 'tool_diagnostics', return_value=None), \
                patch.object(inside, 'execute', return_value=(0, 'intercepted native installation')) as install, \
                patch.object(inside, 'hosted_enable', side_effect=stop) as enable, \
                self.assertRaises(RuntimeError) as raised:
            inside.hosted_install(['python', 'native_install.py', '/contained/core'], Path('/contained/candidate'),
                                  Path('/contained/core'), env)
        self.assertIs(raised.exception, stop)
        self.assertEqual(enable.call_args.args[0], ['python', 'native_install.py', '/contained/core', 'enable', '--offline-enable'])
        self.assertNotIn('--offline-enable', install.call_args.args[0])
        self.assertNotIn('UV_OFFLINE', env, 'ambient env is not supported offline policy')
        self.assertEqual(install.call_args.args[0][-4:], ['--admission-mode', 'hosted-ci-caution', '--origin-commit', 'a'*40])

    def test_ordinary_network_none_call_retains_interactive_consent(self):
        stop = RuntimeError('stop at ordinary enable boundary')
        report = json.dumps({'candidate_commit': 'a'*40, 'candidate_tree': 'b'*40, 'verdict': 'caution'})
        with patch.object(inside, 'git_head', return_value='a'*40), \
                patch.object(inside, 'git_tree', return_value='b'*40), \
                patch.object(inside, 'execute', side_effect=[(0, report), (0, 'intercepted install'), stop]) as execute, \
                self.assertRaises(RuntimeError) as raised:
            inside.scan_and_install(Path('/contained/core'), {}, 'accept')
        self.assertIs(raised.exception, stop)
        self.assertEqual(len(execute.call_args_list), 3)
        self.assertNotIn('--offline-enable', execute.call_args_list[1].args[0])
        self.assertEqual(execute.call_args.args[0][-2:], ['enable', '--offline-enable'])
        self.assertTrue(execute.call_args_list[1].kwargs['interactive'])
        self.assertTrue(execute.call_args.kwargs['interactive'])

    def test_real_activation_selection_and_worker_request_keep_policy_and_refusal(self):
        from hermes_cli.plugins_admission import AdmissionRefused
        from pm import client
        for offline in (False, True):
            with self.subTest(offline=offline), scratch_home() as directory:
                root = Path(directory)
                home = root / 'hermes'
                home.mkdir()
                config = home / 'config.yaml'
                before = b'{"plugins":{"enabled":[],"disabled":[],"entries":{}}}'
                config.write_bytes(before)
                primary = RuntimeError('worker boundary intercepted, no publication')
                with patch.dict(os.environ, dict(fixture_environment(root), UV_OFFLINE='1'), clear=True), \
                        patch.object(self.plugins, 'get_hermes_home', return_value=home), \
                        patch.object(self.plugins, '_resolve_plugin_key_and_source', return_value=('network-atlas', 'user')), \
                        patch.object(self.plugins, '_get_enabled_set', return_value=set()), \
                        patch.object(self.plugins, '_get_disabled_set', return_value=set()), \
                        patch.object(self.plugins, '_plugin_aliases', return_value={'network-atlas'}), \
                        patch.object(self.plugins, '_console', return_value=Mock()), \
                        patch('hermes_cli.plugins_cmd_catalog.refuse_if_installed_removed') as catalog, \
                        patch.object(client, 'is_runtime', return_value=False), \
                        patch.object(client, '_request', side_effect=primary) as request, \
                        patch.object(self.plugins, '_run_capability_consent') as consent, \
                        patch.object(self.plugins, '_resolve_tool_override_grant') as override, \
                        self.assertRaises(AdmissionRefused):
                    self.entry(root, *(['--offline-enable'] if offline else []))
                catalog.assert_called_once()
                consent.assert_not_called()
                override.assert_not_called()
                operation, payload = request.call_args.args
                self.assertEqual(operation, 'sync_venv')
                self.assertIs(payload['offline'], offline)
                self.assertTrue(payload['explicit'])
                self.assertFalse(payload['repair'] or payload['evict_incompatible_plugins'])
                selection = payload['plugins']
                self.assertEqual(selection['kind'], 'selection')
                self.assertEqual(selection['data']['enabled'], ['network-atlas'])
                self.assertEqual(selection['data']['disabled'], [])
                self.assertIn('expected_config', selection['data'])
                self.assertEqual(config.read_bytes(), before)
                self.assertFalse((root / 'native-enabled.json').exists())

    def test_real_engine_fresh_member_lock_and_sync_are_explicit_offline(self):
        from pm.environment import PythonEnvironment, _base_environment
        from pm.workspace import lock_and_sync
        from pm.runtime import runtime_environment
        with scratch_home() as directory:
            root = Path(directory)
            source = root / 'source'
            source.mkdir()
            (source / 'pyproject.toml').write_text('[project]\nname="tiny"\nversion="1"\n[tool.uv]\nexclude-newer="14 days"\n')
            (source / 'uv.lock').write_text('version=1\n')
            member = root / 'member'
            member.mkdir()
            (member / 'plugin.yaml').write_text('python_dependencies: ["ruamel.yaml>=0.18.16,<0.19"]')
            env = {'UV_OFFLINE': '1'}
            self.assertNotIn('UV_OFFLINE', _base_environment(env))
            with patch.dict(os.environ, env, clear=True):
                self.assertNotIn('UV_OFFLINE', runtime_environment())
            engine = PythonEnvironment(uv=root/'uv', python=root/'python', destination=root/'venv',
                                       cache=root/'cache', env=env, offline=True)
            calls = []
            def capture(argv, **kwargs):
                calls.append((argv, kwargs))
                return subprocess.CompletedProcess(argv, 0, '', '')
            with patch('pm.environment.subprocess.run', side_effect=capture):
                lock_and_sync([member], [], root=root/'workspace', source=source, seed_lock=source/'uv.lock',
                              environment=engine, frozen=False)
            self.assertEqual([row[0][1] for row in calls], ['lock', 'sync'])
            self.assertTrue(all('--offline' in row[0] for row in calls))
            self.assertNotIn('--frozen', calls[0][0])
            self.assertIn('--all-packages', calls[1][0])
            self.assertTrue(all('UV_OFFLINE' not in row[1]['env'] for row in calls))
            self.assertFalse((root/'venv').exists(), 'intercepted uv is not actual resolution/installation')

    def test_current_core_identity_workflow_and_unrelated_pins(self):
        import acceptance_support, caution_confirmation, core_identity, docker_builder
        sys.path.insert(0, str(ROOT / 'docker'))
        import hosted_setup
        from ruamel.yaml import YAML
        self.assertEqual(acceptance_support.HERMES_COMMIT, CORE_COMMIT)
        self.assertEqual(hosted_setup.HERMES, CORE_COMMIT)
        for value in (hosted_setup.TREE, docker_builder.CORE_TREE, core_identity.CORE_TREE, caution_confirmation.CORE_TREE):
            self.assertEqual(value, CORE_TREE)
        for value in (core_identity.CORE_SOURCE_DIGEST, caution_confirmation.CORE_SOURCE_DIGEST):
            self.assertEqual(value, CORE_DIGEST)
        deps = json.loads((ROOT/'docker/dependencies.json').read_text())
        self.assertEqual(deps['hermes_commit'], CORE_COMMIT)
        self.assertEqual((deps['python'], deps['uv'], deps['debian_snapshot']), ('3.14.7', '0.12.3', '20260919T000000Z'))
        workflow = YAML(typ='safe').load((ROOT/'.github/workflows/verify.yml').read_text())
        for job in (value for name, value in workflow['jobs'].items() if name != 'feature-phase'):
            steps = [step for step in job['steps'] if step.get('with', {}).get('path') == '.hermes-runtime-source']
            self.assertEqual(len(steps), 1)
            self.assertEqual(steps[0]['with']['repository'], 'vice-magus-faolan/hermes-agent')
            self.assertEqual(steps[0]['with']['ref'], CORE_COMMIT)
            self.assertIs(steps[0]['with']['persist-credentials'], False)
        self.assertIn(CORE_COMMIT, (ROOT/'docker/Dockerfile').read_text())

    def test_historical_base_and_failed_image_never_satisfy_current_pin(self):
        from test_docker_container_readback import proof
        from test_docker_default_command import actual_records
        import docker_acceptance, docker_builder
        image, record = proof()
        with self.assertRaisesRegex(ValueError, 'Config.Labels'):
            docker_acceptance.validate_base(image, record, record['daemon'])
        failed, stopped = actual_records()
        labels = stopped['Config']['Labels']
        identity = docker_builder.BootstrapIdentity(labels[docker_builder.BASE_LABEL],
                    labels['org.network-atlas.acceptance.daemon'], stopped['Image'],
                    labels['org.network-atlas.acceptance.plan'])
        audit = docker_builder.image_validation(failed, identity, failed['Id'], failed['RootFS']['Layers'][:-1])
        self.assertIn('Config.Labels', audit['mismatches'])
        self.assertIn('Config.Cmd', audit['mismatches'])
        self.assertFalse(audit['verified'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
