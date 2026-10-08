# SPDX-License-Identifier: GPL-3.0-or-later
"""Actual pinned PM parser/dispatch contracts; no installation or acquisition."""
import ast
from contextlib import redirect_stdout
import inspect
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from helpers import ROOT, scratch_home
from test_runtime import runtime_root
sys.path.insert(0, str(ROOT / 'scripts'))
from acceptance_support import HERMES_COMMIT, git_head, git_tree
from offline_guard import deny_network


def command_expression(filename, module):
    """Use the production argv expression, not an independently copied good argv."""
    tree = ast.parse((ROOT / filename).read_text())
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == 'run'
             and node.args and isinstance(node.args[0], ast.List)
             and any(isinstance(item, ast.Constant) and item.value == module
                     for item in node.args[0].elts)]
    if len(calls) != 1:
        raise ValueError('unique production PM command required')
    return compile(ast.Expression(calls[0].args[0]), filename, 'eval')


def parse_install(cli, argv):
    """Execute the actual parser and flag predicate, stopping before dispatch."""
    parsed = []
    errors = []
    def inspect_flags(args):
        parsed.append(args)
        errors.append(cli._install_flag_error(
            args, extras=args.extra, cross_target=args.target, tools_only=args.tools_only,
            trust_recorded=args.trust_recorded, test_environment=args.test_environment))
        return 1 if errors[-1] else 0
    with patch.object(cli, 'cmd_install', side_effect=inspect_flags), \
            patch('pm.runtime.is_runtime', return_value=True), \
            patch('pm.runtime.run_cli', side_effect=AssertionError('native runtime dispatch forbidden')):
        code = cli.main(argv)
    return code, parsed[0], errors[0]


class NativePMContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deny_network()
        core = runtime_root()
        if git_head(core) != HERMES_COMMIT or git_tree(core) != '85282aca9d246911005dba7adbdf3ca3ddd04df5':
            raise ValueError('actual pinned public PM source required')
        subprocess.run(['git', '-C', str(core), 'diff', '--exit-code', 'HEAD', '--',
                        'pm', 'hermes_constants.py', 'hermes_cli/plugins_cmd.py'], check=True,
                       capture_output=True, timeout=15)
        sys.path.insert(0, str(core))
        import pm.cli
        if Path(pm.cli.__file__).resolve() != core / 'pm/cli.py':
            raise ValueError('PM import resolved to a different core')
        cls.cli = pm.cli
        cls.core = core
        cls.inputs = json.loads((ROOT / 'docker/dependencies.json').read_text())

    def argv(self, filename='docker/hosted_setup.py'):
        return eval(command_expression(filename, 'pm.cli'), {'sys': sys})[3:]

    def test_candidate_argv_passes_actual_parser_and_flag_predicate(self):
        for filename in ('docker/hosted_setup.py', 'docker/base_setup.py'):
            with self.subTest(filename=filename):
                code, args, error = parse_install(self.cli, self.argv(filename))
                self.assertEqual((code, error), (0, None))
                self.assertEqual(args.names, ['python', 'uv'])
                self.assertFalse(args.tools_only)
                self.assertFalse(args.trust_recorded)
                self.assertFalse(args.extra or args.target or args.without or args.test_environment)

    def test_predecessor_tools_only_names_refuse_before_dispatch(self):
        argv = ['install', 'python', 'uv', '--tools-only']
        code, args, error = parse_install(self.cli, argv)
        self.assertEqual(code, 1)
        self.assertIn('--tools-only installs the tool closure', error)
        with patch.object(self.cli, '_install_names') as install, \
                patch.object(self.cli, '_lockfile') as lock, redirect_stdout(io.StringIO()):
            self.assertEqual(self.cli.cmd_install(args), 1)
        install.assert_not_called()
        lock.assert_not_called()

    def test_named_dispatch_keeps_exact_tools_and_never_syncs_or_defaults(self):
        import pm
        _, args, error = parse_install(self.cli, self.argv())
        self.assertIsNone(error)
        # Only the installation boundary and bookkeeping are replaced. Real
        # cmd_install and its environment branch decide whether builds occur.
        with patch.object(self.cli, '_install_names', return_value=0) as install, \
                patch.object(self.cli, '_lockfile', side_effect=AssertionError('default closure forbidden')), \
                patch.object(self.cli, '_install_defaults') as defaults, \
                patch('pm.defaults.record_declined') as declined, \
                patch('pm.install.activate') as activate, \
                patch('pm.environments.activation_input_mtimes') as stamps, \
                patch('pm.install.sync_venv') as sync, \
                patch.object(pm, 'check_project_lock') as check:
            self.assertEqual(self.cli.cmd_install(args), 0)
        install.assert_called_once_with(['python', 'uv'], target=None, verify=True)
        declined.assert_called_once_with(remove=['python', 'uv'])
        defaults.assert_called_once_with([], verify=True)
        for boundary in (activate, stamps, sync, check):
            boundary.assert_not_called()

    def test_bare_tools_only_closure_is_not_the_authenticated_seed(self):
        from pm.registry import source_install_packages, tool_roots, walk
        from pm.defaults import default_packages
        lock = json.loads((self.core / 'pm/lock.json').read_text())
        names = list(lock['packages'])
        self.assertEqual([item.name for item in walk(['python', 'uv'])], ['python', 'uv'])
        roots = tool_roots(source_install_packages(names))
        self.assertTrue({'node', 'npm', 'ffmpeg', 'ripgrep'} <= set(roots))
        self.assertTrue(set(roots) - {'python', 'uv'})
        defaults = default_packages(names, target='linux-x64', declined_names=frozenset())
        self.assertEqual(set(defaults), {'agent-browser', 'cua-driver'})
        self.assertEqual(parse_install(self.cli, ['install', '--tools-only'])[0], 0)

    def test_verifier_argv_matches_actual_build_parser_and_public_api(self):
        import pm
        from pm import build_env
        from pm.client import build_requirements_environment
        argv = eval(command_expression('docker/hosted_setup.py', 'pm.build_env'),
                    {'sys': sys, 'inputs': self.inputs, 'downloads': Path('/opt/seed/wheelhouse')})
        signature = inspect.signature(build_requirements_environment)
        def validate(*args, **kwargs):
            bound = signature.bind(*args, **kwargs)
            self.assertEqual(bound.arguments['requirements'], self.inputs['verifier_requirements'])
            self.assertEqual(bound.arguments['out'], Path('/opt/verifier'))
            self.assertEqual(bound.arguments['wheelhouse'], Path('/opt/seed/wheelhouse'))
            self.assertTrue(bound.arguments['offline'])
            self.assertTrue(bound.arguments['explicit'])
            return Path('/fixture/not-created/bin/python')
        with patch.object(pm, 'build_requirements_environment', side_effect=validate) as build, \
                patch.object(pm, 'build_environment', side_effect=AssertionError('project build forbidden')), \
                patch.object(pm, 'stage_manager_runtime', side_effect=AssertionError('runtime build forbidden')), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(build_env.main(argv[3:]), 0)
        build.assert_called_once()

    def test_hosted_pm_api_signatures_and_member_encoding(self):
        from pm import client, environments
        from pm.plugin_inputs import Members, encode
        from pm.store import Store
        from hermes_cli import plugins_cmd
        root = Path('/fixture/not-created')
        member = Members([root / 'dependency-input'])
        self.assertEqual(encode(member), {'kind': 'members', 'paths': [str(root / 'dependency-input')]})
        inspect.signature(client.sync_venv).bind(explicit=True, plugins=member, project_root=root)
        inspect.signature(Store).bind(root / 'tools')
        inspect.signature(Store.install_lock).bind(object())
        inspect.signature(Store.scratch).bind(object())
        inspect.signature(Store.fetch_many).bind(object(), [], root, progress=Mock())
        for api in (environments.runtime_facts_path, environments.selected_venv,
                    environments.committed_venv, environments.venv_python):
            inspect.signature(api).bind(root)
        inspect.signature(plugins_cmd.cmd_install).bind('file:///fixture/candidate', enable=False,
                                                       ref='a' * 40, force=True)
        inspect.signature(plugins_cmd.cmd_enable).bind('network-atlas')

    def test_real_command_success_failure_and_bounded_output_diagnostics(self):
        sys.path.insert(0, str(ROOT / 'docker'))
        import hosted_setup as setup
        with scratch_home() as directory:
            root = Path(directory)
            child = root / 'public-command.py'
            for code in (0, 7):
                child.write_text(f"print('x' * 40000)\nraise SystemExit({code})\n")
                output = io.StringIO()
                with patch.object(setup, 'CORE', root), redirect_stdout(output):
                    if code:
                        with self.assertRaisesRegex(RuntimeError, 'public setup command failed: exit=7'):
                            setup.run([sys.executable, str(child)])
                    else:
                        self.assertEqual(len(setup.run([sys.executable, str(child)])), 40001)
                rows = [json.loads(line) for line in output.getvalue().splitlines()]
                self.assertEqual(len(rows), 2)
                self.assertEqual(rows[0]['state'], 'started')
                self.assertEqual(rows[1]['state'], 'failed' if code else 'complete')
                self.assertEqual(rows[1]['exit_code'], code)
                self.assertEqual(rows[1]['output_bytes'], 40001)
                self.assertTrue(rows[1]['output_truncated'])
                self.assertEqual(len(rows[1]['output']), 32768)
                self.assertEqual(rows[1]['public_command'], [sys.executable, str(child)])

    def test_command_diagnostic_failure_never_replaces_primary_error(self):
        sys.path.insert(0, str(ROOT / 'docker'))
        import hosted_setup as setup
        primary = RuntimeError('actual command failure seam')
        with patch.object(setup, 'bounded_run', side_effect=primary), \
                patch('builtins.print', side_effect=[None, OSError('diagnostic seam')]), \
                self.assertRaises(RuntimeError) as raised:
            setup.run(['fixture-not-executed'])
        self.assertIs(raised.exception, primary)
        self.assertIn('command diagnostic failed: OSError', primary.__notes__)


if __name__ == '__main__':
    unittest.main()
