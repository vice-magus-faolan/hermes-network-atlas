# SPDX-License-Identifier: GPL-3.0-or-later
"""Declared disposable verifier prerequisites, not native/image acceptance."""
import sys
import tomllib
import unittest
from pathlib import Path

from helpers import ROOT, scratch_home
from test_runtime import runtime_root
sys.path.insert(0, str(ROOT / 'scripts'))
from offline_guard import deny_network


class DisposableDependencyTests(unittest.TestCase):
    def test_packaging_is_declared_at_pinned_pm_version_and_consumed_by_image(self):
        deny_network()
        core = runtime_root()
        declaration = tomllib.loads((core / 'pm/pyproject.toml').read_text())
        lock = tomllib.loads((core / 'pm/uv.lock').read_text())
        pinned = [row['version'] for row in lock['package'] if row['name'] == 'packaging']
        self.assertEqual(pinned, ['26.0'])
        requirement = 'packaging==' + pinned[0]
        self.assertIn(requirement, declaration['project']['dependencies'])
        app = tomllib.loads((core / 'pyproject.toml').read_text())
        self.assertIn(requirement + "; python_version >= '3.14'", app['project']['dependencies'])
        requirements = [line.strip() for line in (ROOT / 'requirements-test.txt').read_text().splitlines()
                        if line.strip() and not line.lstrip().startswith('#')]
        self.assertEqual([line for line in requirements if line.startswith('packaging')], [requirement])
        dockerfile = (ROOT / 'docker/validation.Dockerfile').read_text()
        self.assertIn('COPY requirements-test.txt /opt/requirements-test.txt', dockerfile)
        self.assertIn('-r /opt/requirements-test.txt', dockerfile)
        # Exercise the actual import site hit by both hosted workspace errors.
        from pm.plugin_declarations import applicable_requirements
        self.assertEqual(applicable_requirements(['ruamel.yaml==0.18.16', 'hermes-agent==0.0.0']),
                         ('ruamel.yaml==0.18.16',))

    def test_every_pinned_pm_runtime_requirement_is_declared_and_lock_aligned(self):
        deny_network()
        from packaging.requirements import Requirement
        from packaging.utils import canonicalize_name
        core = runtime_root()
        declaration = tomllib.loads((core / 'pm/pyproject.toml').read_text())
        lock = tomllib.loads((core / 'pm/uv.lock').read_text())
        dependencies = declaration['project']['dependencies']
        self.assertEqual(dependencies, ['packaging==26.0', 'tomli-w==1.2.0',
                                        'ruamel.yaml==0.18.16', 'truststore==0.10.4'])
        requirements = [Requirement(line.strip()) for line in (ROOT / 'requirements-test.txt').read_text().splitlines()
                        if line.strip() and not line.lstrip().startswith('#')]
        for value in dependencies:
            requirement = Requirement(value)
            name = canonicalize_name(requirement.name)
            with self.subTest(requirement=value):
                self.assertIsNone(requirement.marker)
                self.assertFalse(requirement.extras)
                pinned = [row['version'] for row in lock['package'] if row['name'] == name]
                self.assertEqual(len(pinned), 1)
                self.assertEqual(str(requirement.specifier), '==' + pinned[0])
                self.assertEqual([str(row) for row in requirements if canonicalize_name(row.name) == name],
                                 [str(requirement)])
        dockerfile = (ROOT / 'docker/validation.Dockerfile').read_text()
        self.assertIn('COPY requirements-test.txt /opt/requirements-test.txt', dockerfile)
        self.assertIn('-r /opt/requirements-test.txt', dockerfile)

    def test_actual_pinned_workspace_writes_member_toml_without_acquisition(self):
        deny_network()
        from pm.workspace import _generate_pyproject
        with scratch_home() as directory:
            root = Path(directory)
            source, member = root / 'core-input', root / 'member'
            source.mkdir()
            member.mkdir()
            text = '[project]\nname="synthetic-core"\nversion="0.0.0"\ndependencies=[]\n'
            (source / 'pyproject.toml').write_text(text)
            (member / 'plugin.yaml').write_text('python_dependencies: ["ruamel.yaml==0.18.16"]\n')
            # Execute the real pm/workspace.py:129 import and TOML writer, but
            # only with tiny synthetic inputs: no full-core snapshot or uv call.
            _generate_pyproject([member], root / 'workspace', source=source)
            document = tomllib.loads((root / 'workspace/pyproject.toml').read_text())
            members = document['tool']['uv']['workspace']['members']
            self.assertEqual(len(members), 1)
            manifest = tomllib.loads((root / 'workspace' / members[0] / 'pyproject.toml').read_text())
            self.assertEqual(manifest['project']['dependencies'], ['ruamel.yaml==0.18.16'])
            self.assertEqual(document['project']['name'], 'synthetic-core')
            self.assertEqual((source / 'pyproject.toml').read_text(), text)


if __name__ == '__main__':
    unittest.main()
