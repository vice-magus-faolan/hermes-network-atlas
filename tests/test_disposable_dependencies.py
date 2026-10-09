# SPDX-License-Identifier: GPL-3.0-or-later
"""Declared disposable verifier prerequisites, not native/image acceptance."""
import sys
import tomllib
import unittest

from helpers import ROOT
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


if __name__ == '__main__':
    unittest.main()
