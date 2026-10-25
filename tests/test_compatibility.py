# SPDX-License-Identifier: GPL-3.0-or-later
"""Actual CLI enablement, not a pre-enabled directory-discovery fixture."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

from ruamel.yaml import YAML

from helpers import copy_plugin, scratch_home


class NativeCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.scratch = Path(self.temp.name)
        self.home = self.scratch / "hermes"
        self.plugin = self.home / "plugins" / "network-atlas"
        copy_plugin(self.plugin)
        # Explicitly empty opt-in avoids legacy migration grandfathering a
        # manually placed plugin. Only the real enable command may select it.
        (self.home / "config.yaml").write_text(json.dumps({"plugins": {"enabled": [], "disabled": []}}))
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.scratch / "user"), "HERMES_HOME": str(self.home),
            "TMPDIR": str(self.scratch), "PYTHONDONTWRITEBYTECODE": "1",
            "HERMES_BUNDLED_PLUGINS": str(self.scratch / "empty-bundled"),
            "HERMES_ENABLE_PROJECT_PLUGINS": "0", "HERMES_DISABLE_LAZY_INSTALLS": "1",
            "HERMES_MANAGED": "false", "NO_COLOR": "1", "COLUMNS": "200",
            "XDG_CONFIG_HOME": str(self.scratch / "xdg-config"),
            "XDG_CACHE_HOME": str(self.scratch / "xdg-cache"),
            "XDG_DATA_HOME": str(self.scratch / "xdg-data"),
        }
        # The image owns these pre-acquired PM tools/cache; never borrow a host
        # account or profile. A normal installed runtime can use its own defaults.
        if "HERMES_RUNTIME_DIR" in os.environ:
            self.env["HERMES_RUNTIME_DIR"] = os.environ["HERMES_RUNTIME_DIR"]
        self.hermes = shutil.which("hermes")
        self.assertIsNotNone(self.hermes, "Installed stock Hermes CLI is required")
        self.assertNotEqual(os.geteuid(), 0, "Compatibility must run as the non-root test user")
        version = self.cli("--version")
        self.assertEqual(version.returncode, 0, version.stdout + version.stderr)
        self.assertRegex(version.stdout, r"(?m)^Hermes Agent v[0-9]+\.[0-9]+\.[0-9]+(?:[ \r\n]|$)")
        self.assertNotIn("unknown", version.stdout.lower())
        print("Non-root native runtime: " + version.stdout.strip(), flush=True)

    def cli(self, *args):
        assert self.hermes is not None
        return subprocess.run([self.hermes, *args], env=self.env, cwd=self.scratch,
                              input="", capture_output=True, text=True, timeout=180)

    def selection_status(self):
        result = self.cli("plugins", "list", "--user", "--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = json.loads(result.stdout)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "network-atlas")
        return rows[0]["status"]

    def test_supported_runtime_native_enable_and_empty_status(self):
        self.assertEqual(self.selection_status(), "not enabled")
        result = self.cli("plugins", "enable", "network-atlas")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.selection_status(), "enabled")
        selected = YAML(typ="safe").load((self.home / "config.yaml").read_text())
        self.assertIn("network-atlas", selected["plugins"]["enabled"])
        status = self.cli("network-atlas", "status")
        self.assertEqual(status.returncode, 0, status.stdout + status.stderr)
        data = json.loads(status.stdout)
        self.assertEqual(data["known_devices"], 0)
        self.assertEqual(data["observed_devices"], 0)
        self.assertEqual(data["configured_scopes"], [])
        self.assertIsNone(data["last_discovery"])
        self.assertIsNone(data["last_inspection"])
        self.assertFalse((self.home / "plugin-data" / "network-atlas" / "atlas.sqlite3").exists())
        raw = {"networks": {"lab": {"cidr": "192.0.2.0/29"}}}
        configured = self.cli("config", "set", "plugins.entries.network-atlas.settings.policy", json.dumps(raw))
        self.assertEqual(configured.returncode, 0, configured.stdout + configured.stderr)
        selected = YAML(typ="safe").load((self.home / "config.yaml").read_text())
        self.assertEqual(selected["plugins"]["entries"]["network-atlas"]["settings"]["policy"], raw)
        refreshed = self.cli("network-atlas", "status")
        self.assertEqual(refreshed.returncode, 0, refreshed.stdout + refreshed.stderr)
        self.assertEqual(json.loads(refreshed.stdout)["configured_networks"], ["lab"])
        self.assertFalse((self.home / "plugin-data" / "network-atlas" / "atlas.sqlite3").exists())
        print("Native supported enable: " + result.stdout.strip(), flush=True)
        print("Native fresh-home status: " + status.stdout.strip(), flush=True)
