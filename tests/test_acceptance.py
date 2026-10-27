# SPDX-License-Identifier: GPL-3.0-or-later
"""Three-alias acceptance on stock Hermes with synthetic transports and restart."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

from helpers import ROOT, copy_plugin, scratch_home
from test_runtime import runtime_root


class CumulativeAcceptanceTests(unittest.TestCase):
    def test_three_aliases_and_fresh_process_without_collection(self):
        with scratch_home() as directory:
            root = Path(directory)
            (root / "synthetic-atlas-home").touch()
            home = root / "hermes"
            copy_plugin(home / "plugins" / "network-atlas")
            (home / "config.yaml").write_text(json.dumps({"plugins": {"enabled": ["network-atlas"]}}))
            atlas = home / "network-atlas"
            atlas.mkdir()
            policy = {"version": 1,
                      "networks": {"lab": {"cidr": "192.0.2.0/29", "allow_public": True,
                                           "discovery": {"passive": True, "ping": True}}},
                      "ssh": {"enabled": True, "hosts": {alias: {"alias": alias, "inspect": True}
                                                        for alias in ("lab-a", "lab-b", "lab-c")}},
                      "limits": {"result_count": 100}, "retention": {"stale_after_days": 14}}
            (home / "config.yaml").write_text(json.dumps({"plugins": {
                "enabled": ["network-atlas"], "entries": {"network-atlas": {"settings": {"policy": policy}}}}}))
            fixture = root / "fixture-bin"
            fixture.mkdir()
            (fixture / "offline-fixture").touch()
            (fixture / "stage").write_text("baseline")
            (fixture / "calls.jsonl").write_text("")
            (fixture / "python3").symlink_to(sys.executable)
            for name in ("ip", "nmap", "ssh"):
                shutil.copy2(ROOT / "tests" / "cumulative_transport.py", fixture / name)
                (fixture / name).chmod(0o700)
            env = {"PATH": str(fixture), "HOME": str(root / "user"), "HERMES_HOME": str(home),
                   "TMPDIR": str(root), "PYTHONDONTWRITEBYTECODE": "1",
                   "HERMES_BUNDLED_PLUGINS": str(root / "empty-bundled"), "HERMES_ENABLE_PROJECT_PLUGINS": "0",
                   "HERMES_DISABLE_LAZY_INSTALLS": "1", "HERMES_MANAGED": "false",
                   "XDG_CONFIG_HOME": str(root / "xdg-config"), "XDG_CACHE_HOME": str(root / "xdg-cache"),
                   "XDG_DATA_HOME": str(root / "xdg-data"), "NETWORK_ATLAS_OFFLINE_FIXTURE_DIR": str(fixture)}
            command = [sys.executable, str(ROOT / "tests" / "cumulative_acceptance.py"), str(runtime_root())]
            first = subprocess.run(
                [*command, "collect"], env=env, cwd=root, capture_output=True, text=True, timeout=120)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            calls = (fixture / "calls.jsonl").read_bytes()
            log = [json.loads(line) for line in calls.splitlines()]
            self.assertEqual({row["args"][-2] for row in log if row["binary"] == "ssh"}, {"lab-a", "lab-b", "lab-c"})
            self.assertEqual(len([row for row in log if row["binary"] == "nmap"]), 2)
            for name in ("ip", "nmap", "ssh"):
                (fixture / name).unlink()
            second = subprocess.run([*command, "reopen"], env=env, cwd=root, capture_output=True, text=True, timeout=60)
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertEqual(calls, (fixture / "calls.jsonl").read_bytes(), "restart must not collect")
            self.assertTrue(json.loads(second.stdout.splitlines()[-1])["fresh_process_persistence"])
            for output in (first.stdout, second.stdout):
                result = json.loads(output.splitlines()[-1])
                self.assertTrue(result["issue6_invalid_policy_refusal"])
                self.assertTrue(result["issue6_method_evidence"])
                self.assertEqual(result["tool_count"], 7)
                print("Cumulative native acceptance: " + output.splitlines()[-1], flush=True)
