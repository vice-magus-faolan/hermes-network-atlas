# SPDX-License-Identifier: GPL-3.0-or-later
"""Required real native runtime smoke; missing Hermes is a failure, never a silent skip."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
from test_boundaries import synthetic_policy

PLUGIN_FILES = ("plugin.yaml", "__init__.py", "config.py", "schemas.py", "updates.py", "tools.py", "commands.py",
                "storage.py", "storage_schema.sql", "facts.py", "identity.py", "core.py", "query.py", "batches.py", "render.py",
                "probes.py", "discovery_parse.py", "discovery.py", "reconcile.py", "inspection.py",
                "inspection_parse.py", "inspection_evidence.py", "ssh_identity.py", "unresolved.py", "host_discovery.py")


def runtime_root() -> Path:
    """Use explicitly supplied Hermes source or an importable installed native runtime."""
    configured = os.environ.get("NETWORK_ATLAS_HERMES_ROOT")
    if configured:
        return Path(configured).resolve()
    spec = importlib.util.find_spec("hermes_cli")
    if spec is not None and spec.origin:
        return Path(spec.origin).resolve().parents[1]
    raise RuntimeError("Real Hermes required: set NETWORK_ATLAS_HERMES_ROOT to a verified Hermes source tree")


class NativeRuntimeTests(unittest.TestCase):
    def run_smoke(self, mode: str):
        root = runtime_root()
        self.assertTrue((root / "hermes_cli" / "plugins.py").is_file())
        with scratch_home() as directory:
            scratch = Path(directory)
            (scratch / "synthetic-atlas-home").touch()
            home = scratch / "hermes"
            plugin = home / "plugins" / "network-atlas"
            plugin.mkdir(parents=True)
            for name in PLUGIN_FILES:
                shutil.copy2(ROOT / name, plugin / name)
            (home / "network-atlas").mkdir()
            policy = synthetic_policy() if mode != "invalid" else {"ssh": {"command": "bad"}}
            (home / "network-atlas" / "config.yaml").write_text(json.dumps(policy), encoding="utf-8")
            # Explicit native opt-in selection. No production configuration is copied.
            (home / "config.yaml").write_text(json.dumps({"plugins": {"enabled": ["network-atlas"] if mode != "disabled" else [],
                                                                        "disabled": []}}), encoding="utf-8")
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(scratch / "user"),
                   "HERMES_HOME": str(home), "TMPDIR": str(scratch), "PYTHONDONTWRITEBYTECODE": "1",
                   "HERMES_BUNDLED_PLUGINS": str(scratch / "empty-bundled"), "HERMES_ENABLE_PROJECT_PLUGINS": "0",
                   "HERMES_DISABLE_LAZY_INSTALLS": "1", "HERMES_MANAGED": "false",
                   "XDG_CONFIG_HOME": str(scratch / "xdg-config"), "XDG_CACHE_HOME": str(scratch / "xdg-cache"),
                   "XDG_DATA_HOME": str(scratch / "xdg-data")}
            fixture_bin = scratch / "fixture-bin"
            binary = "ip" if mode == "local_discovery" else "ssh"
            if mode in {"local_discovery", "ssh_inspection"}:
                fixture_bin.mkdir()
                (fixture_bin / "offline-fixture").touch()
                source = "offline_probe.py" if binary == "ip" else "offline_ssh.py"
                shutil.copy2(ROOT / "scripts" / source, fixture_bin / binary)
                (fixture_bin / binary).chmod(0o700)
                env["PATH"] = str(fixture_bin) + os.pathsep + env["PATH"]
                env["NETWORK_ATLAS_OFFLINE_FIXTURE_DIR"] = str(fixture_bin)
            child = subprocess.run([sys.executable, str(ROOT / "scripts" / "runtime_smoke.py"), str(root), mode],
                                   env=env, cwd=scratch, capture_output=True, text=True, timeout=60)
            self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
            receipt = json.loads(child.stdout.strip().splitlines()[-1])
            self.assertEqual(receipt["mode"], mode)
            if mode in {"valid", "local_discovery", "ssh_inspection"}:
                (home / "network-atlas" / "config.yaml").write_text(json.dumps(policy), encoding="utf-8")
                reopen_mode = "reopen" if mode == "valid" else mode + "_reopen"
                if mode in {"local_discovery", "ssh_inspection"}:
                    # If reopen accidentally collected, only a missing fake binary
                    # may be resolved, never the host's actual ip/nmap commands.
                    (fixture_bin / binary).unlink()
                    env["PATH"] = str(fixture_bin)
                restarted = subprocess.run([sys.executable, str(ROOT / "scripts" / "runtime_smoke.py"), str(root), reopen_mode],
                                           env=env, cwd=scratch, capture_output=True, text=True, timeout=60)
                self.assertEqual(restarted.returncode, 0, restarted.stdout + restarted.stderr)
                persistence = json.loads(restarted.stdout.strip().splitlines()[-1])
                self.assertTrue(persistence["fresh_native_process_persistence"])
                receipt["fresh_native_process_persistence"] = True
            print("Native runtime smoke: " + json.dumps(receipt, sort_keys=True), flush=True)
            return receipt

    def test_actual_native_discovery_schemas_tools_commands_and_operator_split(self):
        receipt = self.run_smoke("valid")
        self.assertTrue(receipt["native_discovery"])
        self.assertTrue(receipt["real_dispatch"])
        self.assertEqual(receipt["operator_cli_source"], "user")
        self.assertEqual(receipt["tool_source"], "inference")

    def test_invalid_config_registers_no_tools_or_commands_in_real_runtime(self):
        self.assertTrue(self.run_smoke("invalid")["registration_refused"])

    def test_real_native_local_discovery_reconcile_and_fresh_process(self):
        self.assertTrue(self.run_smoke("local_discovery")["persistent_batches"])

    def test_real_native_ssh_inspect_alias_device_slash_cli_failure_and_restart(self):
        self.assertTrue(self.run_smoke("ssh_inspection")["persistent_ssh_batches"])

    def test_native_plugin_remains_disabled_without_explicit_opt_in(self):
        self.assertTrue(self.run_smoke("disabled")["registration_refused"])

    def test_missing_native_runtime_is_failure_not_skipped_coverage(self):
        with scratch_home() as directory, patch.dict(os.environ, {"NETWORK_ATLAS_HERMES_ROOT": directory}):
            with self.assertRaises(AssertionError):
                self.run_smoke("valid")
