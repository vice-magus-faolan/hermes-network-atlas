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

from helpers import ROOT, copy_plugin, scratch_home
from test_boundaries import synthetic_policy


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
            copy_plugin(plugin)
            (home / "network-atlas").mkdir()
            policy = synthetic_policy() if mode != "invalid" else {"ssh": {"command": "bad"}}
            if mode == "conversion":
                (home / "network-atlas" / "config.yaml").write_text(json.dumps(policy))
                policy = {}
            # Explicit native opt-in selection. No production configuration is copied.
            (home / "config.yaml").write_text(json.dumps({
                "plugins": {"enabled": ["network-atlas"] if mode != "disabled" else [],
                            "disabled": [], "entries": {"network-atlas": {
                                "settings": {"policy": policy}}}}}), encoding="utf-8")
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
                shutil.copy2(ROOT / "tests" / source, fixture_bin / binary)
                (fixture_bin / binary).chmod(0o700)
                env["PATH"] = str(fixture_bin) + os.pathsep + env["PATH"]
                env["NETWORK_ATLAS_OFFLINE_FIXTURE_DIR"] = str(fixture_bin)
            child = subprocess.run([sys.executable, str(ROOT / "tests" / "runtime_smoke.py"), str(root), mode],
                                   env=env, cwd=scratch, capture_output=True, text=True, timeout=60)
            self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
            receipt = json.loads(child.stdout.strip().splitlines()[-1])
            self.assertEqual(receipt["mode"], mode)
            if mode in {"valid", "local_discovery", "ssh_inspection", "conversion"}:
                if mode != "conversion":
                    (home / "config.yaml").write_text(json.dumps({"plugins": {
                        "enabled": ["network-atlas"], "entries": {"network-atlas": {
                            "settings": {"policy": policy}}}}}))
                reopen_mode = "reopen" if mode == "valid" else mode + "_reopen"
                if mode in {"local_discovery", "ssh_inspection"}:
                    # If reopen accidentally collected, only a missing fake binary
                    # may be resolved, never the host's actual ip/nmap commands.
                    (fixture_bin / binary).unlink()
                    env["PATH"] = str(fixture_bin)
                restarted = subprocess.run(
                    [sys.executable, str(ROOT / "tests" / "runtime_smoke.py"), str(root), reopen_mode],
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

    def test_invalid_native_domain_settings_refuse_actions_not_registration(self):
        self.assertTrue(self.run_smoke("invalid")["actions_refused"])

    def test_real_native_local_discovery_reconcile_and_fresh_process(self):
        self.assertTrue(self.run_smoke("local_discovery")["persistent_batches"])

    def test_real_native_ssh_inspect_alias_device_slash_cli_failure_and_restart(self):
        self.assertTrue(self.run_smoke("ssh_inspection")["persistent_ssh_batches"])

    def test_native_plugin_remains_disabled_without_explicit_opt_in(self):
        self.assertTrue(self.run_smoke("disabled")["registration_refused"])

    def test_native_conversion_wal_conflicts_interruption_and_cold_retry(self):
        self.assertTrue(self.run_smoke("conversion")["fresh_native_process_persistence"])

    def test_native_endpoints_fresh_profiles_shared_physical_store_and_isolated_control(self):
        root = runtime_root()
        with scratch_home() as directory:
            scratch = Path(directory)
            (scratch / 'synthetic-atlas-home').touch()
            shared = scratch / 'shared.sqlite3'
            for mode in ('collect', 'reader', 'isolated'):
                home = scratch / mode
                copy_plugin(home / 'plugins' / 'network-atlas')
                (home / 'network-atlas').mkdir()
                raw: dict = {} if mode == 'isolated' else {'store': {'shared_sqlite_path': str(shared)}}
                if mode == 'collect':
                    raw['networks'] = {'lab': {'cidr': '192.0.2.8/31',
                                              'endpoints': {'enabled': True, 'tcp_ports': [22, 2222]}}}
                (home / 'config.yaml').write_text(json.dumps({'plugins': {
                    'enabled': ['network-atlas'], 'entries': {'network-atlas': {'settings': {'policy': raw}}}}}))
                env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(scratch / 'user'),
                       'HERMES_HOME': str(home), 'TMPDIR': str(scratch), 'PYTHONDONTWRITEBYTECODE': '1',
                       'HERMES_BUNDLED_PLUGINS': str(scratch / 'empty-bundled'), 'HERMES_ENABLE_PROJECT_PLUGINS': '0',
                       'HERMES_DISABLE_LAZY_INSTALLS': '1', 'HERMES_MANAGED': 'false',
                       'XDG_CONFIG_HOME': str(scratch / 'xdg-config'), 'XDG_CACHE_HOME': str(scratch / 'xdg-cache'),
                       'XDG_DATA_HOME': str(scratch / 'xdg-data')}
                policy_before = (home / 'config.yaml').read_bytes()
                child = subprocess.run([sys.executable, str(ROOT / 'tests' / 'native_endpoints.py'), str(root), mode],
                                       env=env, cwd=scratch, capture_output=True, text=True, timeout=60)
                self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
                self.assertEqual((home / 'config.yaml').read_bytes(), policy_before)
                self.assertTrue(json.loads(child.stdout.strip().splitlines()[-1])['native_dispatch'])

    def test_missing_native_runtime_is_failure_not_skipped_coverage(self):
        with scratch_home() as directory, patch.dict(os.environ, {"NETWORK_ATLAS_HERMES_ROOT": directory}):
            with self.assertRaises(AssertionError):
                self.run_smoke("valid")
