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

from helpers import ROOT, copy_plugin, scratch_home, symlink_plugin_data
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
    def run_smoke(self, mode: str, *, data_layout: str | None = None, umask: int = 0o022):
        root = runtime_root()
        self.assertTrue((root / "hermes_cli" / "plugins.py").is_file())
        with scratch_home() as directory:
            scratch = Path(directory)
            (scratch / "synthetic-atlas-home").touch()
            home = scratch / "hermes"
            plugin = home / "plugins" / "network-atlas"
            copy_plugin(plugin)
            if data_layout is not None:
                symlink_plugin_data(home, data_layout)
            (home / "network-atlas").mkdir()
            policy = synthetic_policy() if mode != "invalid" else {"ssh": {"command": "bad"}}
            if mode in {"status_availability", "status_eligibility"}:
                policy = {}
            if mode in {"conversion", "conversion_overlap", "conversion_hardkill", "native_clone"}:
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
            if data_layout is not None:
                env["NETWORK_ATLAS_TEST_DATA_LAYOUT"] = data_layout
            env["NETWORK_ATLAS_TEST_UMASK"] = oct(umask)
            if "HERMES_RUNTIME_DIR" in os.environ:
                env["HERMES_RUNTIME_DIR"] = os.environ["HERMES_RUNTIME_DIR"]
            fixture_bin = scratch / "fixture-bin"
            binary = "ip" if mode == "local_discovery" else "ssh"
            if mode in {"local_discovery", "ssh_inspection", "symlink_profiles", "revocation"}:
                fixture_bin.mkdir()
                (fixture_bin / "offline-fixture").touch()
                source = "offline_probe.py" if binary == "ip" else "offline_ssh.py"
                shutil.copy2(ROOT / "tests" / source, fixture_bin / binary)
                (fixture_bin / binary).chmod(0o700)
                env["PATH"] = str(fixture_bin) + os.pathsep + env["PATH"]
                env["NETWORK_ATLAS_OFFLINE_FIXTURE_DIR"] = str(fixture_bin)
                if mode in {"symlink_profiles", "revocation"}:
                    shutil.copy2(ROOT / "tests" / "offline_probe.py", fixture_bin / "ip")
                    (fixture_bin / "ip").chmod(0o700)
            # Revocation also launches the documented installed config CLI;
            # each native subprocess retains its own bounded timeout.
            timeout = 180 if mode in {"revocation", "native_clone", "native_reset", "native_reset_custom"} else 60
            script = ("native_store_upgrade.py" if mode == "store_upgrade" else
                      "native_profiles.py" if mode in {"native_clone", "native_privacy", "native_reset",
                                                       "native_reset_custom"} else "runtime_smoke.py")
            child = subprocess.run([sys.executable, str(ROOT / "tests" / script), str(root), mode],
                                   env=env, cwd=scratch, capture_output=True, text=True, timeout=timeout)
            self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
            receipt = json.loads(child.stdout.strip().splitlines()[-1])
            self.assertEqual(receipt["mode"], mode)
            if mode in {"valid", "local_discovery", "ssh_inspection", "conversion",
                        "conversion_overlap", "conversion_hardkill", "store_upgrade"}:
                if not mode.startswith("conversion"):
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
                    [sys.executable, str(ROOT / "tests" / script), str(root), reopen_mode],
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

    def test_native_active_scope_admission_and_saved_work_revocation(self):
        self.assertTrue(self.run_smoke("active_scopes")["native_scope_admission"])

    def test_native_status_executable_presence_and_unverified_runtime_without_contact(self):
        self.assertTrue(self.run_smoke("status_availability")["read_only_no_contact"])

    def test_native_disabled_methods_refuse_before_public_opt_in_guidance(self):
        self.assertTrue(self.run_smoke("status_eligibility")["read_only_no_contact"])

    def test_real_native_ssh_inspect_alias_device_slash_cli_failure_and_restart(self):
        self.assertTrue(self.run_smoke("ssh_inspection")["persistent_ssh_batches"])

    def test_native_plugin_remains_disabled_without_explicit_opt_in(self):
        self.assertTrue(self.run_smoke("disabled")["registration_refused"])

    def test_native_conversion_wal_conflicts_interruption_and_cold_retry(self):
        self.assertTrue(self.run_smoke("conversion")["fresh_native_process_persistence"])

    def test_native_operator_upgrade_refusal_rollback_cold_retry_and_endpoint_pause(self):
        self.assertTrue(self.run_smoke("store_upgrade")["fresh_native_process_persistence"])

    def test_native_conversion_writer_overlap_refuses_changed_source_and_stale_cold_retry(self):
        self.assertTrue(self.run_smoke("conversion_overlap")["fresh_native_process_persistence"])

    def test_native_conversion_hardkill_retains_owned_stage_foreign_copies_and_cold_retry(self):
        self.assertTrue(self.run_smoke("conversion_hardkill")["fresh_native_process_persistence"])

    def test_native_clone_converted_binding_sharing_ownership_and_explicit_rebinding(self):
        self.assertTrue(self.run_smoke("native_clone")["native_clone_binding"])

    def test_native_backup_reset_default_custom_and_retained_shared_inventory(self):
        for mode in ("native_reset", "native_reset_custom"):
            with self.subTest(mode=mode):
                self.assertTrue(self.run_smoke(mode)["owned_backup_reset"])

    def test_native_privacy_records_native_directory_and_database_modes(self):
        for mask in (0o022, 0o077):
            with self.subTest(umask=oct(mask)):
                receipt = self.run_smoke("native_privacy", umask=mask)
                self.assertEqual(receipt["umask"], oct(mask))
                self.assertEqual(receipt["directory_modes"], [oct(0o777 & ~mask)] * 2)
                self.assertEqual(receipt["database_mode"], "0o600")

    def test_native_symlinked_data_preserves_profile_identity_and_default_inventory(self):
        for layout in ("plugin-data", "network-atlas"):
            with self.subTest(layout=layout):
                self.assertTrue(self.run_smoke("symlink_profiles", data_layout=layout)["profile_isolation"])

    def test_native_symlinked_conversion_retains_legacy_refusal_history_and_cold_retry(self):
        for layout in ("plugin-data", "network-atlas"):
            with self.subTest(layout=layout):
                self.assertTrue(self.run_smoke("conversion", data_layout=layout)["fresh_native_process_persistence"])

    def test_documented_native_config_cli_replaces_network_ssh_and_empty_policy(self):
        self.assertTrue(self.run_smoke("revocation")["replacement_revocation"])

    def test_native_endpoints_fresh_profiles_shared_physical_store_and_isolated_control(self):
        self.endpoint_profiles('native_endpoints.py')

    def test_native_continuation_producer_cold_owner_shared_reader_and_isolated_control(self):
        self.endpoint_profiles('native_endpoint_continuation.py')

    def endpoint_profiles(self, script):
        root = runtime_root()
        continuation = script == 'native_endpoint_continuation.py'
        with scratch_home() as directory:
            scratch = Path(directory)
            (scratch / 'synthetic-atlas-home').touch()
            shared = scratch / 'shared.sqlite3'
            for mode in (('collect', 'owner', 'reader', 'isolated') if continuation else
                         ('collect', 'reader', 'isolated')):
                home = scratch / ('collect' if mode == 'owner' else mode)
                if mode != 'owner':
                    copy_plugin(home / 'plugins' / 'network-atlas')
                    (home / 'network-atlas').mkdir()
                raw: dict = {} if mode == 'isolated' else {'store': {'shared_sqlite_path': str(shared)}}
                if mode == 'collect':
                    raw['networks'] = {'lab': {'cidr': '192.0.2.0/28' if continuation else '192.168.1.0/24',
                                              'allow_public': True,
                                              'endpoints': {'enabled': True, 'tcp_ports': (
                                                  [22, 2222] if continuation else [22, 2222, 8006, 8384, 22000]),
                                                  'udp_ports': [2222, 22000] if continuation else [21027, 22000]}}}
                    if continuation:
                        raw['limits'] = {'operation_timeout_seconds': 2, 'host_timeout_seconds': 1}
                if mode != 'owner':
                    (home / 'config.yaml').write_text(json.dumps({'plugins': {
                        'enabled': ['network-atlas'], 'entries': {'network-atlas': {'settings': {'policy': raw}}}}}))
                env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(scratch / 'user'),
                       'HERMES_HOME': str(home), 'TMPDIR': str(scratch), 'PYTHONDONTWRITEBYTECODE': '1',
                       'HERMES_BUNDLED_PLUGINS': str(scratch / 'empty-bundled'), 'HERMES_ENABLE_PROJECT_PLUGINS': '0',
                       'HERMES_DISABLE_LAZY_INSTALLS': '1', 'HERMES_MANAGED': 'false',
                       'XDG_CONFIG_HOME': str(scratch / 'xdg-config'), 'XDG_CACHE_HOME': str(scratch / 'xdg-cache'),
                       'XDG_DATA_HOME': str(scratch / 'xdg-data')}
                policy_before = (home / 'config.yaml').read_bytes()
                child = subprocess.run([sys.executable, str(ROOT / 'tests' / script), str(root), mode],
                                       env=env, cwd=scratch, capture_output=True, text=True, timeout=60)
                self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
                self.assertEqual((home / 'config.yaml').read_bytes(), policy_before)
                self.assertTrue(json.loads(child.stdout.strip().splitlines()[-1])['native_dispatch'])

    def test_missing_native_runtime_is_failure_not_skipped_coverage(self):
        with scratch_home() as directory, patch.dict(os.environ, {"NETWORK_ATLAS_HERMES_ROOT": directory}):
            with self.assertRaises(AssertionError):
                self.run_smoke("valid")
