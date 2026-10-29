#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise real Hermes directory discovery/registration/dispatch in an isolated home.

Run only through tests/test_runtime.py: it provides a minimal environment, copies
our native plugin into a scratch home, and refuses any runtime fallback/skip.
No registry, PluginContext, loader, command handler, or config mocks are used.
"""
from __future__ import annotations

import argparse
from contextlib import closing, redirect_stdout
import importlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
from unittest.mock import patch

from helpers import symlink_plugin_data


def _deny_network(event: str, args: tuple) -> None:
    if event in {"socket.connect", "socket.getaddrinfo", "socket.bind"}:
        raise RuntimeError("runtime smoke must remain network-free")


def _database_dump(database: Path) -> list[str]:
    """Read exact fixture history without initializing an absent database."""
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
        return list(connection.iterdump())


def _profile_switch_smoke(home, ctx, dispatch, command, batch_id=None):
    """Re-enter the SAME registered callbacks with real native profile settings."""
    original = dispatch("network_query", {})
    histories = {item["id"]: dispatch("network_query", {"view": "history", "device_id": item["id"]})
                 for item in original["devices"]}
    database = home / "plugin-data" / "network-atlas" / "atlas.sqlite3"
    for name in ("reader", "isolated"):
        current = home.parent / ("switch-" + name)
        layout = os.environ.get("NETWORK_ATLAS_TEST_DATA_LAYOUT")
        if layout is not None:
            symlink_plugin_data(current, layout)
        private_database = current / "plugin-data" / "network-atlas" / "atlas.sqlite3"
        private_before = _database_dump(private_database) if private_database.exists() else None
        shared_before = _database_dump(database)
        raw = {"store": {"shared_sqlite_path": str(database)}} if name == "reader" else {}
        with patch.dict(os.environ, {"HERMES_HOME": str(current)}):
            ctx.set_config("policy", raw)
            assert ctx.get_config("policy", None) == raw
            result = dispatch("network_query", {})
            assert [item["id"] for item in result["devices"]] == (
                [item["id"] for item in original["devices"]] if name == "reader" else [])
            if name == "reader":
                for device, history in histories.items():
                    assert dispatch("network_query", {"view": "history", "device_id": device}) == history
            status = json.loads(command("status"))
            assert status["configured_networks"] == []
            assert status["authorized_for_atlas_ssh_inspection"] == []
            assert status["guidance"]["inspection_targets"]["items"] == []
            assert status["guidance"]["discovery_options"]["items"] == []
            assert status["guidance"]["reconcilable_batches"]["items"] == []
            with patch("subprocess.Popen", side_effect=AssertionError("foreign authority")):
                assert "error" in dispatch("network_inspect", {"target": "lab-router"})
                assert "error" in dispatch("network_discover", {"network": "lab", "mode": "passive"})
                assert "error" in dispatch("network_check_endpoints", {"network": "lab"})
                if batch_id is not None:
                    assert "error" in dispatch("network_reconcile", {"batch_id": batch_id})
            assert _database_dump(database) == shared_before
            assert (_database_dump(private_database) if private_database.exists() else None) == private_before
            exported = dispatch("network_map", {"export": True})
            assert "error" not in exported, exported
            assert {Path(path).name for path in exported["exports"]} == {"network_map.md", "network_map.mmd"}
            assert all(Path(path).is_relative_to(current / "network-atlas" / "exports")
                       for path in exported["exports"])
            for path in exported["exports"]:
                assert Path(path).is_file()
            if name == "reader":
                assert not private_database.exists()
                shared_after = _database_dump(database)
                assert set(shared_before) <= set(shared_after)
                additions = set(shared_after) - set(shared_before)
                assert len(additions) == 2
                assert all(row.startswith('INSERT INTO "audit_events"') for row in additions)
            else:
                # Export is an explicit audited write, unlike query/map reads.
                # It may initialize this isolated DB, but never copy inventory.
                assert _database_dump(database) == shared_before
                with closing(sqlite3.connect(private_database.as_uri() + "?mode=ro", uri=True)) as isolated:
                    tables = isolated.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name!='audit_events'").fetchall()
                    assert all(isolated.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0] == 0
                               for (table,) in tables)
                    assert {row[0] for row in isolated.execute("SELECT action FROM audit_events")} == {
                        "map_export_requested", "map_exported"}
    assert dispatch("network_query", {}) == original
    for device, history in histories.items():
        assert dispatch("network_query", {"view": "history", "device_id": device}) == history


def _registered_cli(manager, argv, code=0):
    """Call the same native parser/handler pair registered by Atlas."""
    entry = manager._cli_commands["network-atlas"]
    parser = argparse.ArgumentParser(allow_abbrev=False)
    entry["setup_fn"](parser)
    output = io.StringIO()
    with redirect_stdout(output):
        result = entry["handler_fn"](parser.parse_args(argv))
    assert result == code, output.getvalue()
    return json.loads(output.getvalue())


def _symlink_profiles_smoke(home, ctx, manager, dispatch, command):
    """Separate actual profile identity from two genuinely relocated data layouts."""
    from hermes_constants import get_hermes_home, set_hermes_home_override, reset_hermes_home_override
    from plugins.plugin_storage import plugin_data_dir

    loaded = next(item for item in manager._plugins.values() if item.manifest.name == "network-atlas")
    config = importlib.import_module(loaded.module.__name__ + ".config")
    raw = ctx.get_config("policy", {})
    database = plugin_data_dir("network-atlas").resolve() / "atlas.sqlite3"
    policy = config.load_policy(ctx)
    assert policy.home == home and policy.database == database
    receipt = dispatch("network_discover", {"network": "lab", "mode": "passive"})
    assert receipt["completion"] == "complete", receipt
    assert "error" not in dispatch("network_reconcile", {"batch_id": receipt["batch_id"]})
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
        assert {row[0] for row in connection.execute("SELECT DISTINCT policy_context FROM batches")} == {str(home)}
    _profile_switch_smoke(home, ctx, dispatch, command, receipt["batch_id"])
    original = dispatch("network_query", {})
    assert original["devices"], "the first profile must have inventory to distinguish isolation"
    exported = _registered_cli(manager, ["map", "--export"])
    assert len(exported["exports"]) == 2
    assert all(Path(path).is_file() and Path(path).is_relative_to(home / "network-atlas" / "exports")
               for path in exported["exports"])
    before = _database_dump(database)
    other = home.parent / "symlink-other"
    other_data = symlink_plugin_data(other, os.environ["NETWORK_ATLAS_TEST_DATA_LAYOUT"])
    # Native context-local routing must win even while the process env remains A.
    token = set_hermes_home_override(other)
    try:
        assert get_hermes_home().resolve() == other and Path(os.environ["HERMES_HOME"]) == home
        ctx.set_config("policy", raw)
        policy = config.load_policy(ctx)
        assert policy.home == other
        assert policy.database == plugin_data_dir("network-atlas").resolve() / "atlas.sqlite3"
        assert policy.database == other_data / "atlas.sqlite3" and policy.database != database
        assert dispatch("network_query", {})["devices"] == []
        device = _registered_cli(manager, ["create", "--name", "Separate profile inventory"])["device_id"]
        assert [row["id"] for row in dispatch("network_query", {})["devices"]] == [device]
        batch = dispatch("network_discover", {"network": "lab", "mode": "passive"})
        assert batch["completion"] == "complete", batch
        with closing(sqlite3.connect(policy.database.as_uri() + "?mode=ro", uri=True)) as connection:
            assert {row[0] for row in connection.execute("SELECT DISTINCT policy_context FROM batches")} == {str(other)}
        exported = dispatch("network_map", {"export": True})
        assert "error" not in exported, exported
        assert len(exported["exports"]) == 2
        assert all(Path(path).is_file() and Path(path).is_relative_to(other / "network-atlas" / "exports")
                   for path in exported["exports"])
        assert _database_dump(database) == before
    finally:
        reset_hermes_home_override(token)
    assert dispatch("network_query", {}) == original
    assert _database_dump(database) == before
    manager.unload()
    print(json.dumps({"mode": "symlink_profiles", "profile_isolation": True}))
    return 0


def _policy_revocation_smoke(home, ctx, manager, dispatch, command):
    """Replace real native policy via the documented CLI, then use registered consumers."""
    hermes = shutil.which("hermes")
    assert hermes is not None, "installed stock Hermes CLI required"
    retained = ctx.get_config("policy", {})
    expanded = json.loads(json.dumps(retained))
    expanded["networks"]["removed"] = {"cidr": "198.51.100.0/24", "discovery": {"passive": True}}
    expanded["ssh"]["hosts"]["removed-host"] = {"alias": "removed-router", "inspect": True}

    def replace_policy(raw):
        result = subprocess.run([hermes, "-p", "default", "config", "set",
                                 "plugins.entries.network-atlas.settings.policy", json.dumps(raw)],
                                cwd=home.parent, env=os.environ.copy(), input="", capture_output=True,
                                text=True, timeout=45)
        assert result.returncode == 0, result.stdout + result.stderr
        assert ctx.get_config("policy", None) == raw

    def refuse(network, alias):
        database = home / "plugin-data" / "network-atlas" / "atlas.sqlite3"
        before = _database_dump(database) if database.exists() else None
        with patch("subprocess.Popen", side_effect=AssertionError("revoked grant attempted transport")) as transport:
            for result in (
                dispatch("network_discover", {"network": network, "mode": "passive"}),
                json.loads(command("discover " + network + " passive")),
                _registered_cli(manager, ["discover", "--network", network, "--mode", "passive"], 2),
                dispatch("network_inspect", {"target": alias}),
                json.loads(command("inspect " + alias)),
                _registered_cli(manager, ["inspect", "--target", alias], 2),
            ):
                assert "error" in result and not result["applied"] and not result["persisted"], result
            transport.assert_not_called()
        assert (_database_dump(database) if database.exists() else None) == before

    replace_policy(expanded)
    status = json.loads(command("status"))
    assert status["configured_networks"] == ["lab", "removed"]
    assert status["authorized_for_atlas_ssh_inspection"] == ["lab-router", "removed-router"]
    replace_policy(retained)
    status = _registered_cli(manager, ["status"])
    assert status["configured_networks"] == ["lab"]
    assert status["authorized_for_atlas_ssh_inspection"] == ["lab-router"]
    refuse("removed", "removed-router")
    # Retained permissions still reach real code through offline-only executables.
    discovery = dispatch("network_discover", {"network": "lab", "mode": "passive"})
    inspection = json.loads(command("inspect lab-router"))
    for receipt in (discovery, inspection):
        assert receipt["completion"] == "complete" and receipt["persisted"], receipt
        assert "error" not in _registered_cli(manager, ["reconcile", "--batch-id", receipt["batch_id"]])
    replace_policy({})
    status = json.loads(command("status"))
    assert status["configured_networks"] == []
    assert status["authorized_for_atlas_ssh_inspection"] == []
    refuse("lab", "lab-router")
    assert dispatch("network_query", {})["devices"], "revocation must retain collected knowledge"
    manager.unload()
    print(json.dumps({"mode": "revocation", "replacement_revocation": True}))
    return 0


def _inspection_smoke(mode, home, manager, dispatch, command):
    database = home / "plugin-data" / "network-atlas" / "atlas.sqlite3"
    entry = manager._cli_commands["network-atlas"]
    parser = argparse.ArgumentParser(allow_abbrev=False)
    entry["setup_fn"](parser)
    def cli(argv):
        output = io.StringIO()
        with redirect_stdout(output):
            assert entry["handler_fn"](parser.parse_args(argv)) == 0
        return json.loads(output.getvalue())
    saved = home.parent / "phase3-receipt.json"
    if mode == "ssh_inspection":
        policy_before = (home / "config.yaml").read_bytes()
        with patch("subprocess.Popen", side_effect=AssertionError("read attempted collection")) as transport:
            empty = dispatch("network_query", {"view": "status"})
            assert empty["known_devices"] == 0 and empty["guidance"]["inventory_state"] == "empty"
            assert empty["guidance"]["local_collection_state"] == "none"
            assert empty["guidance"]["inspection_targets"]["items"] == [
                {"tool": "network_inspect", "parameters": {"target": "lab-router"}}]
            assert dispatch("network_query", {})["devices"] == []
            assert "error" not in dispatch("network_map", {})
            transport.assert_not_called()
        assert not database.exists() and (home / "config.yaml").read_bytes() == policy_before
        receipt = dispatch("network_inspect", {"target": "lab-router"}, command="id", source="user")
        assert receipt["completion"] == "complete" and not receipt["applied"], receipt
        collected = _database_dump(database)
        with patch("subprocess.Popen", side_effect=AssertionError("read attempted collection")) as transport:
            pending = dispatch("network_query", {"view": "status"})["guidance"]
            assert pending["local_collection_state"] == "recorded"
            assert pending["unapplied_local_batches"] == 1
            assert pending["reconcilable_batches"]["items"] == [
                {"tool": "network_reconcile", "parameters": {"batch_id": receipt["batch_id"]}}]
            assert dispatch("network_query", {})["devices"] == []
            assert "error" not in dispatch("network_map", {})
            transport.assert_not_called()
        assert _database_dump(database) == collected
        result = dispatch("network_reconcile", {"batch_id": receipt["batch_id"]})
        assert len(result["new"]) == 1 and not result["missing"], result
        device = result["new"][0]
        applied = _database_dump(database)
        with patch("subprocess.Popen", side_effect=AssertionError("read attempted collection")) as transport:
            detail = dispatch("network_query", {"device_id": device})["devices"][0]
            assert detail["fields"]["hostname"]["value"] == "fixture-ssh-host"
            assert detail["fields"]["os"]["value"] == "Synthetic Fixture Linux"
            interface = detail["interfaces"][0]
            assert len(detail["interfaces"]) == 1
            assert interface["fields"]["name"]["value"] == "ssh0"
            assert interface["mac_address"] == "00:11:22:33:44:77"
            assert {a["address"] for a in interface["addresses"]} == {"198.51.100.7"}
            assert all(a["batch_id"] == receipt["batch_id"] for a in interface["addresses"])
            assert detail["relationships"] == []
            evidence = detail["fields"]["os"]["evidence"]
            assert evidence and all(e["source"] == "ssh:lab-router" and e["confidence"] == "observed"
                                    and e["evidence_kind"] == "ssh_response" and e["qualified"] for e in evidence)
            guidance = dispatch("network_query", {"view": "status"})["guidance"]
            assert guidance["inventory_state"] == "recorded" and guidance["devices_without_relationships"] == 1
            assert guidance["reconcilable_batches"]["total_count"] == 0
            topology = dispatch("network_map", {"format": "text"})
            assert "fixture-ssh-host [" in topology["content"] and "198.51.100.7" in topology["content"]
            assert "canonical_name" not in detail["fields"]
            markdown = dispatch("network_map", {"format": "markdown"})["content"]
            assert f"| fixture-ssh-host ({device}) |" in markdown
            mermaid = dispatch("network_map", {"format": "mermaid"})["content"]
            assert 'n' + device.replace("-", "") + '["fixture#45;ssh#45;host #91;' in mermaid
            assert not topology["discovery_performed"] and not topology["exports"]
            transport.assert_not_called()
        assert _database_dump(database) == applied and (home / "config.yaml").read_bytes() == policy_before
        for receipt in (json.loads(command("inspect " + device)), cli(["inspect", "--target", "lab-router"])):
            assert receipt["completion"] == "complete", receipt
            assert not dispatch("network_reconcile", {"batch_id": receipt["batch_id"]})["new"]
        for key in ("command", "probe", "flags", "source", "hostname", "port", "username", "limits"):
            assert "error" in dispatch("network_inspect", {"target": "lab-router", key: "bad"})
        assert "error" in dispatch("network_inspect", {"target": "-oProxyCommand=id"})
        before = dispatch("network_query", {"device_id": device})["devices"][0]
        fixture = Path(os.environ["NETWORK_ATLAS_OFFLINE_FIXTURE_DIR"])
        (fixture / "ssh-outcome").write_text("synthetic-host-key-refusal")
        failed = dispatch("network_inspect", {"target": device})
        assert failed["completion"] == "failed", failed
        assert {p["outcome"] for p in failed["probes"]} == {"command_failed"}, failed
        assert not dispatch("network_query", {"view": "status"})["last_inspection"]["succeeded"]
        failed_result = dispatch("network_reconcile", {"batch_id": failed["batch_id"]})
        after = dispatch("network_query", {"device_id": device})["devices"][0]
        assert after["last_seen"] == before["last_seen"] and after["fields"] == before["fields"]
        assert "SECRET_FIXTURE_DIAGNOSTIC" not in json.dumps(after)
        assert dispatch("network_query", {"access_method": "ssh"})["devices"][0]["id"] == device
        content = dispatch("network_map", {"format": "text"})["content"]
        saved.write_text(json.dumps({"result": failed_result, "device": device, "content": content}))
    data = json.loads(saved.read_text())
    assert dispatch("network_reconcile", {"batch_id": data["result"]["batch_id"]}) == data["result"]
    detail = dispatch("network_query", {"device_id": data["device"]})["devices"][0]
    assert detail["fields"]["hostname"]["value"] == "fixture-ssh-host"
    assert detail["fields"]["os"]["value"] == "Synthetic Fixture Linux"
    assert len(detail["interfaces"]) == 1
    assert detail["interfaces"][0]["addresses"][0]["address"] == "198.51.100.7"
    assert detail["access"][0]["authorized_for_atlas_ssh_inspection"]
    assert not detail["access"][0]["last_inspection"]["succeeded"]
    assert dispatch("network_map", {"format": "text"})["content"] == data["content"]
    assert {row["source"] for row in dispatch(
        "network_query", {"view": "history", "device_id": detail["id"]})["observations"]} == {"ssh:lab-router"}
    from hermes_cli.plugins import PluginContext
    loaded = next(item for item in manager._plugins.values() if item.manifest.name == "network-atlas")
    _profile_switch_smoke(home, PluginContext(loaded.manifest, manager), dispatch, command,
                          data["result"]["batch_id"])
    if mode == "ssh_inspection_reopen":
        # One qualified mapping remains usable at the minimum result limit;
        # a second mapping must omit the suggestion, not break status.
        ctx = PluginContext(loaded.manifest, manager)
        policy = ctx.get_config("policy", {})
        ctx.set_config("policy", {**policy, "limits": {**policy.get("limits", {}), "result_count": 1}})
        policy_before = (home / "config.yaml").read_bytes()
        snapshot = _database_dump(database)
        with patch("subprocess.Popen", side_effect=AssertionError("status attempted transport")) as transport:
            status = dispatch("network_query", {"view": "status"})
            assert status["last_collection"]["probe_summary"]["detail_limit"] == 1
            assert status["guidance"]["inspection_targets"] == {
                "items": [{"tool": "network_inspect", "parameters": {"target": "lab-router"}}],
                "total_count": 1, "omitted_count": 0}
            transport.assert_not_called()
        assert _database_dump(database) == snapshot
        other = cli(["create", "--name", "Conflicting fixture"])["device_id"]
        cli(["update", "--device-id", other, "--field", "ssh_alias", "--value-json", '"lab-router"'])
        snapshot = _database_dump(database)
        with patch("subprocess.Popen", side_effect=AssertionError("ambiguous transport")) as transport:
            status = dispatch("network_query", {"view": "status"})
            assert "error" not in status and status["known_devices"] == 2, status
            assert status["guidance"]["inspection_targets"] == {"items": [], "total_count": 0, "omitted_count": 0}
            for target in ("lab-router", data["device"], other):
                assert "error" in dispatch("network_inspect", {"target": target})
            transport.assert_not_called()
        assert _database_dump(database) == snapshot and (home / "config.yaml").read_bytes() == policy_before
    manager.unload()
    print(json.dumps({"mode": mode, "native_discovery": True, "real_dispatch": True,
                      "persistent_ssh_batches": True, "fresh_native_process_persistence": True}))
    return 0


def main() -> int:
    home = Path(os.environ["HERMES_HOME"]).resolve()
    scratch = Path(os.environ["TMPDIR"]).resolve()
    if not home.is_relative_to(scratch) or not (home.parent / "synthetic-atlas-home").is_file():
        raise RuntimeError("refusing non-fixture Hermes home")
    root = Path(sys.argv[1]).resolve()
    mode = sys.argv[2]
    if not (root / "hermes_cli" / "plugins.py").is_file():
        raise RuntimeError("real Hermes plugin runtime required")
    sys.path.insert(0, str(root))
    sys.addaudithook(_deny_network)
    if mode == "active_scopes":
        from native_active_scopes import run
        return run(home, root)
    if mode in {"status_availability", "status_eligibility"}:
        from native_status import run
        return run(home, root, mode)
    # This uses installed native plugin APIs directly; not hermes_bootstrap/PM,
    # so it cannot activate/repair/install a dependency generation as a side effect.
    from hermes_constants import get_hermes_home
    from hermes_cli.plugins import discover_plugins, get_plugin_manager, get_plugin_command_handler
    from tools.registry import registry

    assert get_hermes_home().resolve() == home
    discover_plugins()
    manager = get_plugin_manager()
    def dispatch(name: str, params: dict, **kwargs) -> dict:
        result = registry.dispatch(name, params, scope=manager.scope_key, **kwargs)
        assert isinstance(result, str), result
        return json.loads(result)

    plugin = next(item for item in manager.list_plugins() if item["name"] == "network-atlas")
    if mode == "disabled":
        assert not plugin["enabled"], plugin
        for name in ("network_query", "network_update", "network_map", "network_discover", "network_reconcile",
                     "network_inspect", "network_check_endpoints"):
            assert registry.get_entry(name, scope=manager.scope_key) is None
        assert get_plugin_command_handler("network") is None
        assert "network-atlas" not in manager._cli_commands
        print(json.dumps({"mode": mode, "registration_refused": True}))
        return 0

    assert plugin["enabled"] and not plugin["error"], plugin
    from hermes_cli.plugins import PluginContext
    loaded = next(item for item in manager._plugins.values() if item.manifest.name == "network-atlas")
    ctx = PluginContext(loaded.manifest, manager)
    if mode == "symlink_profiles":
        return _symlink_profiles_smoke(home, ctx, manager, dispatch, get_plugin_command_handler("network"))
    if mode == "revocation":
        return _policy_revocation_smoke(home, ctx, manager, dispatch, get_plugin_command_handler("network"))
    if mode in {"conversion", "conversion_reopen", "conversion_overlap", "conversion_overlap_reopen",
                "conversion_hardkill", "conversion_hardkill_reopen", "conversion_kill_child"}:
        from native_conversion import run_conversion
        return run_conversion(mode, home, manager)
    if mode == "invalid":
        for name in ("network_query", "network_update", "network_map", "network_discover", "network_reconcile",
                     "network_inspect", "network_check_endpoints"):
            assert "policy:" in dispatch(name, {})["error"]
        assert get_plugin_command_handler("network") is not None
        assert "network-atlas" in manager._cli_commands
        print(json.dumps({"mode": mode, "actions_refused": True}))
        return 0
    definitions = registry.get_definitions({"network_query", "network_update", "network_map", "network_discover",
                                            "network_reconcile", "network_inspect", "network_check_endpoints"})
    assert len(definitions) == 7, definitions
    for definition in definitions:
        assert definition["function"]["parameters"]["additionalProperties"] is False
        assert "source" not in definition["function"]["parameters"]["properties"]
        if definition["function"]["name"] == "network_query":
            properties = definition["function"]["parameters"]["properties"]
            assert "unresolved" in properties["view"]["enum"] and "batch_id" in properties
    if mode in {"ssh_inspection", "ssh_inspection_reopen"}:
        return _inspection_smoke(mode, home, manager, dispatch, get_plugin_command_handler("network"))
    if mode in {"local_discovery", "local_discovery_reopen"}:
        command = get_plugin_command_handler("network")
        assert command is not None
        if mode == "local_discovery":
            receipt = dispatch("network_discover", {"network": "lab", "mode": "passive"})
            assert receipt["completion"] == "complete" and receipt["persisted"] and not receipt["applied"], receipt
            result = dispatch("network_reconcile", {"batch_id": receipt["batch_id"]})
            assert len(result["new"]) == 2 and not result["missing"], result
            assert dispatch("network_reconcile", {"batch_id": receipt["batch_id"]}) == result
            assert json.loads(command("reconcile " + receipt["batch_id"])) == result
            entry = manager._cli_commands["network-atlas"]
            parser = argparse.ArgumentParser(allow_abbrev=False)
            entry["setup_fn"](parser)
            output = io.StringIO()
            with redirect_stdout(output):
                assert entry["handler_fn"](parser.parse_args([
                    "discover", "--network", "lab", "--mode", "passive"])) == 0
            cli_batch = json.loads(output.getvalue())["batch_id"]
            output = io.StringIO()
            with redirect_stdout(output):
                assert entry["handler_fn"](parser.parse_args(["reconcile", "--batch-id", cli_batch])) == 0
            cli_result = json.loads(output.getvalue())
            assert not cli_result["new"] and len(cli_result["unchanged"]) == 2, cli_result
            for key in ("command", "flags", "source", "target", "limits"):
                assert "error" in dispatch("network_discover", {"network": "lab", "mode": "passive", key: "bad"})
                assert "error" in dispatch("network_reconcile", {"batch_id": receipt["batch_id"], key: "bad"})
            (home.parent / "phase2-receipt.json").write_text(json.dumps(result))
        else:
            result = json.loads((home.parent / "phase2-receipt.json").read_text())
            assert dispatch("network_reconcile", {"batch_id": result["batch_id"]}) == result
        devices = dispatch("network_query", {})["devices"]
        assert len(devices) == 2
        assert {device["status"] for device in devices} == {"observed", "known"}
        assert "cached_neighbor" in json.dumps(devices)
        assert "observed" in dispatch("network_map", {"format": "text"})["content"]
        _profile_switch_smoke(home, ctx, dispatch, command, result["batch_id"])
        manager.unload()
        print(json.dumps({"mode": mode, "native_discovery": True, "real_dispatch": True,
                          "persistent_batches": True, "fresh_native_process_persistence": True}))
        return 0
    if mode == "reopen":
        devices = dispatch("network_query", {})["devices"]
        assert len(devices) == 1 and devices[0]["status"] == "retired"
        history = dispatch("network_query", {"view": "history", "device_id": devices[0]["id"]})
        assert {item["confidence"] for item in history["observations"]} == {"inferred", "user_supplied"}
        topology = dispatch("network_map", {"format": "mermaid"})
        assert topology["content"] == (home / "network-atlas" / "exports" / "network_map.mmd").read_text()
        assert not topology["exports"]
        manager.unload()
        print(json.dumps({"mode": mode, "fresh_native_process_persistence": True, "discovery_performed": False}))
        return 0
    query = dispatch("network_query", {"view": "status"})
    assert query["stage"] == "v1"
    assert query["authorized_for_atlas_ssh_inspection"] == ["lab-router"]
    assert query["last_inspection"] is None
    entry = manager._cli_commands["network-atlas"]
    parser = argparse.ArgumentParser(allow_abbrev=False)
    entry["setup_fn"](parser)
    def cli(argv):
        output = io.StringIO()
        with redirect_stdout(output):
            assert entry["handler_fn"](parser.parse_args(argv)) == 0
        return json.loads(output.getvalue())
    device = cli(["create", "--name", "Synthetic native router"])["device_id"]
    params = {"device_id": device, "field": "description", "value": "Synthetic fixture",
              "explanation": "fixture inference"}
    inference = dispatch("network_update", params, source="user", operator=True)
    assert inference["update"]["source"] == "inference" and inference["applied"] and inference["persisted"]
    for key in ("source", "command", "permissions", "attestation"):
        bad = dispatch("network_update", {**params, key: "user"})
        assert "error" in bad and not bad["applied"]
    command = get_plugin_command_handler("network")
    assert command is not None
    assert json.loads(command("status"))["known_devices"] == 1
    assert json.loads(command("show " + device))["devices"][0]["id"] == device
    assert "error" in json.loads(command('update {"source":"user"}'))
    operator = cli(["update", "--device-id", device, "--field", "retired", "--value-json", "true"])
    assert operator["update"]["source"] == "user" and operator["update"]["confidence"] == "user_supplied"
    assert operator["applied"] and operator["persisted"]
    assert (home / "plugin-data" / "network-atlas" / "atlas.sqlite3").exists()
    topology = dispatch("network_map", {"format": "mermaid", "export": True})
    assert "retired" in topology["content"]
    assert [Path(path).name for path in topology["exports"]] == ["network_map.md", "network_map.mmd"]
    assert cli(["query"])["devices"][0]["id"] == device
    assert "retired" in json.loads(command("map"))["content"]
    _profile_switch_smoke(home, ctx, dispatch, command)
    # Hermes may retain last-known-good settings after malformed root YAML. Atlas
    # follows that native result, rather than inventing a stronger reload veto.
    saved = (home / "config.yaml").read_bytes()
    good = ctx.get_config("policy", {})
    try:
        (home / "config.yaml").write_text("plugins: [")
        assert ctx.get_config("policy", {}) == good
        assert dispatch("network_query", {"view": "status"})["authorized_for_atlas_ssh_inspection"] == ["lab-router"]
    finally:
        (home / "config.yaml").write_bytes(saved)
    # Use the real native writer, not an Atlas root-YAML reload contract.
    ctx.set_config("policy", {"ssh": {"enabled": True, "command": "bad"}})
    assert "error" in dispatch("network_query", {"view": "status"})
    assert "error" in dispatch("network_update", params)
    manager.unload()
    assert registry.get_entry("network_query", scope=manager.scope_key) is None
    print(json.dumps({"mode": mode, "native_discovery": True, "real_dispatch": True,
                      "operator_cli_source": "user", "tool_source": "inference", "persistent_core": True,
                      "third_party_imports": sorted({name.split(".")[0] for name, module in sys.modules.items()
                          if "site-packages" in str(getattr(module, "__file__", ""))})}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
