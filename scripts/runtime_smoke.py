#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise real Hermes directory discovery/registration/dispatch in an isolated home.

Run only through tests/test_runtime.py: it provides a minimal environment, copies
our native plugin into a scratch home, and refuses any runtime fallback/skip.
No registry, PluginContext, loader, command handler, or config mocks are used.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys


def _deny_network(event: str, args: tuple) -> None:
    if event in {"socket.connect", "socket.getaddrinfo", "socket.bind"}:
        raise RuntimeError("runtime smoke must remain network-free")


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
    if mode in {"invalid", "disabled"}:
        assert not plugin["enabled"], plugin
        if mode == "invalid":
            assert plugin["error"], plugin
        for name in ("network_query", "network_update", "network_map", "network_discover", "network_reconcile"):
            assert registry.get_entry(name, scope=manager.scope_key) is None
        assert get_plugin_command_handler("network") is None
        assert "network-atlas" not in manager._cli_commands
        print(json.dumps({"mode": mode, "registration_refused": True}))
        return 0

    assert plugin["enabled"] and not plugin["error"], plugin
    for unavailable in ("network_inspect",):
        assert registry.get_entry(unavailable, scope=manager.scope_key) is None
    definitions = registry.get_definitions({"network_query", "network_update", "network_map", "network_discover", "network_reconcile"})
    assert len(definitions) == 5, definitions
    for definition in definitions:
        assert definition["function"]["parameters"]["additionalProperties"] is False
        assert "source" not in definition["function"]["parameters"]["properties"]
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
                assert entry["handler_fn"](parser.parse_args(["discover", "--network", "lab", "--mode", "passive"])) == 0
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
    assert query["stage"] == "local_discovery"
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
    assert (home / "network-atlas" / "atlas.sqlite3").exists()
    topology = dispatch("network_map", {"format": "mermaid", "export": True})
    assert "retired" in topology["content"]
    assert [Path(path).name for path in topology["exports"]] == ["network_map.md", "network_map.mmd"]
    assert cli(["query"])["devices"][0]["id"] == device
    assert "retired" in json.loads(command("map"))["content"]
    # Re-check policy after registration: a now-invalid policy cannot use old grants.
    (home / "network-atlas" / "config.yaml").write_text("ssh: {enabled: true, command: bad}", encoding="utf-8")
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
