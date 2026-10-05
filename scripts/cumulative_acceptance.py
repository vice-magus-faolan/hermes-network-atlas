#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Cumulative fixture workflow through actual native discovery/dispatch, never a chat simulation."""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sqlite3
import sys

from acceptance_support import contained
from offline_guard import deny_network


class NativeAtlas:
    """Small adapter to REAL registered APIs; no loader, core or consent mocks."""
    def __init__(self, source: Path):
        sys.path.insert(0, str(source))
        from pm.environments import selected_venv
        assert Path(sys.prefix).resolve() == selected_venv(source).resolve()
        from hermes_cli.plugins import discover_plugins, get_plugin_manager, get_plugin_command_handler
        from tools.registry import registry
        discover_plugins()
        self.manager = get_plugin_manager()
        self.registry = registry
        self.command = get_plugin_command_handler("network")
        assert self.command is not None
        plugin = next(item for item in self.manager.list_plugins() if item["name"] == "network-atlas")
        assert plugin["enabled"] and not plugin["error"], plugin
        self.entry = self.manager._cli_commands["network-atlas"]
        self.parser = argparse.ArgumentParser(allow_abbrev=False)
        self.entry["setup_fn"](self.parser)
        names = {"network_query", "network_update", "network_map", "network_discover", "network_inspect", "network_reconcile"}
        definitions = self.registry.get_definitions(names)
        assert {d["function"]["name"] for d in definitions} == names
        for definition in definitions:
            assert definition["function"]["parameters"]["additionalProperties"] is False
        assert plugin["source"] == "user" and plugin["hooks"] == 0, plugin

    def tool(self, name: str, params: dict) -> dict:
        result = self.registry.dispatch(name, params, scope=self.manager.scope_key)
        assert isinstance(result, str), result
        return json.loads(result)

    def slash(self, text: str) -> dict:
        assert self.command is not None
        return json.loads(self.command(text))

    def cli(self, argv: list[str]) -> dict:
        output = io.StringIO()
        with redirect_stdout(output):
            code = self.entry["handler_fn"](self.parser.parse_args(argv))
        result = json.loads(output.getvalue())
        assert code == 0, result
        return result

    def update(self, device: str, field: str, value: object) -> dict:
        result = self.cli(["update", "--device-id", device, "--field", field, "--value-json", json.dumps(value)])
        assert result["update"]["confidence"] == "user_supplied", result
        return result


def counts(home: Path) -> dict:
    database = home / "network-atlas" / "atlas.sqlite3"
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        return {name: connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in
                ("devices", "interfaces", "observations", "batches", "applications", "audit_events", "access_evidence")}


def collect(atlas: NativeAtlas, root: Path) -> dict:
    """Two scope-complete synthetic scans; exactly three authorized SSH aliases."""
    status = atlas.slash("status")
    assert status["known_devices"] == 0 and status["last_discovery"] is None, status
    passive = atlas.slash("discover lab passive")
    assert passive["completion"] == "complete" and not passive["applied"], passive
    assert not atlas.tool("network_reconcile", {"batch_id": passive["batch_id"]})["new"]
    first = atlas.tool("network_discover", {"network": "lab", "mode": "ping"})
    assert first["completion"] == "complete" and not first["applied"], first
    assert not atlas.tool("network_query", {})["devices"]
    original = atlas.tool("network_query", {"view": "unresolved", "batch_id": first["batch_id"]})
    assert len(original["evidence"]) == 5 and not original["has_more"], original
    assert {row["identity_state"] for row in original["evidence"]} == {"never_reconciled"}
    assert all(row["historical_responder_evidence"] for row in original["evidence"])
    initial = atlas.slash("reconcile " + first["batch_id"])
    assert len(initial["new"]) == 4 and initial["unresolved"] and not initial["missing"], initial
    assert atlas.tool("network_reconcile", {"batch_id": first["batch_id"]}) == initial
    unidentified = atlas.cli(["query", "--query-json", json.dumps({"view": "unresolved", "address": "192.0.2.4"})])
    assert len(unidentified["evidence"]) == 1 and unidentified["evidence"][0]["identity_state"] == "reconciled_unresolved"
    assert unidentified["evidence"][0]["identity_reason"] == "no_unique_stable_interface"
    ids = {}
    for number, alias in enumerate(("lab-a", "lab-b", "lab-c"), 1):
        device = atlas.tool("network_query", {"address": f"192.0.2.{number}"})["devices"][0]["id"]
        ids[alias] = device
        atlas.update(device, "ssh_alias", alias)
        receipt = atlas.slash("inspect " + device) if alias == "lab-b" else atlas.tool("network_inspect", {"target": alias})
        assert receipt["completion"] == "complete", receipt
        result = atlas.cli(["reconcile", "--batch-id", receipt["batch_id"]])
        assert not result["new"] and not result["missing"], result
    queried = atlas.tool("network_query", {"access_method": "ssh"})
    assert {row["id"] for row in queried["devices"]} == set(ids.values()) and not queried["has_more"]
    assert all(row["access"][0]["last_inspection"]["succeeded"] for row in queried["devices"])
    assert not atlas.tool("network_query", {"address": "198.51.100.99"})["devices"]
    (root / "fixture-bin" / "stage").write_text("changed")
    second = atlas.cli(["discover", "--network", "lab", "--mode", "ping"])
    change = atlas.tool("network_reconcile", {"batch_id": second["batch_id"]})
    assert change["new"] and ids["lab-a"] in change["changed"] and change["conflicting"] and change["unresolved"], change
    assert {row["meaning"] for row in change["missing"]} == {"not_observed_in_this_run"}, change
    assert ids["lab-c"] in {row["device_id"] for row in change["missing"]}, change
    return {"ids": ids, "initial": initial, "change": change}


def sources_and_failure(atlas: NativeAtlas, root: Path, data: dict) -> None:
    device = data["ids"]["lab-a"]
    atlas.update(device, "canonical_name", 'Fixture "] --> Evil["<script>|')
    atlas.update(device, "description", "Operator assertion")
    inference = atlas.tool("network_update", {"device_id": device, "field": "description", "value": "Inference assertion",
                                            "explanation": "Synthetic fixture proposal"})
    assert inference["update"]["confidence"] == "inferred", inference
    history = atlas.tool("network_query", {"view": "history", "device_id": device})
    assert {row["confidence"] for row in history["observations"]} == {"observed", "inferred", "user_supplied"}, history
    assert not history["has_more"], history
    detail = atlas.slash("show " + device)["devices"][0]
    assert detail["fields"]["description"]["value"] == "Operator assertion", detail
    before = detail["last_seen"]
    (root / "fixture-bin" / "stage").write_text("refused")
    refused = atlas.cli(["inspect", "--target", "lab-a"])
    assert refused["completion"] == "failed", refused
    failed = atlas.tool("network_reconcile", {"batch_id": refused["batch_id"]})
    assert not failed["missing"], failed
    after = atlas.slash("show " + device)["devices"][0]
    assert before == after["last_seen"] and after["fields"] == detail["fields"]
    assert not after["access"][0]["last_inspection"]["succeeded"]
    assert "SECRET_FIXTURE_DIAGNOSTIC" not in json.dumps(after)
    atlas.update(device, "relationship", {"target_device": data["ids"]["lab-b"], "relationship_type": "hosted_on"})


def negatives(atlas: NativeAtlas, home: Path, root: Path) -> None:
    before = counts(home)
    calls = (root / "fixture-bin" / "calls.jsonl").read_bytes()
    attempts = [("network_inspect", {"target": "lab-a", "command": "id"}),
                ("network_inspect", {"target": "-oProxyCommand=id"}),
                ("network_inspect", {"target": "192.0.2.1"}),
                ("network_inspect", {"target": "lab-denied"}),
                ("network_discover", {"network": "198.51.100.0/24", "mode": "ping"}),
                ("network_discover", {"network": "lab", "mode": "ping", "flags": "-sV"}),
                ("network_update", {"source": "user"}),
                ("network_query", {"view": "unresolved", "address": "192.0.2.0/29"}),
                ("network_query", {"view": "unresolved", "batch_id": "../atlas.sqlite3"}),
                ("network_query", {"view": "unresolved", "command": "id"})]
    for name, params in attempts:
        assert "error" in atlas.tool(name, params), (name, params)
    assert "error" in atlas.slash('update {"source":"user"}')
    assert before == counts(home) and calls == (root / "fixture-bin" / "calls.jsonl").read_bytes()


def snapshot(atlas: NativeAtlas, home: Path) -> dict:
    devices = atlas.tool("network_query", {})
    assert not devices["has_more"] and devices["discovery_performed"] is False
    histories = {row["id"]: atlas.tool("network_query", {"view": "history", "device_id": row["id"]}) for row in devices["devices"]}
    maps = {kind: atlas.tool("network_map", {"format": kind}) for kind in ("text", "markdown", "mermaid")}
    assert maps["mermaid"]["content"].count(" -->|") == 1
    assert '<script>' not in maps["markdown"]["content"] and 'Evil["' not in maps["mermaid"]["content"]
    assert "isolated" in maps["text"]["content"]
    assert atlas.slash("map mermaid")["content"] == maps["mermaid"]["content"]
    assert all(not result["exports"] for result in maps.values())
    unresolved = atlas.tool("network_query", {"view": "unresolved", "address": "192.0.2.4"})
    assert len(unresolved["evidence"]) == 2 and not unresolved["has_more"], unresolved
    assert all(row["identity_reason"] == "no_unique_stable_interface" for row in unresolved["evidence"])
    originals = atlas.tool("network_query", {"view": "unresolved", "address": "192.0.2.1"})
    assert originals["evidence"] and any(row["identity_state"] == "subsequently_resolved" for row in originals["evidence"])
    return {"devices": devices, "histories": histories, "maps": maps,
            "unresolved": unresolved, "original_evidence": originals,
            "ssh": atlas.tool("network_query", {"access_method": "ssh"}), "status": atlas.slash("status"), "counts": counts(home)}


def main() -> int:
    root = Path(os.environ["TMPDIR"]).resolve()
    if not (root / "synthetic-atlas-home").is_file():
        raise ValueError("synthetic scratch fixture required")
    home = contained(root, os.environ["HERMES_HOME"])
    source = contained(root, sys.argv[1])
    deny_network()
    atlas = NativeAtlas(source)
    mode = sys.argv[2]
    saved = root / "cumulative.json"
    if mode == "collect":
        data = collect(atlas, root)
        sources_and_failure(atlas, root, data)
        negatives(atlas, home, root)
        exported = atlas.tool("network_map", {"format": "mermaid", "export": True})
        assert {Path(path).name for path in exported["exports"]} == {"network_map.md", "network_map.mmd"}
        data["snapshot"] = snapshot(atlas, home)
        saved.write_text(json.dumps(data, sort_keys=True))
    elif mode == "reopen":
        data = json.loads(saved.read_text())
        before = counts(home)
        assert atlas.tool("network_reconcile", {"batch_id": data["change"]["batch_id"]}) == data["change"]
        assert snapshot(atlas, home) == data["snapshot"]
        assert counts(home) == before
        for kind, name in (("markdown", "network_map.md"), ("mermaid", "network_map.mmd")):
            assert (home / "network-atlas" / "exports" / name).read_text() == data["snapshot"]["maps"][kind]["content"]
    else:
        raise ValueError("unknown acceptance mode")
    atlas.manager.unload()
    print(json.dumps({"mode": mode, "supported_native_admission": True, "three_aliases": sorted(data["ids"]),
                      "network_denied": True, "fresh_process_persistence": mode == "reopen",
                      "synthetic_transport_only": True, "counts": counts(home)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
