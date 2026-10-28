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

from network_guard import deny_network
from native_host_acceptance import collect_methods, reopen_methods


class NativeAtlas:
    """Small adapter to REAL registered APIs; no loader, core or consent mocks."""
    def __init__(self, source: Path):
        sys.path.insert(0, str(source))

        from hermes_cli.plugins import discover_plugins, get_plugin_manager, get_plugin_command_handler
        from tools.registry import registry
        discover_plugins()
        self.manager = get_plugin_manager()
        from hermes_cli.plugins import PluginContext
        loaded = next(item for item in self.manager._plugins.values() if item.manifest.name == "network-atlas")
        self.ctx = PluginContext(loaded.manifest, self.manager)
        self.registry = registry
        self.command = get_plugin_command_handler("network")
        assert self.command is not None
        plugin = next(item for item in self.manager.list_plugins() if item["name"] == "network-atlas")
        assert plugin["enabled"] and not plugin["error"], plugin
        self.entry = self.manager._cli_commands["network-atlas"]
        self.parser = argparse.ArgumentParser(allow_abbrev=False)
        self.entry["setup_fn"](self.parser)
        names = {"network_query", "network_update", "network_map", "network_discover", "network_inspect",
                 "network_reconcile", "network_check_endpoints"}
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

    def cli(self, argv: list[str], *, expected_code: int = 0) -> dict:
        output = io.StringIO()
        with redirect_stdout(output):
            code = self.entry["handler_fn"](self.parser.parse_args(argv))
        result = json.loads(output.getvalue())
        assert code == expected_code, result
        return result

    def update(self, device: str, field: str, value: object) -> dict:
        result = self.cli(["update", "--device-id", device, "--field", field, "--value-json", json.dumps(value)])
        assert result["update"]["confidence"] == "user_supplied", result
        return result


def counts(home: Path) -> dict:
    database = home / "plugin-data" / "network-atlas" / "atlas.sqlite3"
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        return {name: connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in
                ("devices", "interfaces", "observations", "batches", "applications", "audit_events", "access_evidence")}


def invalid_policy_refusal(atlas: NativeAtlas, home: Path, root: Path) -> None:
    """Refuse hostile method grants on real tool/slash/CLI before any effects."""
    original = json.loads(json.dumps(atlas.ctx.get_config("policy", {})))
    config_path = home / "config.yaml"
    native_config = config_path.read_bytes()
    healthy_status = atlas.slash("status")
    assert "error" not in healthy_status, healthy_status
    database = home / "plugin-data" / "network-atlas" / "atlas.sqlite3"
    before = counts(home) if database.exists() else None
    files = set(database.parent.rglob("*"))
    calls_path = root / "fixture-bin" / "calls.jsonl"
    calls = calls_path.read_bytes()
    for methods in ({"icmp_echo": 1}, {"tcp_ports": [4403]}, {"icmp_echo": True, "options": "-PE"}):
        try:
            raw = json.loads(json.dumps(original))
            raw["networks"]["lab"]["discovery"].update(methods)
            atlas.ctx.set_config("policy", raw)
            assert atlas.ctx.get_config("policy", None) == raw

            results = (atlas.tool("network_discover", {"network": "lab", "mode": "ping"}),
                       atlas.slash("discover lab ping"),
                       atlas.cli(["discover", "--network", "lab", "--mode", "ping"], expected_code=2))
            for result in results:
                assert "error" in result, result
                assert not result["applied"] and not result["persisted"], result
            assert files == set(database.parent.rglob("*")) and calls_path.read_bytes() == calls
            assert before == (counts(home) if database.exists() else None)
        finally:
            # Native dictionary writes merge omitted keys. Restore the complete
            # synthetic file so each negative varies only its intended setting.
            config_path.write_bytes(native_config)
        assert atlas.ctx.get_config("policy", None) == original
        assert atlas.slash("status") == healthy_status
        assert atlas.tool("network_query", {"view": "status"}) == healthy_status
        assert atlas.cli(["status"]) == healthy_status


def collect(atlas: NativeAtlas, root: Path) -> dict:
    """Two synthetic scans with excluded scope edges; three authorized SSH aliases."""
    status = atlas.slash("status")
    assert status["known_devices"] == 0 and status["last_discovery"] is None, status
    passive = atlas.slash("discover lab passive")
    assert passive["completion"] == "complete" and not passive["applied"], passive
    assert not atlas.tool("network_reconcile", {"batch_id": passive["batch_id"]})["new"]
    first = atlas.tool("network_discover", {"network": "lab", "mode": "ping"})
    assert first["completion"] == "partial" and not first["applied"], first
    assert not atlas.tool("network_query", {})["devices"]
    original = atlas.tool("network_query", {"view": "unresolved", "batch_id": first["batch_id"]})
    assert len(original["evidence"]) == 5 and not original["has_more"], original
    assert {row["identity_state"] for row in original["evidence"]} == {"never_reconciled"}
    assert all(row["historical_responder_evidence"] for row in original["evidence"])
    initial = atlas.slash("reconcile " + first["batch_id"])
    assert len(initial["new"]) == 4 and initial["unresolved"] and not initial["missing"], initial
    assert atlas.tool("network_reconcile", {"batch_id": first["batch_id"]}) == initial
    unidentified = atlas.cli(["query", "--query-json", json.dumps({"view": "unresolved", "address": "192.0.2.4"})])
    assert (len(unidentified["evidence"]) == 1
            and unidentified["evidence"][0]["identity_state"] == "reconciled_unresolved")
    assert unidentified["evidence"][0]["identity_reason"] == "no_unique_stable_interface"
    ids = {}
    for number, alias in enumerate(("lab-a", "lab-b", "lab-c"), 1):
        device = atlas.tool("network_query", {"address": f"192.0.2.{number}"})["devices"][0]["id"]
        ids[alias] = device
        atlas.update(device, "ssh_alias", alias)
        receipt = (atlas.slash("inspect " + device) if alias == "lab-b"
                   else atlas.tool("network_inspect", {"target": alias}))
        assert receipt["completion"] == "complete", receipt
        result = atlas.cli(["reconcile", "--batch-id", receipt["batch_id"]])
        assert not result["new"] and not result["missing"], result
    queried = atlas.tool("network_query", {"access_method": "ssh"})
    assert {row["id"] for row in queried["devices"]} == set(ids.values()) and not queried["has_more"]
    assert all(row["access"][0]["last_inspection"]["succeeded"] for row in queried["devices"])
    before_maps = counts(Path(os.environ["HERMES_HOME"]))
    calls = (root / "fixture-bin" / "calls.jsonl").read_bytes()
    for kind in ("text", "markdown", "mermaid"):
        mapped = atlas.tool("network_map", {"format": kind})
        assert not mapped["exports"], mapped
        for alias, device in ids.items():
            row = next(row for row in queried["devices"] if row["id"] == device)
            assert "canonical_name" not in row["fields"] and row["fields"]["hostname"]["value"] == alias, row
            expected = {"text": alias + " [", "markdown": f"| {alias} ({device}) |",
                        "mermaid": 'n' + device.replace("-", "") + '["' + alias.replace("-", "#45;") + ' #91;'}
            assert expected[kind] in mapped["content"], mapped
    assert atlas.tool("network_query", {"access_method": "ssh"}) == queried
    assert counts(Path(os.environ["HERMES_HOME"])) == before_maps
    assert (root / "fixture-bin" / "calls.jsonl").read_bytes() == calls
    assert not atlas.tool("network_query", {"address": "198.51.100.99"})["devices"]
    pair = atlas.slash("discover pair ping")
    assert pair["completion"] == "complete", pair
    missing = atlas.tool("network_reconcile", {"batch_id": pair["batch_id"]})
    assert {row["device_id"] for row in missing["missing"]} == {ids["lab-b"], ids["lab-c"]}, missing
    assert {row["meaning"] for row in missing["missing"]} == {"not_observed_in_this_run"}, missing
    assert atlas.tool("network_reconcile", {"batch_id": pair["batch_id"]}) == missing
    (root / "fixture-bin" / "stage").write_text("changed")
    second = atlas.cli(["discover", "--network", "lab", "--mode", "ping"])
    change = atlas.tool("network_reconcile", {"batch_id": second["batch_id"]})
    assert (change["new"] and ids["lab-a"] in change["changed"]
            and change["conflicting"] and change["unresolved"]), change
    # Completed eligible hosts cannot turn excluded scope edges into exact coverage.
    assert second["completion"] == "partial" and not change["missing"], change
    return {"ids": ids, "initial": initial, "change": change, "missing": missing}


def sources_and_failure(atlas: NativeAtlas, root: Path, data: dict) -> None:
    device = data["ids"]["lab-a"]
    atlas.update(device, "canonical_name", 'Fixture "] --> Evil["<script>|')
    atlas.update(device, "description", "Operator assertion")
    inference = atlas.tool("network_update", {"device_id": device, "field": "description",
                                             "value": "Inference assertion",
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
    hostname_collisions(atlas, root, data["ids"])
    saved_conflict_workflow(atlas, root)
    data["uncertainty_batch"] = uncertainty_workflow(atlas, root, data["ids"])


def saved_conflict_workflow(atlas: NativeAtlas, root: Path) -> None:
    """Seven ID-less conflicts must survive real native apply and every replay adapter."""
    (root / "fixture-bin" / "stage").write_text("conflicts")
    batch = atlas.tool("network_inspect", {"target": "lab-a"})["batch_id"]
    applied = atlas.tool("network_reconcile", {"batch_id": batch})
    database = Path(os.environ["HERMES_HOME"]) / "plugin-data" / "network-atlas" / "atlas.sqlite3"
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        saved = json.loads(connection.execute(
            "SELECT result_json FROM applications WHERE batch_id=?", (batch,)).fetchone()[0])
        originals = [row[0] for row in connection.execute(
            "SELECT id FROM observations WHERE batch_id=? AND entity_id IS NULL ORDER BY observed_at DESC,id",
            (batch,))]
        history = tuple(connection.iterdump())
    conflicts = [entry for entry in applied["conflicting"] if entry["reason"] == "duplicate_remote_interface_mac"]
    assert len(conflicts) == 7 and all("evidence_id" not in entry for entry in conflicts), applied
    assert applied["conflicting"] == saved["conflicting"]
    assert applied["conflicting_total_count"] == len(saved["conflicting"]) and applied["conflicting_omitted_count"] == 0
    summary = applied["uncertainty"]
    assert summary["conflict_record_count"] == len(saved["conflicting"])
    assert {entry["reason"]: entry["conflict_record_count"] for entry in summary["conflict_reasons"]}[
        "duplicate_remote_interface_mac"] == 7
    assert summary["observation_count"] == len(saved["unresolved"])
    calls = (root / "fixture-bin" / "calls.jsonl").read_bytes()
    assert atlas.tool("network_reconcile", {"batch_id": batch}) == applied
    assert atlas.slash("reconcile " + batch) == applied
    assert atlas.cli(["reconcile", "--batch-id", batch]) == applied
    retained = []
    for offset in range(0, len(originals), 23):
        page = atlas.tool("network_query", {"view": "unresolved", "batch_id": batch, "limit": 23, "offset": offset})
        assert page["total_count"] == len(originals) and page["omitted_count"] == len(originals) - len(page["evidence"])
        assert page["has_more"] == (offset + len(page["evidence"]) < len(originals))
        retained.extend(row["id"] for row in page["evidence"])
    assert retained == originals
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        assert tuple(connection.iterdump()) == history
    assert (root / "fixture-bin" / "calls.jsonl").read_bytes() == calls
    (root / "fixture-bin" / "stage").write_text("refused")


def uncertainty_workflow(atlas: NativeAtlas, root: Path, ids: dict) -> str:
    """Real registered inspect/reconcile/query adapters, with virtual-interface noise."""
    stage = root / "fixture-bin" / "stage"
    stage.write_text("collision")
    historical = atlas.tool("network_inspect", {"target": "lab-a"})["batch_id"]
    frozen = atlas.tool("network_reconcile", {"batch_id": historical})
    assert frozen["unresolved_total_count"] > 0
    historical_params = {"view": "unresolved", "batch_id": historical, "summary": True}
    assert atlas.tool("network_query", historical_params)["summary"]["current_unresolved_observation_count"] > 0
    stage.write_text("uncertainty")
    receipt = atlas.tool("network_inspect", {"target": "lab-a"})
    assert receipt["completion"] == "complete" and all(p["outcome"] == "success" for p in receipt["probes"]), receipt
    applied = atlas.slash("reconcile " + receipt["batch_id"])
    assert not applied["new"] and applied["unresolved_total_count"] == 206, applied
    summary = applied["uncertainty"]
    assert summary["observation_count"] == 206 and summary["subject_count"] == 43, summary
    reasons = {group["reason"]: group for group in summary["reasons"]}
    assert set(reasons) == {"no_unique_stable_interface", "no_unique_stable_peer", "unsupported_route"}, summary
    assert reasons["no_unique_stable_interface"]["conflicting_observation_count"] == 4
    assert len(applied["unresolved"]) == 5 and applied["unresolved_omitted_count"] == 201, applied
    assert {entry["reason"] for entry in applied["unresolved"]} == set(reasons)
    assert any(entry.get("candidate_device_ids") == [ids["lab-b"]] for entry in applied["unresolved"])
    assert len(json.dumps(applied)) < 12000
    assert_uncertainty_reads(atlas, root, receipt["batch_id"])
    resolved = atlas.tool("network_query", historical_params)
    assert resolved["summary"]["current_unresolved_observation_count"] == 0, resolved
    assert resolved["summary"]["resolved_observation_count"] > 0, resolved
    assert atlas.tool("network_reconcile", {"batch_id": historical}) == frozen
    assert atlas.tool("network_reconcile", {"batch_id": receipt["batch_id"]}) == applied
    stage.write_text("refused")
    return receipt["batch_id"]


def assert_uncertainty_reads(atlas: NativeAtlas, root: Path, batch: str) -> None:
    home = Path(os.environ["HERMES_HOME"])
    database = home / "plugin-data" / "network-atlas" / "atlas.sqlite3"
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        history = tuple(connection.iterdump())
        originals = connection.execute(
            "SELECT id,value_json,source,observed_at,probe_id,subject_anchor FROM observations "
            "WHERE batch_id=? AND entity_id IS NULL ORDER BY observed_at DESC,id", (batch,)).fetchall()
    files = {p.name: p.read_bytes() for p in database.parent.glob("atlas.sqlite3*")}
    calls = (root / "fixture-bin" / "calls.jsonl").read_bytes()
    params = {"view": "unresolved", "batch_id": batch, "summary": True}
    current = atlas.tool("network_query", params)
    assert current == atlas.cli(["query", "--query-json", json.dumps(params)])
    assert current["total_count"] == len(originals) and not current["evidence"], current
    counts = current["summary"]
    assert counts["current_unresolved_observation_count"] == 206, current
    assert counts["supporting_observation_count"] == 1, current
    assert counts["resolved_observation_count"] > 0 and counts["uncertainty"]["subject_count"] == 43
    assert len(json.dumps(current)) < 10000
    retained = []
    for offset in range(0, len(originals), 23):
        page = atlas.tool("network_query", {"view": "unresolved", "batch_id": batch, "limit": 23, "offset": offset})
        assert page["total_count"] == len(originals) and page["omitted_count"] == len(originals) - len(page["evidence"])
        assert page["has_more"] == (offset + len(page["evidence"]) < len(originals))
        retained.extend(page["evidence"])
    assert [row["id"] for row in retained] == [row[0] for row in originals]
    for row, raw in zip(retained, originals, strict=True):
        assert (row["value"], row["source"], row["observed_at"], row["probe"]["id"], row["subject_anchor"]) == (
            json.loads(raw[1]), raw[2], raw[3], raw[4], json.loads(raw[5]))
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        assert tuple(connection.iterdump()) == history
    assert {p.name: p.read_bytes() for p in database.parent.glob("atlas.sqlite3*")} == files
    assert (root / "fixture-bin" / "calls.jsonl").read_bytes() == calls


def hostname_collisions(atlas: NativeAtlas, root: Path, ids: dict) -> None:
    """Distinct inspected identities sharing a hostname stay distinguishable in real maps."""
    first, second, third = (ids[alias] for alias in ("lab-a", "lab-b", "lab-c"))
    stage = root / "fixture-bin" / "stage"
    atlas.update(first, "canonical_name", "Canonical control")
    stage.write_text("duplicate")
    receipt = atlas.tool("network_inspect", {"target": "lab-c"})
    assert receipt["completion"] == "complete", receipt
    applied = atlas.tool("network_reconcile", {"batch_id": receipt["batch_id"]})
    assert not applied["new"] and not applied["conflicting"], applied
    assert_collision_map(atlas, root, {first: "Canonical control", second: second, third: third})
    stage.write_text("baseline")
    receipt = atlas.tool("network_inspect", {"target": "lab-c"})
    assert receipt["completion"] == "complete", receipt
    applied = atlas.tool("network_reconcile", {"batch_id": receipt["batch_id"]})
    assert not applied["new"] and not applied["conflicting"], applied
    atlas.update(first, "canonical_name", "lab-b")
    assert_collision_map(atlas, root, {first: "lab-b", second: second, third: "lab-c"})
    atlas.update(first, "canonical_name", 'Fixture "] --> Evil["<script>|')
    stage.write_text("refused")


def assert_collision_map(atlas: NativeAtlas, root: Path, names: dict) -> None:
    home = Path(os.environ["HERMES_HOME"])
    database = home / "plugin-data" / "network-atlas" / "atlas.sqlite3"
    devices = atlas.tool("network_query", {})
    histories = {device: atlas.tool("network_query", {"view": "history", "device_id": device}) for device in names}
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        history = tuple(connection.iterdump())
    files = {path.name: path.read_bytes() for path in database.parent.glob("atlas.sqlite3*")}
    calls = (root / "fixture-bin" / "calls.jsonl").read_bytes()
    source, target, _ = names
    line = names[source] + " -- hosted_on [user_supplied] --> " + names[target]
    for kind in ("text", "markdown", "mermaid"):
        mapped = atlas.tool("network_map", {"format": kind})
        assert not mapped["exports"] and not mapped["discovery_performed"], mapped
        for device, name in names.items():
            expected = {"text": name + " [", "markdown": f"| {name} ({device}) |",
                        "mermaid": 'n' + device.replace("-", "") + '["' + name.replace("-", "#45;") + ' #91;'}
            assert expected[kind] in mapped["content"], mapped
        edge = {"text": line, "markdown": line.replace("_", "&#95;").replace("[", "&#91;").replace(
            "]", "&#93;").replace(">", "&#62;"),
            "mermaid": 'n' + source.replace("-", "") + ' -->|"hosted#95;on #91;user#95;supplied#93;"| n'
            + target.replace("-", "")}
        assert edge[kind] in mapped["content"], mapped
    assert atlas.tool("network_query", {}) == devices
    assert {device: atlas.tool("network_query", {"view": "history", "device_id": device})
            for device in names} == histories
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        assert tuple(connection.iterdump()) == history
    assert {path.name: path.read_bytes() for path in database.parent.glob("atlas.sqlite3*")} == files
    assert (root / "fixture-bin" / "calls.jsonl").read_bytes() == calls


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
    histories = {row["id"]: atlas.tool("network_query", {"view": "history", "device_id": row["id"]})
                 for row in devices["devices"]}
    maps = {kind: atlas.tool("network_map", {"format": kind}) for kind in ("text", "markdown", "mermaid")}
    assert maps["mermaid"]["content"].count(" -->|") == 1
    assert 'Fixture "] --> Evil["<script>| -- hosted_on [user_supplied] --> lab-b' in maps["text"]["content"]
    assert '<script>' not in maps["markdown"]["content"] and 'Evil["' not in maps["mermaid"]["content"]
    assert "isolated" in maps["text"]["content"]
    assert atlas.slash("map mermaid")["content"] == maps["mermaid"]["content"]
    assert all(not result["exports"] for result in maps.values())
    unresolved = atlas.tool("network_query", {"view": "unresolved", "address": "192.0.2.4"})
    assert len(unresolved["evidence"]) == 2 and not unresolved["has_more"], unresolved
    assert all(row["identity_reason"] == "no_unique_stable_interface" for row in unresolved["evidence"])
    originals = atlas.tool("network_query", {"view": "unresolved", "address": "192.0.2.1"})
    assert originals["evidence"] and any(row["identity_state"] == "subsequently_resolved"
                                         for row in originals["evidence"])
    return {"devices": devices, "histories": histories, "maps": maps,
            "unresolved": unresolved, "original_evidence": originals,
            "ssh": atlas.tool("network_query", {"access_method": "ssh"}),
            "status": atlas.slash("status"), "counts": counts(home)}


def main() -> int:
    root = Path(os.environ["TMPDIR"]).resolve()
    if not (root / "synthetic-atlas-home").is_file():
        raise ValueError("synthetic scratch fixture required")
    home = Path(os.environ["HERMES_HOME"]).resolve()
    if not home.is_relative_to(root):
        raise ValueError("synthetic fixture home required")
    source = Path(sys.argv[1]).resolve()
    deny_network()
    atlas = NativeAtlas(source)
    mode = sys.argv[2]
    saved = root / "cumulative.json"
    if mode == "collect":
        invalid_policy_refusal(atlas, home, root)
        data = collect(atlas, root)
        sources_and_failure(atlas, root, data)
        collect_methods(atlas, home, root)
        negatives(atlas, home, root)
        exported = atlas.tool("network_map", {"format": "mermaid", "export": True})
        assert {Path(path).name for path in exported["exports"]} == {"network_map.md", "network_map.mmd"}
        data["snapshot"] = snapshot(atlas, home)
        saved.write_text(json.dumps(data, sort_keys=True))
    elif mode == "reopen":
        data = json.loads(saved.read_text())
        before = counts(home)
        assert atlas.tool("network_reconcile", {"batch_id": data["change"]["batch_id"]}) == data["change"]
        assert atlas.tool("network_reconcile", {"batch_id": data["missing"]["batch_id"]}) == data["missing"]
        assert snapshot(atlas, home) == data["snapshot"]
        assert counts(home) == before
        assert_uncertainty_reads(atlas, root, data["uncertainty_batch"])
        for kind, name in (("markdown", "network_map.md"), ("mermaid", "network_map.mmd")):
            assert (home / "network-atlas" / "exports" / name).read_text() == data["snapshot"]["maps"][kind]["content"]
        invalid_policy_refusal(atlas, home, root)
        reopen_methods(atlas, root)
    else:
        raise ValueError("unknown acceptance mode")
    atlas.manager.unload()
    print(json.dumps({"mode": mode, "native_registration": True, "tool_count": 7, "three_aliases": sorted(data["ids"]),
                      "network_denied": True, "fresh_process_persistence": mode == "reopen",
                      "issue6_invalid_policy_refusal": True, "issue6_method_evidence": True,
                      "synthetic_transport_only": True, "counts": counts(home)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
