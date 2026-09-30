# SPDX-License-Identifier: GPL-3.0-or-later
"""Transactional application of immutable LAN batches; no subprocesses or deletion.

MACs resolve interfaces first. IP-only/randomized/colliding observations remain
unresolved evidence, never merge keys. A scan response at a known IP prevents a
false absence report without attesting that IP's owner. Address evidence is a set:
new ping/neighbor addresses do not invalidate other assignments on an interface.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address, ip_network
import json
import re
import sqlite3

from .batches import _scope
from .config import NAME_PATTERN, Policy
from .core import _positive
from .facts import freshness, selected_facts
from .identity import mac_address
from .storage import Store, encode, identifier, response_json, timestamp, utc_now


@dataclass
class Application:
    """One transaction's bounded result and identity cache; never shared between calls."""
    store: Store
    batch: sqlite3.Row
    now: datetime
    result: dict
    anchors: dict[str, tuple[str, str]] = field(default_factory=dict)
    seen: set[str] = field(default_factory=set)
    touched: set[str] = field(default_factory=set)
    changed: set[str] = field(default_factory=set)
    local_device: str | None = None

    def event(self, action: str, entity: str | None, details: object) -> None:
        event = self.store.audit(self.result["id"], action, self.batch["source"], self.result["applied_at"],
                                 entity=entity, details=details, batch=self.batch["id"])
        self.result["audit_event_ids"].append(event)


def _rows(store: Store, sql: str, args: tuple = ()) -> list:
    rows = store.connection.execute(sql + " LIMIT ?", (*args, store.policy.limits.observations + 1)).fetchall()
    if len(rows) > store.policy.limits.observations:
        raise ValueError("reconciliation scope exceeds configured record bound")
    return rows


def _select(store: Store, batch_id: str | None):
    if batch_id is None:
        allowed = [(collector, network.name, network.cidr) for network in store.policy.networks
                   for collector, enabled in (("local_passive", network.passive), ("ping", network.ping)) if enabled]
        scope_sql = " OR ".join("(b.collector=? AND b.scope_name=? AND b.scope_value=?)" for _ in allowed) or "0"
        bindings = tuple(value for scope in allowed for value in scope)
        row = store.connection.execute("""SELECT b.* FROM batches b WHERE b.policy_context=?
          AND (""" + scope_sql + """) AND NOT EXISTS
          (SELECT 1 FROM applications a WHERE a.batch_id=b.id) ORDER BY b.ended_at DESC,b.id DESC LIMIT 1""",
          (str(store.policy.home), *bindings)).fetchone()
        if row is None:
            raise ValueError("no unapplied local discovery batch")
    else:
        row = store.require("batches", batch_id)
    if row["policy_context"] != str(store.policy.home) or row["collector"] not in {"local_passive", "ping"}:
        raise ValueError("batch is not this profile's LAN evidence")
    kind, scope, _ = _scope(store, row["collector"], row["scope_name"])
    if kind != row["scope_kind"] or scope != row["scope_value"]:
        raise ValueError("batch scope no longer matches local policy")
    return row


def reconcile(policy: Policy, params: object, *, now: datetime | None = None) -> dict:
    """Apply one selected/latest stored batch atomically; exact retries add no events."""
    if not isinstance(params, dict) or not set(params) <= {"batch_id"}:
        raise ValueError("invalid reconciliation arguments")
    batch_id = params.get("batch_id")
    if "batch_id" in params and (not isinstance(batch_id, str) or re.fullmatch(NAME_PATTERN, batch_id) is None):
        raise ValueError("invalid stored batch ID")
    if not policy.database.exists():
        raise ValueError("no stored batches")
    clock = now or utc_now()
    with Store(policy, writable=True) as store, store.transaction():
        batch = _select(store, batch_id)
        previous = store.connection.execute("SELECT result_json FROM applications WHERE batch_id=?", (batch["id"],)).fetchone()
        if previous is not None:
            result = json.loads(previous[0])
            response_json(result, policy.limits.output_bytes)
            return result
        if timestamp(clock) < batch["ended_at"]:
            raise ValueError("application time precedes batch")
        return _apply(store, batch, clock)


def _apply(store: Store, batch, now: datetime) -> dict:
    result = {"id": identifier(), "batch_id": batch["id"], "schema_version": 1,
              "applied_at": timestamp(now), "applied": True, "persisted": True,
              **{name: [] for name in ("new", "changed", "unchanged", "missing", "conflicting", "unresolved", "audit_event_ids")}}
    app = Application(store, batch, now, result)
    observations = _rows(store, "SELECT * FROM observations WHERE batch_id=? AND entity_id IS NULL ORDER BY rowid", (batch["id"],))
    _local_identity(app, observations)
    for observation in observations:
        _apply_observation(app, observation)
    _absence(app, observations)
    _statuses(app)
    result["changed"] = sorted(app.changed - set(result["new"]))
    result["unchanged"] = sorted(app.touched - app.changed - set(result["new"]))
    app.event("batch_reconciled", None, {name: len(result[name]) for name in ("new", "changed", "unchanged", "missing", "conflicting", "unresolved")})
    response_json(result, store.policy.limits.output_bytes)
    store.connection.execute("INSERT INTO applications VALUES (?,?,?,?,?)",
                             (result["id"], batch["id"], 1, result["applied_at"], encode(result)))
    return result


def _local_identity(app: Application, observations: list) -> None:
    # A single ip addr command is direct same-host evidence. Reuse an already
    # anchored device only if all of its resolved interfaces agree; never merge
    # existing devices to make a seemingly neat local-host representation.
    owners = set()
    for row in observations:
        if row["evidence_kind"] != "local_interface":
            continue
        anchor = json.loads(row["subject_anchor"])
        if anchor["kind"] == "mac":
            candidates = _rows(app.store, "SELECT * FROM interfaces WHERE mac_address=? ORDER BY id", (anchor["value"],))
            if len(candidates) == 1 and candidates[0]["stable_mac"]:
                owners.add(candidates[0]["device_id"])
    if len(owners) == 1:
        app.local_device = next(iter(owners))
    elif len(owners) > 1:
        app.result["conflicting"].append({"reason": "local_host_multiple_devices", "candidate_device_ids": sorted(owners)})


def _resolve(app: Application, row) -> tuple[tuple[str, str] | None, list[str]]:
    key = row["subject_anchor"]
    if key in app.anchors:
        return app.anchors[key], []
    anchor = json.loads(key)
    candidates = []
    if anchor["kind"] == "mac":
        mac, stable = mac_address(anchor["value"])
        candidates = _rows(app.store, "SELECT * FROM interfaces WHERE mac_address=? ORDER BY id", (mac,))
        if stable and len(candidates) == 1:
            app.anchors[key] = (candidates[0]["device_id"], candidates[0]["id"])
            return app.anchors[key], []
        if stable and not candidates:
            return _new_interface(app, row, mac), []
    # Unstable/colliding/absent anchors remain explicit; do not pick IP owners.
    owners = {candidate["device_id"] for candidate in candidates}
    if row["subject_kind"] == "address":
        value = json.loads(row["value_json"])
        matches = _rows(app.store, "SELECT DISTINCT i.device_id FROM addresses a JOIN interfaces i ON i.id=a.interface_id "
                        "WHERE a.address=? AND a.ended_at IS NULL ORDER BY i.device_id", (value["address"],))
        owners.update(match[0] for match in matches)
    return None, sorted(owners)


def _new_interface(app: Application, row: sqlite3.Row, mac: str) -> tuple[str, str]:
    local = row["evidence_kind"] == "local_interface"
    device = app.local_device if local else None
    if device is None:
        device = identifier()
        app.store.connection.execute("INSERT INTO devices(id,created_at) VALUES (?,?)", (device, app.result["applied_at"]))
        app.result["new"].append(device)
        app.event("device_discovered", device, {"evidence_id": row["id"]})
        if local:
            app.local_device = device
    interface = identifier()
    app.store.connection.execute("INSERT INTO interfaces VALUES (?,?,?,?,?)", (interface, device, mac, 1, app.result["applied_at"]))
    app.anchors[row["subject_anchor"]] = (device, interface)
    app.changed.add(device)
    app.event("interface_discovered", interface, {"device_id": device, "mac_address": mac})
    return device, interface


def _copy_fact(app: Application, row, entity: str) -> str:
    observation = identifier()
    app.store.connection.execute("""INSERT INTO observations
      SELECT ?,batch_id,probe_id,subject_kind,subject_anchor,?,field,value_json,source,confidence,
             observed_at,evidence_kind,explanation,neighbor_state,qualified FROM observations WHERE id=?""",
      (observation, entity, row["id"]))
    return observation


def _apply_observation(app: Application, row) -> None:
    resolved, candidates = _resolve(app, row)
    if resolved is None:
        conflict = {"evidence_id": row["id"], "candidate_device_ids": sorted(set(candidates)), "reason": "no_unique_stable_interface"}
        app.result["unresolved"].append(conflict)
        if candidates:
            app.result["conflicting"].append(conflict)
        return
    device, interface = resolved
    app.touched.add(device)
    if row["subject_kind"] == "address":
        _assignment(app, row, device, interface)
    elif row["subject_kind"] in {"device", "interface"}:
        _scalar(app, row, device, device if row["subject_kind"] == "device" else interface)
    if row["qualified"]:
        _positive(app.store, device, row["observed_at"])
        app.seen.add(device)
    elif row["evidence_kind"] == "cached_neighbor" and row["neighbor_state"] not in {"FAILED", "INCOMPLETE"}:
        _checked(app.store, device, row["observed_at"])


def _scalar(app: Application, row, device: str, entity: str) -> None:
    before = selected_facts(app.store.connection, row["subject_kind"], entity, app.now, app.store.policy.stale_after_days)
    _copy_fact(app, row, entity)
    after = selected_facts(app.store.connection, row["subject_kind"], entity, app.now, app.store.policy.stale_after_days)
    old, new = before.get(row["field"]), after.get(row["field"])
    if (old or {}).get("value") != (new or {}).get("value"):
        app.changed.add(device)
        app.event("field_observed", entity, {"field": row["field"], "evidence_id": row["id"]})
    if new and new["conflict"]:
        app.result["conflicting"].append({"entity_id": entity, "field": row["field"], "reason": "equal_rank_disagreement"})


def _assignment(app: Application, row, device: str, interface: str) -> None:
    value = json.loads(row["value_json"])
    existing = app.store.connection.execute("""SELECT * FROM addresses WHERE interface_id=? AND address=?
      AND prefix_length=? AND source=? AND ended_at IS NULL ORDER BY first_seen,id LIMIT 1""",
      (interface, value["address"], value["prefix_length"], row["source"])).fetchone()
    assignment = existing["id"] if existing else identifier()
    fact = _copy_fact(app, row, assignment)
    if existing:
        app.store.connection.execute("""UPDATE addresses SET last_seen=MAX(last_seen,?),first_seen=MIN(first_seen,?),
          observation_id=CASE WHEN last_seen<=? THEN ? ELSE observation_id END WHERE id=?""",
          (row["observed_at"], row["observed_at"], row["observed_at"], fact, assignment))
    else:
        app.store.connection.execute("INSERT INTO addresses VALUES (?,?,?,?,?,?,?,?,?,NULL)",
          (assignment, interface, value["address"], value["prefix_length"], ip_address(value["address"]).version,
           row["source"], row["observed_at"], row["observed_at"], fact))
        app.changed.add(device)
        app.event("address_observed", assignment, {"device_id": device, "address": value["address"], "evidence_id": row["id"]})
    owners = _rows(app.store, "SELECT DISTINCT i.device_id FROM addresses a JOIN interfaces i ON i.id=a.interface_id "
                   "WHERE a.address=? AND a.ended_at IS NULL ORDER BY i.device_id", (value["address"],))
    if len(owners) > 1:
        app.result["conflicting"].append({"address": value["address"], "candidate_device_ids": [owner[0] for owner in owners], "reason": "address_ownership"})


def _checked(store: Store, device: str, at: str) -> None:
    store.connection.execute("UPDATE devices SET last_checked=CASE WHEN last_checked IS NULL OR last_checked<? THEN ? ELSE last_checked END WHERE id=?", (at, at, device))


def _absence(app: Application, observations: list) -> None:
    eligible = app.store.connection.execute("SELECT 1 FROM probes WHERE batch_id=? AND absence_eligible=1 LIMIT 1", (app.batch["id"],)).fetchone()
    if app.batch["completion"] != "complete" or app.batch["collector"] != "ping" or not eligible:
        return
    observed = {json.loads(row["value_json"])["address"] for row in observations if row["subject_kind"] == "address" and row["qualified"]}
    scope = ip_network(app.batch["scope_value"])
    by_device = {}
    assignments = _rows(app.store, "SELECT a.address,i.device_id FROM addresses a JOIN interfaces i ON i.id=a.interface_id WHERE a.ended_at IS NULL ORDER BY i.device_id,a.address")
    for row in assignments:
        if ip_address(row["address"]) in scope:
            by_device.setdefault(row["device_id"], set()).add(row["address"])
    for device, addresses in sorted(by_device.items()):
        _checked(app.store, device, app.batch["ended_at"])
        if device not in app.seen and not addresses & observed:
            app.result["missing"].append({"device_id": device, "addresses": sorted(addresses), "meaning": "not_observed_in_this_run"})
            app.event("not_observed", device, {"scope": str(scope), "addresses": sorted(addresses)})


def _statuses(app: Application) -> None:
    for row in _rows(app.store, "SELECT * FROM devices ORDER BY id"):
        status = freshness(row, app.now, app.store.policy.stale_after_days)
        previous = app.store.connection.execute("SELECT details_json FROM audit_events WHERE entity_id=? AND action='freshness_transition' ORDER BY rowid DESC LIMIT 1", (row["id"],)).fetchone()
        old = json.loads(previous[0])["status"] if previous else "known"
        if status != old:
            app.event("freshness_transition", row["id"], {"previous_status": old, "status": status})
            app.changed.add(row["id"])
