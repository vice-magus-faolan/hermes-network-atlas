# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only original collector evidence with explicit application/identity lineage.

NULL entity IDs identify immutable originals, NOT unresolved identity. Copies
made by reconciliation and its saved receipt establish identity state. Later
lineage uses the same typed subject anchor AND origin context, never an IP match.
No collection, policy admission, reconciliation or schema migration happens here.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import json
import time

from .config import Policy
from .facts import evidence
from .storage import Store, response_json, timestamp


def _bounded(store: Store, sql: str, bindings: tuple) -> list:
    rows = store.connection.execute(sql + " LIMIT ?", (*bindings, store.policy.limits.result_count + 1)).fetchall()
    if len(rows) > store.policy.limits.result_count:
        raise ValueError("identity lineage exceeds configured detail bound")
    return rows


def _application(store: Store, batch: str) -> dict | None:
    # Old receipts can exceed a reader's lowered byte limit. Refuse, not truncate
    # reasons or hide candidates. Bound before bringing the JSON into Python.
    maximum = store.policy.limits.output_bytes
    row = store.connection.execute(
        "SELECT id,batch_id,applied_at,rowid AS sequence,substr(result_json,1,?) AS result_json "
        "FROM applications WHERE batch_id=?", (maximum + 1, batch)).fetchone()
    if row is None:
        return None
    if len(row["result_json"].encode("utf-8")) > maximum:
        raise ValueError("stored application exceeds configured byte bound")
    result = json.loads(row["result_json"])
    if not isinstance(result, dict) or not isinstance(result.get("unresolved", []), list):
        raise ValueError("invalid stored application")
    for entry in result.get("unresolved", []):
        _validate_entry(entry)
    return {**dict(row), "result": result}


def _validate_entry(entry: object) -> None:
    """Reject malformed saved identity data before original or later aggregation."""
    if not isinstance(entry, dict) or not isinstance(entry.get("evidence_id"), str):
        raise ValueError("invalid stored application")
    candidates = entry.get("candidate_device_ids", [])
    if (not isinstance(entry.get("reason"), str) or not isinstance(candidates, list)
            or any(not isinstance(candidate, str) for candidate in candidates)):
        raise ValueError("invalid stored application")


def _reason(store: Store, application: dict | None, ids: set[str]) -> tuple[str | None, list[str]]:
    if application is None:
        return None, []
    entries = [entry for entry in application["result"].get("unresolved", []) if entry.get("evidence_id") in ids]
    reasons = sorted({entry["reason"] for entry in entries})
    candidates = sorted({candidate for entry in entries for candidate in entry.get("candidate_device_ids", [])})
    if len(candidates) > store.policy.limits.result_count:
        raise ValueError("identity candidates exceed configured detail bound")
    return "; ".join(reasons) or None, candidates


def _application_info(application: dict | None) -> dict | None:
    if application is None:
        return None
    return {key: application[key] for key in ("id", "batch_id", "applied_at")}


def _subject_match(row) -> tuple[str, tuple]:
    # Unresolved IDs are collector labels, not strong identity. Even if reused,
    # they cannot relate two different addresses/values. MAC/alias anchors can
    # relate a subject's different fields/addresses within the same context.
    return ("o.subject_kind=? AND o.subject_anchor=? AND "
            "(json_extract(o.subject_anchor,'$.kind')<>'unresolved' OR (o.field=? AND o.value_json=?))",
            (row["subject_kind"], row["subject_anchor"], row["field"], row["value_json"]))


def _copied_devices(store: Store, row, batch: str, *, exact: bool) -> list[str]:
    match, bindings = _subject_match(row)
    restriction = " AND o.field=? AND o.value_json=? AND o.probe_id=?" if exact else ""
    values = (*bindings, row["field"], row["value_json"], row["probe_id"]) if exact else bindings
    rows = _bounded(store,
        "SELECT DISTINCT CASE o.subject_kind WHEN 'device' THEN d.id WHEN 'interface' THEN i.device_id "
        "WHEN 'address' THEN ai.device_id END AS resolved_device FROM observations o "
        "LEFT JOIN devices d ON o.subject_kind='device' AND d.id=o.entity_id "
        "LEFT JOIN interfaces i ON o.subject_kind='interface' AND i.id=o.entity_id "
        "LEFT JOIN addresses a ON o.subject_kind='address' AND a.id=o.entity_id "
        "LEFT JOIN interfaces ai ON ai.id=a.interface_id WHERE " + match + restriction +
        " AND o.batch_id=? AND o.entity_id IS NOT NULL AND resolved_device IS NOT NULL ORDER BY resolved_device",
        (*values, batch))
    return [entry["resolved_device"] for entry in rows]


def _state(application: dict | None, reason: str | None, candidates: list, resolved: list) -> str:
    if application is None:
        return "never_reconciled"
    if len(resolved) > 1 or candidates:
        return "reconciled_conflicting"
    if resolved:
        return "resolved_in_batch"
    return "reconciled_unresolved" if reason else "applied_without_identity_result"


def _lineage(store: Store, row, batch, application: dict | None) -> dict | None:
    match, bindings = _subject_match(row)
    sequence = application["sequence"] if application else 0
    later = store.connection.execute(
        "SELECT b.id FROM observations o JOIN batches b ON b.id=o.batch_id "
        "JOIN applications a ON a.batch_id=b.id WHERE " + match +
        " AND b.policy_context=? AND b.id<>? AND o.entity_id IS NULL AND o.observed_at>=? "
        "AND a.rowid>? AND (? OR b.rowid>?) ORDER BY a.rowid DESC LIMIT 1",
        (*bindings, batch["policy_context"], batch["id"], row["observed_at"], sequence,
         application is not None, batch["sequence"])).fetchone()
    if later is None:
        return None
    latest = _application(store, later["id"])
    assert latest is not None  # The snapshot's applications JOIN proved this row.
    originals = _bounded(store, "SELECT o.id FROM observations o WHERE " + match +
                         " AND o.batch_id=? AND o.entity_id IS NULL ORDER BY o.id", (*bindings, later["id"]))
    reason, candidates = _reason(store, latest, {entry["id"] for entry in originals})
    resolved = _copied_devices(store, row, later["id"], exact=False)
    state = _state(latest, reason, candidates, resolved)
    return {"id": latest["id"], "batch_id": latest["batch_id"], "applied_at": latest["applied_at"],
            "state": state, "identity_reason": reason,
            "candidate_device_ids": candidates, "resolved_device_ids": resolved}


def _identity(store: Store, row, batch, application: dict | None) -> dict:
    reason, candidates = _reason(store, application, {row["id"]})
    resolved = _copied_devices(store, row, batch["id"], exact=True) if application else []
    state = _state(application, reason, candidates, resolved)
    lineage = _lineage(store, row, batch, application)
    if lineage:
        state = {"resolved_in_batch": "subsequently_resolved", "reconciled_conflicting": "subsequently_conflicting",
                 "reconciled_unresolved": "subsequently_unresolved"}.get(lineage["state"], "subsequent_identity_unknown")
    return {"identity_state": state, "identity_reason": reason, "candidate_device_ids": candidates,
            "resolved_device_ids": resolved, "application": _application_info(application), "lineage": lineage}


def _freshness(row, now: datetime, stale_days: int) -> str:
    if not row["qualified"] or row["confidence"] != "observed":
        return "unqualified"
    if row["observed_at"] > timestamp(now):
        return "future"
    return "stale" if row["observed_at"] < timestamp(now - timedelta(days=stale_days)) else "fresh"


def _responder(row) -> bool:
    """SSH inventory of an IP/interface is not an exact-address response."""
    qualified = row["qualified"] and row["confidence"] == "observed"
    response = row["evidence_kind"] == "ping_response" or (row["evidence_kind"] == "ssh_response" and row["subject_kind"] == "device")
    return bool(qualified and response)


def _batch_summary(store: Store, batch) -> dict:
    # Fixed enum summary covers legacy V1 complete/partial/failed and every
    # supported outcome, independently of lowered evidence-page ceilings.
    from .query import _probe_totals
    totals = _probe_totals(store, batch["id"])
    return {**{key: batch[key] for key in ("id", "collector", "source", "policy_context", "scope_kind", "scope_name",
                                          "scope_value", "started_at", "ended_at", "completion")},
            "local_policy_context": batch["policy_context"] == str(store.policy.home), "probe_summary": totals,
            "scope_absence_eligible": batch["completion"] == "complete" and totals["absence_eligible_count"] > 0}


def _address_candidates(store: Store, address: str | None) -> list[str]:
    if address is None:
        return []
    rows = _bounded(store, "SELECT DISTINCT i.device_id FROM addresses a JOIN interfaces i ON i.id=a.interface_id "
                    "WHERE a.address=? AND a.ended_at IS NULL ORDER BY i.device_id", (address,))
    return [row["device_id"] for row in rows]


def _detail(store: Store, row, now: datetime, batches: dict, applications: dict) -> dict:
    store.check_deadline()
    batch_id = row["batch_id"]
    if batch_id not in batches:
        batch = store.connection.execute("SELECT *,rowid AS sequence FROM batches WHERE id=?", (batch_id,)).fetchone()
        batches[batch_id] = {"record": batch, "summary": _batch_summary(store, batch)}
        applications[batch_id] = _application(store, batch_id)
    batch = batches[batch_id]["record"]
    value = _checked_evidence(store, row)
    address = value["value"].get("address") if row["subject_kind"] == "address" else None
    candidates = _address_candidates(store, address)
    probe = store.connection.execute("SELECT id,probe_name,outcome,diagnostic_code,coverage_kind,coverage_value,"
                                     "started_at,ended_at,absence_eligible FROM probes WHERE id=? AND batch_id=?",
                                     (row["probe_id"], batch_id)).fetchone()
    return {**value, "subject_kind": row["subject_kind"], "subject_anchor": json.loads(row["subject_anchor"]),
            "entity_id": None, "address": address, "batch": batches[batch_id]["summary"],
            "probe": dict(probe) if probe else None, "freshness": _freshness(row, now, store.policy.stale_after_days),
            "historical_responder_evidence": _responder(row),
            "current_address_candidate_device_ids": candidates, "address_ownership_conflict": len(candidates) > 1,
            **_identity(store, row, batch, applications[batch_id])}


def _checked_evidence(store: Store, row) -> dict:
    for key in ("subject_anchor", "value_json", "explanation"):
        if row[key] is not None and len(row[key].encode("utf-8")) > store.policy.limits.output_bytes:
            raise ValueError("stored evidence exceeds configured byte bound")
    value = evidence(row)
    if row["subject_kind"] == "address" and not isinstance(value["value"], dict):
        raise ValueError("invalid stored address evidence")
    return value


def _page(store: Store, params: dict, now: datetime) -> dict:
    clauses, bindings = ["o.entity_id IS NULL"], []
    if "batch_id" in params:
        store.require("batches", params["batch_id"])
        clauses.append("o.batch_id=?")
        bindings.append(params["batch_id"])
    if "address" in params:
        clauses.append("o.subject_kind='address' AND json_extract(o.value_json,'$.address')=?")
        bindings.append(params["address"])
    rows = store.connection.execute(
        "SELECT o.id,o.batch_id,o.probe_id,o.subject_kind,substr(o.subject_anchor,1,?) AS subject_anchor,"
        "o.entity_id,o.field,substr(o.value_json,1,?) AS value_json,o.source,o.confidence,o.observed_at,"
        "o.evidence_kind,substr(o.explanation,1,?) AS explanation,o.neighbor_state,o.qualified "
        "FROM observations o JOIN batches b ON b.id=o.batch_id WHERE " + " AND ".join(clauses) +
        " ORDER BY o.observed_at DESC,o.id LIMIT ? OFFSET ?",
        (store.policy.limits.output_bytes + 1,) * 3 + (*bindings, params["limit"] + 1, params["offset"])).fetchall()
    batches, applications = {}, {}
    return {"view": "unresolved", "evidence": [_detail(store, row, now, batches, applications) for row in rows[:params["limit"]]],
            "limit": params["limit"], "offset": params["offset"], "has_more": len(rows) > params["limit"],
            "discovery_performed": False, "reachability": "historical evidence only; current reachability not established"}


def query_evidence(policy: Policy, params: dict, now: datetime) -> dict:
    """Bound SQL and Python work by one policy deadline; never create a missing store."""
    deadline = time.monotonic() + policy.limits.operation_timeout_seconds
    if not policy.database.exists():
        if "batch_id" in params:
            raise ValueError("unknown atlas batch")
        result = {"view": "unresolved", "evidence": [], "limit": params["limit"], "offset": params["offset"],
                  "has_more": False, "discovery_performed": False,
                  "reachability": "historical evidence only; current reachability not established"}
        response_json(result, policy.limits.output_bytes)
        return result
    with Store(policy, deadline=deadline) as store, store.snapshot():
        result = _page(store, params, now)
        response_json(result, policy.limits.output_bytes)
        store.check_deadline()
        return result
