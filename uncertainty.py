# SPDX-License-Identifier: GPL-3.0-or-later
"""Compact diagnostics over immutable originals, never canonical identity.

A subject belongs to one batch/origin. Interface names qualify anchors; ambiguous
labels stay separate rather than pretending that field observations are devices.
"""
from __future__ import annotations

import json

from .storage import Store, encode


def original_rows(store: Store, batch_id: str) -> list:
    """Keep summary work within the existing single-batch observation ceiling."""
    rows = store.connection.execute(
        "SELECT id,batch_id,probe_id,subject_kind,substr(subject_anchor,1,?) AS subject_anchor,entity_id,field,"
        "substr(value_json,1,?) AS value_json,source,confidence,observed_at,evidence_kind,"
        "substr(explanation,1,?) AS explanation,neighbor_state,qualified FROM observations "
        "WHERE batch_id=? AND entity_id IS NULL ORDER BY id LIMIT ?",
        (store.policy.limits.output_bytes + 1,) * 3 + (batch_id, store.policy.limits.observations + 1)).fetchall()
    if len(rows) > store.policy.limits.observations:
        raise ValueError("uncertainty summary exceeds configured observation bound")
    for row in rows:
        store.check_deadline()
        for key in ("subject_anchor", "value_json"):
            if len(row[key].encode("utf-8")) > store.policy.limits.output_bytes:
                raise ValueError("stored evidence exceeds configured byte bound")
    return rows


class Subjects:
    """Index diagnostic labels once per batch; no database or persistent cache."""

    def __init__(self, rows: list):
        self.rows = {row["id"]: row for row in rows}
        self.names = {}
        for row in rows:
            if row["subject_kind"] == "interface" and row["field"] == "name":
                self.names.setdefault((row["probe_id"], row["subject_anchor"]), set()).add(
                    json.loads(row["value_json"]))

    def subject(self, evidence_id: str) -> dict:
        row = self.rows[evidence_id]
        anchor = json.loads(row["subject_anchor"])
        value = json.loads(row["value_json"])
        if row["subject_kind"] == "device" and anchor["kind"] == "alias":
            return {"kind": "device", "anchor": anchor}
        if row["subject_kind"] == "route":
            return {"kind": "route", **value}
        names = self.names.get((row["probe_id"], row["subject_anchor"]), set())
        if row["subject_kind"] in {"interface", "address"} and len(names) == 1:
            return {"kind": "interface", "anchor": anchor, "name": next(iter(names))}
        if row["subject_kind"] == "interface" and row["field"] == "name":
            return {"kind": "interface", "anchor": anchor, "name": value}
        # MAC-less field labels and colliding anchors cannot safely associate
        # address/state rows with any one interface, even in the same batch.
        return {"kind": row["subject_kind"], "anchor": anchor, "probe_id": row["probe_id"],
                "field": row["field"], "value": value}


def _category(entry: dict, subjects: Subjects) -> str:
    return "topology" if subjects.rows[entry["evidence_id"]]["subject_kind"] == "route" else "identity"


def _groups(entries: list[dict], subjects: Subjects) -> list:
    groups = {}
    for entry in entries:
        key = (_category(entry, subjects), entry["reason"])
        groups.setdefault(key, []).append(entry)
    def priority(key):
        conflict = any(entry.get("candidate_device_ids") for entry in groups[key])
        return (0 if conflict else 1 if key[0] == "topology" else 2, key)
    return [(key, sorted(groups[key], key=lambda entry: (not bool(entry.get("candidate_device_ids")),
                                                        entry["evidence_id"])))
            for key in sorted(groups, key=priority)]


def summarize(entries: list[dict], subjects: Subjects, limit: int, temporal_scope: str) -> dict:
    """Count observations separately from diagnostic subjects; sample, never embed overflow."""
    groups = _groups(entries, subjects)
    reasons, all_subjects = [], set()
    for (category, reason), members in groups:
        grouped = {}
        for entry in members:
            subject = subjects.subject(entry["evidence_id"])
            key = encode(subject)
            grouped.setdefault(key, {"subject": subject, "evidence_id": entry["evidence_id"], "observation_count": 0})
            grouped[key]["observation_count"] += 1
        all_subjects.update(grouped)
        examples = list(grouped.values())[:min(3, limit)]
        reasons.append({"category": category, "reason": reason, "observation_count": len(members),
                        "conflicting_observation_count": sum(
                            bool(entry.get("candidate_device_ids")) for entry in members),
                        "subject_count": len(grouped), "subjects": examples,
                        "omitted_subject_count": len(grouped) - len(examples)})
    return {"temporal_scope": temporal_scope, "observation_count": len(entries), "subject_count": len(all_subjects),
            "reason_count": len(reasons), "reasons": reasons[:limit],
            "omitted_reason_count": max(0, len(reasons) - limit)}


def reconciliation_reply(store: Store, result: dict, rows: list | None = None) -> dict:
    """Project saved application diagnostics without altering its receipt or audit counts."""
    if not result.get("unresolved") and not result.get("conflicting"):
        return result
    rows = original_rows(store, result["batch_id"]) if rows is None else rows
    subjects = Subjects(rows)
    entries = result.get("unresolved", [])
    limit = min(5, store.policy.limits.result_count)
    groups = _groups(entries, subjects)
    # One representative of each priority/reason before repetitive field rows.
    ordered = [members[0] for _, members in groups]
    ordered += [entry for _, members in groups for entry in members[1:]]
    conflicts = {}
    for entry in result.get("conflicting", []):
        conflicts.setdefault(entry["reason"], []).append(entry)
    conflict_sample = [members[0] for members in conflicts.values()]
    conflict_sample += [entry for members in conflicts.values() for entry in members[1:]]
    return {**result, "unresolved": ordered[:limit], "unresolved_total_count": len(entries),
            "unresolved_omitted_count": max(0, len(entries) - limit),
            "conflicting": conflict_sample[:limit],
            "conflicting_total_count": len(result.get("conflicting", [])),
            "conflicting_omitted_count": max(0, len(result.get("conflicting", [])) - limit),
            "uncertainty": summarize(entries, subjects, limit, "at_application"),
            "evidence_query": {"view": "unresolved", "batch_id": result["batch_id"], "limit": limit},
            "current_summary_query": {"view": "unresolved", "batch_id": result["batch_id"], "summary": True}}
