# SPDX-License-Identifier: GPL-3.0-or-later
"""Compact diagnostics over immutable originals, never canonical identity.

A subject belongs to one batch/origin. Interface names qualify anchors; ambiguous
labels stay separate rather than pretending that field observations are devices.
"""
from __future__ import annotations

import json

from .facts import ORIGINAL_EVIDENCE_COLUMNS, checked_evidence
from .storage import Store, encode


def original_rows(store: Store, batch_id: str) -> list:
    """Keep summary work within the existing single-batch observation ceiling."""
    rows = store.connection.execute(
        "SELECT " + ORIGINAL_EVIDENCE_COLUMNS + " FROM observations o "
        "WHERE o.batch_id=? AND o.entity_id IS NULL ORDER BY o.id LIMIT ?",
        (store.policy.limits.output_bytes + 1,) * 3 + (batch_id, store.policy.limits.observations + 1)).fetchall()
    if len(rows) > store.policy.limits.observations:
        raise ValueError("uncertainty summary exceeds configured observation bound")
    for row in rows:
        checked_evidence(store, row)
    return rows


def validate_entry(entry: object, *, evidence_required: bool = True) -> None:
    """Validate one saved diagnostic; some conflict records have no evidence ID."""
    if not isinstance(entry, dict):
        raise ValueError("invalid stored application")
    if evidence_required or "evidence_id" in entry:
        if not isinstance(entry.get("evidence_id"), str):
            raise ValueError("invalid stored application")
    candidates = entry.get("candidate_device_ids", [])
    if (not isinstance(entry.get("reason"), str) or not isinstance(candidates, list)
            or any(not isinstance(candidate, str) for candidate in candidates)):
        raise ValueError("invalid stored application")


def validate_application(store: Store, result: object, batch_id: str) -> None:
    """Validate shape and exact original membership before diagnostic indexing.

    Indexed ID lookups avoid loading a whole batch for a paginated detail read;
    the receipt byte ceiling and operation deadline still bound validation work.
    """
    if not isinstance(result, dict) or result.get("batch_id", batch_id) != batch_id:
        raise ValueError("invalid stored application")
    checked = set()
    for name in ("unresolved", "conflicting"):
        entries = result.get(name, [])
        if not isinstance(entries, list):
            raise ValueError("invalid stored application")
        for entry in entries:
            store.check_deadline()
            validate_entry(entry, evidence_required=name == "unresolved")
            evidence_id = entry.get("evidence_id")
            if evidence_id is None or evidence_id in checked:
                continue
            if store.connection.execute(
                    "SELECT 1 FROM observations WHERE id=? AND batch_id=? AND entity_id IS NULL",
                    (evidence_id, batch_id)).fetchone() is None:
                raise ValueError("invalid stored application evidence membership")
            checked.add(evidence_id)


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


def reconciliation_reply(store: Store, batch_id: str, result: dict, rows: list | None = None) -> dict:
    """Project saved application diagnostics without altering its receipt or audit counts."""
    validate_application(store, result, batch_id)
    if not result.get("unresolved") and not result.get("conflicting"):
        return result
    rows = original_rows(store, batch_id) if rows is None else rows
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
    conflict_reasons = [{"reason": reason, "conflict_record_count": len(members)}
                        for reason, members in sorted(conflicts.items())]
    # Conflicts need not reference originals: evidence pages cannot recover them.
    saved_conflicts = result.get("conflicting", [])
    return {**result, "unresolved": ordered[:limit], "unresolved_total_count": len(entries),
            "unresolved_omitted_count": max(0, len(entries) - limit),
            "conflicting": saved_conflicts, "conflicting_total_count": len(saved_conflicts),
            "conflicting_omitted_count": 0,
            "uncertainty": {"conflict_record_count": len(saved_conflicts),
                            "conflict_reasons": conflict_reasons[:limit],
                            "conflict_reason_count": len(conflict_reasons),
                            "omitted_conflict_reason_count": max(0, len(conflict_reasons) - limit),
                            **summarize(entries, subjects, limit, "at_application")},
            "evidence_query": {"view": "unresolved", "batch_id": batch_id, "limit": limit},
            "current_summary_query": {"view": "unresolved", "batch_id": batch_id, "summary": True}}
