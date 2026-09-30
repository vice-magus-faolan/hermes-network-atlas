# SPDX-License-Identifier: GPL-3.0-or-later
"""Per-field selection and evidence-qualified freshness, shared by query and map."""
from __future__ import annotations

from datetime import datetime, timedelta
import json
import sqlite3

from .storage import timestamp

OPERATOR_FIELDS = ("canonical_name", "description", "device_type", "retired")
DEVICE_FIELDS = (*OPERATOR_FIELDS, "hostname", "os", "manufacturer", "ssh_alias")
INTERFACE_FIELDS = ("name", "interface_type", "state", "mac_address")
RELATION_TYPES = ("physical", "virtual", "parent", "bridge_member", "routes_via", "hosted_on", "unknown")


def selection_cte(now: datetime, stale_days: int) -> tuple[str, tuple[str, str]]:
    """SQL selects latest assertions per source then keeps every top-tier disagreement.

    Same-time writes from one source follow append order. Ordering across sources
    is presentation only: multiple distinct top-tier values produce no winner.
    Unqualified observations remain evidence, not canonical direct facts.
    """
    cutoff = timestamp(now - timedelta(days=stale_days))
    current = timestamp(now)
    sql = """WITH latest AS (
      SELECT *, ROW_NUMBER() OVER (
        PARTITION BY subject_kind,entity_id,field,source,confidence,qualified
        ORDER BY observed_at DESC,rowid DESC) AS seq
      FROM observations WHERE entity_id IS NOT NULL AND observed_at<=?
    ), ranked AS (
      SELECT *, CASE
        WHEN field IN ('canonical_name','description','device_type','retired')
          THEN CASE WHEN confidence='user_supplied' THEN 0 ELSE 9 END
        WHEN field IN ('relationship','ssh_alias')
          THEN CASE WHEN confidence='user_supplied' THEN 0
                    WHEN confidence='observed' AND qualified=1 THEN 1 ELSE 3 END
        WHEN confidence='observed' AND qualified=1 AND observed_at>=? THEN 0
        WHEN confidence='user_supplied' THEN 1
        WHEN confidence='observed' AND qualified=1 THEN 2
        WHEN confidence='inferred' THEN 3 ELSE 9 END AS tier
      FROM latest WHERE seq=1
    ), best AS (
      SELECT subject_kind,entity_id,field,MIN(tier) AS tier FROM ranked WHERE tier<9
      GROUP BY subject_kind,entity_id,field
    ), chosen AS (
      SELECT r.* FROM ranked r JOIN best b
       ON r.subject_kind=b.subject_kind AND r.entity_id=b.entity_id AND r.field=b.field AND r.tier=b.tier
    ), canonical AS (
      SELECT subject_kind,entity_id,field,
        CASE WHEN COUNT(DISTINCT value_json)=1 THEN MIN(value_json) ELSE NULL END AS value_json,
        COUNT(DISTINCT value_json)>1 AS conflict FROM chosen
      GROUP BY subject_kind,entity_id,field
    ) """
    return sql, (current, cutoff)


def selected_facts(connection: sqlite3.Connection, kind: str, entity: str,
                   now: datetime, stale_days: int, maximum: int = 100) -> dict:
    """Expose canonical values, winning provenance, assertions, and explicit conflicts."""
    cte, params = selection_cte(now, stale_days)
    rows = connection.execute(cte + "SELECT * FROM chosen WHERE subject_kind=? AND entity_id=? "
                              "ORDER BY field,source,observed_at,id LIMIT ?", (*params, kind, entity, maximum + 1)).fetchall()
    if len(rows) > maximum:
        raise ValueError("canonical evidence exceeds configured result bound")
    fields = {}
    for row in rows:
        item = fields.setdefault(row["field"], {"value": None, "conflict": False, "evidence": []})
        item["evidence"].append(evidence(row))
    for item in fields.values():
        values = {json.dumps(entry["value"], sort_keys=True) for entry in item["evidence"]}
        item["conflict"] = len(values) > 1
        if not item["conflict"]:
            item["value"] = item["evidence"][0]["value"]
    return fields


def evidence(row: sqlite3.Row) -> dict:
    """Return bounded stored values with their actual provenance, not authority claims."""
    return {"id": row["id"], "field": row["field"], "value": json.loads(row["value_json"]),
            "source": row["source"], "confidence": row["confidence"], "observed_at": row["observed_at"],
            "evidence_kind": row["evidence_kind"], "qualified": bool(row["qualified"]),
            "explanation": row["explanation"], "neighbor_state": row["neighbor_state"]}


def freshness(row: sqlite3.Row, now: datetime, stale_days: int) -> str:
    """Age is read-only; no assertion or failed check manufactures a positive sighting."""
    if row["retired"]:
        return "retired"
    if row["last_seen"] is None:
        return "known"
    if row["last_seen"] < timestamp(now - timedelta(days=stale_days)):
        return "stale"
    return "observed"
