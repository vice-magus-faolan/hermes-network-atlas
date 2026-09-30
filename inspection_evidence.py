# SPDX-License-Identifier: GPL-3.0-or-later
"""Read immutable inspection attempts without transport, reconciliation, or grants."""
from __future__ import annotations

import sqlite3

from .storage import Store


def most_recent_inspection(attempt: dict | None, record: sqlite3.Row | None) -> dict | None:
    """Keep older stored native access primitives compatible with raw attempt answers."""
    if record is not None and (attempt is None or record["checked_at"] > attempt["checked_at"]):
        return dict(record)
    return attempt


def latest_inspection(store: Store, alias: str | None = None) -> dict | None:
    """Expose this context's last persisted attempt even before canonical application.

    Success means at least one fixed probe returned valid parsed output, not every
    capability or current access. Failed/missing probes remain explicitly visible.
    No device is fabricated merely to persist an unsuccessful alias-only attempt.
    """
    where, args = "", (str(store.policy.home),)
    if alias is not None:
        where, args = " AND scope_value=?", (*args, alias)
    batch = store.connection.execute("SELECT * FROM batches WHERE collector='ssh' AND policy_context=?" + where +
                                     " ORDER BY ended_at DESC,rowid DESC LIMIT 1", args).fetchone()
    if batch is None:
        return None
    rows = store.connection.execute("SELECT probe_name,outcome,diagnostic_code FROM probes WHERE batch_id=? ORDER BY rowid LIMIT ?",
                                     (batch["id"], store.policy.limits.observations + 1)).fetchall()
    if len(rows) > store.policy.limits.observations:
        raise ValueError("inspection probe detail exceeds bound")
    succeeded = any(row["outcome"] == "success" for row in rows)
    return {"batch_id": batch["id"], "alias": batch["scope_value"], "policy_context": batch["policy_context"],
            "checked_at": batch["ended_at"], "completion": batch["completion"], "succeeded": succeeded,
            "diagnostic_code": "parsed_probe_succeeded" if succeeded else "no_successful_probe",
            "probes": [dict(row) for row in rows]}
