# SPDX-License-Identifier: GPL-3.0-or-later
"""Interface-first identity lookups. Never merge by address or hostname."""
from __future__ import annotations

import re
import sqlite3


def mac_address(value: object) -> tuple[str, bool]:
    """Canonicalize a MAC; local/randomized, multicast and zero MACs are not anchors."""
    if not isinstance(value, str) or re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value) is None:
        raise ValueError("six-octet MAC required")
    mac = value.lower()
    first = int(mac[:2], 16)
    stable = first & 3 == 0 and mac != "00:00:00:00:00:00"
    return mac, stable


def resolve_mac(connection: sqlite3.Connection, value: str) -> dict:
    """A unique stable MAC identifies an interface, not all interfaces on a host."""
    mac, stable = mac_address(value)
    rows = connection.execute("SELECT id,device_id FROM interfaces WHERE mac_address=? ORDER BY id", (mac,)).fetchall()
    resolved = stable and len(rows) == 1
    return {"resolved": resolved, "interface_id": rows[0]["id"] if resolved else None,
            "device_id": rows[0]["device_id"] if resolved else None,
            "candidates": [dict(row) for row in rows],
            "reason": "stable_mac" if resolved else "colliding_or_unstable_mac"}


def resolve_alias(connection: sqlite3.Connection, context: str, alias: str) -> dict:
    """Only a context-qualified operator/direct association can anchor identity."""
    rows = connection.execute("""SELECT DISTINCT a.device_id FROM aliases a JOIN observations o
      ON o.id=a.observation_id WHERE a.policy_context=? AND a.alias=?
      AND (o.confidence='user_supplied' OR (o.confidence='observed' AND o.qualified=1)) ORDER BY a.device_id""",
                              (context, alias)).fetchall()
    return {"resolved": len(rows) == 1, "device_id": rows[0][0] if len(rows) == 1 else None,
            "candidates": [row[0] for row in rows], "reason": "alias_anchor" if len(rows) == 1 else "unresolved_alias"}
