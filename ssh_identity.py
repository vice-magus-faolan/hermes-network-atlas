# SPDX-License-Identifier: GPL-3.0-or-later
"""Current-policy SSH destination resolution. Knowledge and permission are separate."""
from __future__ import annotations

import re

from .config import NAME_PATTERN, Policy
from .storage import Store


def alias_candidates(store: Store, alias: str) -> list[str]:
    """Only this context's operator/qualified direct alias mappings anchor a device."""
    rows = store.connection.execute("""SELECT DISTINCT a.device_id FROM aliases a JOIN observations o
      ON o.id=a.observation_id WHERE a.policy_context=? AND a.alias=?
      AND (o.confidence='user_supplied' OR (o.confidence='observed' AND o.qualified=1))
      ORDER BY a.device_id LIMIT ?""", (str(store.policy.home), alias, store.policy.limits.result_count + 1)).fetchall()
    if len(rows) > store.policy.limits.result_count:
        raise ValueError("alias candidates exceed bound")
    return [row[0] for row in rows]


def _mapped_alias(store: Store, device: str) -> str:
    store.require("devices", device)
    rows = store.connection.execute("SELECT alias FROM aliases WHERE device_id=? AND policy_context=? ORDER BY alias LIMIT ?",
                                    (device, str(store.policy.home), store.policy.limits.result_count + 1)).fetchall()
    if len(rows) > store.policy.limits.result_count:
        raise ValueError("device alias count exceeds bound")
    eligible = [row[0] for row in rows if row[0] in store.policy.authorized_aliases
                and alias_candidates(store, row[0]) == [device]]
    if len(eligible) != 1:
        raise ValueError("device requires one unambiguous locally authorized alias")
    return eligible[0]


def resolve_in_store(store: Store, target: str) -> str:
    """Resolve only configured aliases or exact stable device IDs, never hostnames/IPs."""
    if target in store.policy.authorized_aliases:
        if len(alias_candidates(store, target)) > 1:
            raise ValueError("ambiguous alias association")
        return target
    return _mapped_alias(store, target)


def resolve_target(policy: Policy, params: object, deadline: float) -> str:
    """Exact schema validation precedes read-only mapping lookup and all transport."""
    if not isinstance(params, dict) or set(params) != {"target"}:
        raise ValueError("target required, no other arguments")
    target = params["target"]
    if not isinstance(target, str) or re.fullmatch(NAME_PATTERN, target) is None:
        raise ValueError("invalid configured alias or device ID")
    if len(target) > policy.limits.input_chars or not policy.authorized_aliases:
        raise ValueError("no current local inspection authorization")
    if not policy.database.exists():
        if target not in policy.authorized_aliases:
            raise ValueError("unknown authorized alias or device")
        return target
    with Store(policy, deadline=deadline) as store, store.snapshot():
        return resolve_in_store(store, target)
