# SPDX-License-Identifier: GPL-3.0-or-later
"""Separate proposal paths: model inference versus trusted local operator CLI.

These validated envelopes are consumed inside Atlas Core's audited transaction.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from collections.abc import Mapping

from .config import NAME_PATTERN, Policy
from .schemas import TOOL_UPDATE_FIELDS, UPDATE_FIELDS
from .facts import RELATION_TYPES

DEVICE_TYPES = ("router", "switch", "access_point", "hypervisor", "server", "desktop", "laptop",
                "nas", "vm", "lxc", "iot", "printer", "unknown")


@dataclass(frozen=True)
class Update:
    """Immutable scalar proposal. Source is code-owned, never taken from the payload."""

    device_id: str
    field: str
    value: str | bool | tuple[tuple[str, str], ...]
    source: str
    confidence: str
    explanation: str | None


def _text(value: object, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError("update text must be nonempty and within the configured bound")
    return value


def _relation(value: object, policy: Policy) -> tuple[tuple[str, str], ...]:
    keys = {"target_device", "relationship_type", "source_interface", "target_interface"}
    if not isinstance(value, dict) or not {"target_device", "relationship_type"} <= set(value) <= keys:
        raise ValueError("typed relationship endpoints required")
    for key, item in value.items():
        if not isinstance(item, str) or re.fullmatch(NAME_PATTERN, item) is None:
            raise ValueError("invalid relationship endpoint or type")
        if len(item) > policy.limits.input_chars:
            raise ValueError("relationship input exceeds configured bound")
    if value["relationship_type"] not in RELATION_TYPES:
        raise ValueError("invalid relationship type")
    return tuple(sorted(value.items()))


def _validate_value(field: str, value: object, policy: Policy) -> str | bool | tuple[tuple[str, str], ...]:
    """Check semantic scalar types and alias association without granting permission."""
    if field == "relationship":
        return _relation(value, policy)
    if field == "retired":
        if type(value) is not bool:
            raise ValueError("retired requires boolean value")
        return value
    text = _text(value, policy.limits.input_chars)
    if field == "device_type" and text not in DEVICE_TYPES:
        raise ValueError("invalid device type")
    if field == "ssh_alias" and text not in policy.authorized_aliases:
        raise ValueError("alias association requires existing local inspection authorization")
    return text


def _validate(params: object, policy: Policy, *, operator: bool) -> Update:
    keys = {"device_id", "field", "value"} | (set() if operator else {"explanation"})
    if not isinstance(params, Mapping) or set(params) != keys:
        raise ValueError("update requires exactly the documented arguments")
    device_id = params["device_id"]
    if not isinstance(device_id, str) or re.fullmatch(NAME_PATTERN, device_id) is None:
        raise ValueError("invalid device ID")
    field = params["field"]
    allowed = UPDATE_FIELDS if operator else TOOL_UPDATE_FIELDS
    if not isinstance(field, str) or field not in allowed:
        raise ValueError("unsupported update field for this origin")
    value = _validate_value(field, params["value"], policy)
    explanation = None if operator else _text(params["explanation"], policy.limits.input_chars)
    return Update(device_id, field, value, "user" if operator else "inference",
                  "user_supplied" if operator else "inferred", explanation)


def inference_update(params: object, policy: Policy) -> Update:
    """Model-callable path: inference only; retirement and provenance claims fail closed."""
    return _validate(params, policy, operator=False)


def operator_update(params: object, policy: Policy) -> Update:
    """Trusted native local CLI path only; not registered as a model tool or slash update."""
    return _validate(params, policy, operator=True)
