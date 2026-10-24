# SPDX-License-Identifier: GPL-3.0-or-later
"""Separate proposal paths: model inference versus trusted local operator CLI.

These validated envelopes are consumed inside Atlas Core's audited transaction.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from collections.abc import Mapping

from .config import NAME_PATTERN, Policy
from .errors import RequestError
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


def _text(value: object, limit: int, label: str = "text") -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise RequestError(f"{label}: nonempty text within limits.input_chars required")
    return value


def _relation(value: object, policy: Policy) -> tuple[tuple[str, str], ...]:
    keys = {"target_device", "relationship_type", "source_interface", "target_interface"}
    if not isinstance(value, dict) or not {"target_device", "relationship_type"} <= set(value) <= keys:
        raise RequestError("value.relationship: target_device and relationship_type required; only documented endpoints supported")
    for key, item in value.items():
        if not isinstance(item, str) or re.fullmatch(NAME_PATTERN, item) is None:
            raise RequestError("value.relationship: endpoints and type must be stable names")
        if len(item) > policy.limits.input_chars:
            raise RequestError("value.relationship: shorten endpoints to limits.input_chars")
    if value["relationship_type"] not in RELATION_TYPES:
        raise RequestError("value.relationship_type: choose a documented relationship type")
    return tuple(sorted(value.items()))


def _validate_value(field: str, value: object, policy: Policy) -> str | bool | tuple[tuple[str, str], ...]:
    """Check semantic scalar types and alias association without granting permission."""
    if field == "relationship":
        return _relation(value, policy)
    if field == "retired":
        if type(value) is not bool:
            raise RequestError("value.retired: boolean required")
        return value
    text = _text(value, policy.limits.input_chars, "value")
    if field == "device_type" and text not in DEVICE_TYPES:
        raise RequestError("value.device_type: choose a documented device type")
    if field == "ssh_alias" and text not in policy.authorized_aliases:
        raise RequestError("value.ssh_alias: existing local inspection authorization required")
    return text


def _validate(params: object, policy: Policy, *, operator: bool) -> Update:
    keys = {"device_id", "field", "value"} | (set() if operator else {"explanation"})
    if not isinstance(params, Mapping) or set(params) != keys:
        raise RequestError("update arguments: device_id, field and value required; inference also requires explanation; no other arguments")
    device_id = params["device_id"]
    if not isinstance(device_id, str) or re.fullmatch(NAME_PATTERN, device_id) is None:
        raise RequestError("device_id: stable atlas device ID required")
    field = params["field"]
    allowed = UPDATE_FIELDS if operator else TOOL_UPDATE_FIELDS
    if not isinstance(field, str) or field not in allowed:
        raise RequestError("field: choose a documented update field permitted for this origin")
    value = _validate_value(field, params["value"], policy)
    explanation = None if operator else _text(params["explanation"], policy.limits.input_chars, "explanation")
    return Update(device_id, field, value, "user" if operator else "inference",
                  "user_supplied" if operator else "inferred", explanation)


def inference_update(params: object, policy: Policy) -> Update:
    """Model-callable path: inference only; retirement and provenance claims fail closed."""
    return _validate(params, policy, operator=False)


def operator_update(params: object, policy: Policy) -> Update:
    """Trusted native local CLI path only; not registered as a model tool or slash update."""
    return _validate(params, policy, operator=True)
