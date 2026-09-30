# SPDX-License-Identifier: GPL-3.0-or-later
"""Separate proposal paths: model inference versus trusted local operator CLI.

These immutable envelopes are validation results, not database writes. Atlas Core
will consume the validated envelope inside its audited transaction boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from collections.abc import Mapping

from .config import NAME_PATTERN, Policy
from .schemas import TOOL_UPDATE_FIELDS, UPDATE_FIELDS

DEVICE_TYPES = ("router", "switch", "access_point", "hypervisor", "server", "desktop", "laptop",
                "nas", "vm", "lxc", "iot", "printer", "unknown")


@dataclass(frozen=True)
class Update:
    """Immutable scalar proposal. Source is code-owned, never taken from the payload."""

    device_id: str
    field: str
    value: str | bool
    source: str
    confidence: str
    explanation: str | None


def _text(value: object, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError("update text must be nonempty and within the configured bound")
    return value


def _validate_value(field: str, value: object, policy: Policy) -> str | bool:
    """Check semantic scalar types and alias association without granting permission."""
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
