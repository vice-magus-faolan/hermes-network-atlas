# SPDX-License-Identifier: GPL-3.0-or-later
"""Model-facing contract gate schemas; authority/provenance are never parameters."""

UPDATE_FIELDS = ("canonical_name", "description", "device_type", "hostname", "os", "ssh_alias", "retired")
TOOL_UPDATE_FIELDS = tuple(field for field in UPDATE_FIELDS if field != "retired")

QUERY_SCHEMA = {
    "name": "network_query",
    "description": "Read Network Atlas scaffold/policy readiness only. No inventory, persistence, or collection yet.",
    "parameters": {
        "type": "object", "additionalProperties": False,
        "properties": {"view": {"type": "string", "enum": ["status"]}},
        "required": ["view"],
    },
}

UPDATE_SCHEMA = {
    "name": "network_update",
    "description": "Validate an inference proposal only; nothing is applied or persisted in this scaffold. Cannot attest operator origin or grant permissions.",
    "parameters": {
        "type": "object", "additionalProperties": False,
        "properties": {
            "device_id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$", "maxLength": 64},
            "field": {"type": "string", "enum": list(TOOL_UPDATE_FIELDS)},
            "value": {"type": "string", "minLength": 1, "maxLength": 4096},
            "explanation": {"type": "string", "minLength": 1, "maxLength": 4096},
        },
        "required": ["device_id", "field", "value", "explanation"],
    },
}
