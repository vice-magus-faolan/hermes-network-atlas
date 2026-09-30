# SPDX-License-Identifier: GPL-3.0-or-later
"""Model-facing bounded schemas; authority/provenance are never parameters."""

UPDATE_FIELDS = ("canonical_name", "description", "device_type", "hostname", "os", "ssh_alias", "relationship", "retired")
TOOL_UPDATE_FIELDS = tuple(field for field in UPDATE_FIELDS if field != "retired")

QUERY_SCHEMA = {
    "name": "network_query",
    "description": "Read stored devices, relations, provenance or status. Never performs discovery.",
    "parameters": {
        "type": "object", "additionalProperties": False,
        "properties": {
            "view": {"type": "string", "enum": ["devices", "status", "history"]},
            **{key: {"type": "string", "maxLength": 4096} for key in
               ("device_id", "name", "address", "device_type", "status", "access_method", "relationship", "related_to", "text")},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            "offset": {"type": "integer", "minimum": 0, "maximum": 10000},
        },
        "required": [],
    },
}

UPDATE_SCHEMA = {
    "name": "network_update",
    "description": "Persist an explained inference about an existing device. Does not override operator-owned facts, retire devices, or grant permission.",
    "parameters": {
        "type": "object", "additionalProperties": False,
        "properties": {
            "device_id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$", "maxLength": 64},
            "field": {"type": "string", "enum": list(TOOL_UPDATE_FIELDS)},
            "value": {"oneOf": [
                {"type": "string", "minLength": 1, "maxLength": 4096},
                {"type": "object", "additionalProperties": False,
                 "properties": {key: {"type": "string", "maxLength": 64} for key in
                                ("target_device", "relationship_type", "source_interface", "target_interface")},
                 "required": ["target_device", "relationship_type"]},
            ]},
            "explanation": {"type": "string", "minLength": 1, "maxLength": 4096},
        },
        "required": ["device_id", "field", "value", "explanation"],
    },
}

MAP_SCHEMA = {
    "name": "network_map",
    "description": "Render stored topology without invented links or live reachability claims. Optional fixed profile-local exports.",
    "parameters": {"type": "object", "additionalProperties": False,
                   "properties": {"format": {"type": "string", "enum": ["text", "markdown", "mermaid"]},
                                  "export": {"type": "boolean"}}, "required": []},
}
