# SPDX-License-Identifier: GPL-3.0-or-later
"""Model-facing bounded schemas; authority/provenance are never parameters."""

UPDATE_FIELDS = (
    "canonical_name", "description", "device_type", "hostname", "os", "ssh_alias", "relationship", "retired")
TOOL_UPDATE_FIELDS = tuple(field for field in UPDATE_FIELDS if field != "retired")

QUERY_SCHEMA = {
    "name": "network_query",
    "description": ("Read stored device inventory (hostname, OS, interfaces, addresses and provenance), endpoints, "
                    "relations or history. Use view=status for bounded currently authorized next actions when "
                    "inventory is empty; view=unresolved explains original evidence and identity lineage. "
                    "After inspect/discover, reconcile the returned batch_id before querying device IDs. "
                    "Historical evidence establishes neither current reachability nor access. Never collects."),
    "parameters": {
        "type": "object", "additionalProperties": False,
        "properties": {
            "view": {"type": "string", "enum": ["devices", "status", "history", "unresolved", "endpoints"]},
            "batch_id": {"type": "string", "maxLength": 64, "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$",
                         "description": ("Optional exact stored batch filter for unresolved/endpoints views; "
                                         "foreign origin remains read-only knowledge.")},
            **{key: {"type": "string", "maxLength": 4096} for key in
               ("device_id", "name", "address", "device_type", "status", "access_method",
                "relationship", "related_to", "text")},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            "offset": {"type": "integer", "minimum": 0, "maximum": 10000},
        },
        "required": [],
    },
}

UPDATE_SCHEMA = {
    "name": "network_update",
    "description": ("Persist an explained inference about an existing device. "
                    "Does not override operator-owned facts, retire devices, or grant permission."),
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
    "description": ("Render stored inventory and supported relationships after reconciliation; never collects. "
                    "Isolated devices mean no supported links, not disconnection. For empty inventory use "
                    "network_query view=status for guidance; no invented links or live reachability claims. "
                    "Optional export explicitly writes fixed profile-local files."),
    "parameters": {"type": "object", "additionalProperties": False,
                   "properties": {"format": {"type": "string", "enum": ["text", "markdown", "mermaid"]},
                                  "export": {"type": "boolean"}}, "required": []},
}

DISCOVER_SCHEMA = {
    "name": "network_discover",
    "description": ("Collect bounded LAN host/interface/address evidence only for a currently enabled configured "
                    "network/mode. Passive neighbors are cached, not reachability; IP-only responses cannot "
                    "establish device identity. Does not apply inventory: pass returned batch_id to "
                    "network_reconcile, then network_query/network_map. For hostname/OS inventory of an "
                    "authorized SSH alias use network_inspect instead."),
    "parameters": {"type": "object", "additionalProperties": False,
                   "properties": {"network": {"type": "string", "maxLength": 64},
                                  "mode": {"type": "string", "enum": ["passive", "ping"]}},
                   "required": ["network", "mode"]},
}

RECONCILE_SCHEMA = {
    "name": "network_reconcile",
    "description": ("Apply a stored currently authorized local LAN/SSH batch to canonical devices, interfaces "
                    "and addresses; use the exact batch_id returned by network_inspect/network_discover "
                    "(or omit for latest eligible unapplied). Query returned device IDs and render network_map "
                    "afterward. IP-only/conflicting identity remains unresolved; endpoint batches use their "
                    "own resume path, not reconciliation. Never collects. Exact retries are idempotent; "
                    "missing means not observed, never offline/deleted."),
    "parameters": {"type": "object", "additionalProperties": False,
                   "properties": {"batch_id": {"type": "string", "maxLength": 64}}, "required": []},
}

INSPECT_SCHEMA = {
    "name": "network_inspect",
    "description": ("Obtain Linux machine inventory (hostname, OS, owned interfaces and IPv4/IPv6 addresses) "
                    "from one currently authorized configured SSH alias, even with no existing device ID, "
                    "or a uniquely mapped device. Uses fixed read-only probes and stores an immutable attempt. "
                    "Does not apply inventory: pass returned batch_id to network_reconcile, then query its "
                    "device IDs and render network_map. Does not create topology or grant access."),
    "parameters": {"type": "object", "additionalProperties": False,
                   "properties": {"target": {"type": "string", "minLength": 1, "maxLength": 64,
                                              "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"}},
                   "required": ["target"]},
}

ENDPOINT_SCHEMA = {
    "name": "network_check_endpoints",
    "description": ("Check separately enabled configured TCP endpoints, persist, project and read back historical "
                    "evidence. Select network, no-contact resume batch_id, read-only preview_batch_id, OR "
                    "explicit continue_batch_id to make NEW TCP checks of remaining unattempted work. "
                    "Read stored results via network_query view=endpoints. TCP responses do not create device "
                    "identity or machine inventory; use authorized network_inspect for that. "
                    "No service identity, greetings or SSH authority."),
    "parameters": {"type": "object", "additionalProperties": False,
                   "properties": {key: {"type": "string", "maxLength": 64,
                                        "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"}
                                  for key in ("network", "batch_id", "preview_batch_id", "continue_batch_id")},
                   "oneOf": [{"required": [key]} for key in
                             ("network", "batch_id", "preview_batch_id", "continue_batch_id")]},
}
