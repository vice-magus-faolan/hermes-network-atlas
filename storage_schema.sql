-- SPDX-License-Identifier: GPL-3.0-or-later
CREATE TABLE devices (
 id TEXT PRIMARY KEY, created_at TEXT NOT NULL, retired INTEGER NOT NULL DEFAULT 0 CHECK(retired IN (0,1)),
 first_seen TEXT, last_seen TEXT, last_checked TEXT
);
CREATE TABLE interfaces (
 id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id),
 mac_address TEXT, stable_mac INTEGER NOT NULL CHECK(stable_mac IN (0,1)), created_at TEXT NOT NULL
);
CREATE INDEX interface_mac ON interfaces(mac_address);
CREATE TABLE batches (
 id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL CHECK(schema_version=1), collector TEXT NOT NULL,
 source TEXT NOT NULL, policy_context TEXT NOT NULL, scope_kind TEXT NOT NULL, scope_name TEXT NOT NULL,
 scope_value TEXT NOT NULL, started_at TEXT NOT NULL, ended_at TEXT NOT NULL, completion TEXT NOT NULL
);
CREATE TABLE probes (
 id TEXT PRIMARY KEY, batch_id TEXT NOT NULL REFERENCES batches(id), probe_name TEXT NOT NULL,
 outcome TEXT NOT NULL, started_at TEXT NOT NULL, ended_at TEXT NOT NULL, coverage_kind TEXT NOT NULL,
 coverage_value TEXT NOT NULL, evidence_kind TEXT NOT NULL, absence_eligible INTEGER NOT NULL CHECK(absence_eligible IN (0,1)),
 diagnostic_code TEXT NOT NULL
);
CREATE TABLE observations (
 id TEXT PRIMARY KEY, batch_id TEXT REFERENCES batches(id), probe_id TEXT REFERENCES probes(id),
 subject_kind TEXT NOT NULL, subject_anchor TEXT NOT NULL, entity_id TEXT,
 field TEXT NOT NULL, value_json TEXT NOT NULL, source TEXT NOT NULL,
 confidence TEXT NOT NULL CHECK(confidence IN ('observed','inferred','user_supplied')),
 observed_at TEXT NOT NULL, evidence_kind TEXT NOT NULL, explanation TEXT, neighbor_state TEXT,
 qualified INTEGER NOT NULL CHECK(qualified IN (0,1)),
 CHECK(confidence != 'inferred' OR length(explanation)>0)
);
CREATE INDEX fact_lookup ON observations(subject_kind,entity_id,field,source,observed_at);
CREATE TABLE addresses (
 id TEXT PRIMARY KEY, interface_id TEXT NOT NULL REFERENCES interfaces(id), address TEXT NOT NULL,
 prefix_length INTEGER NOT NULL, address_family INTEGER NOT NULL CHECK(address_family IN (4,6)),
 source TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
 observation_id TEXT NOT NULL REFERENCES observations(id), ended_at TEXT,
 UNIQUE(interface_id,address,prefix_length,source,first_seen)
);
CREATE INDEX address_lookup ON addresses(address,ended_at);
CREATE TABLE relations (
 id TEXT PRIMARY KEY, source_device TEXT NOT NULL REFERENCES devices(id),
 source_interface TEXT REFERENCES interfaces(id), target_device TEXT NOT NULL REFERENCES devices(id),
 target_interface TEXT REFERENCES interfaces(id), relationship_type TEXT NOT NULL,
 observation_id TEXT NOT NULL REFERENCES observations(id)
);
CREATE TABLE aliases (
 id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id), policy_context TEXT NOT NULL,
 alias TEXT NOT NULL, observation_id TEXT NOT NULL REFERENCES observations(id),
 UNIQUE(device_id,policy_context,alias)
);
CREATE TABLE access_evidence (
 id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id), policy_context TEXT NOT NULL,
 alias TEXT NOT NULL, succeeded INTEGER NOT NULL CHECK(succeeded IN (0,1)), checked_at TEXT NOT NULL,
 diagnostic_code TEXT NOT NULL, batch_id TEXT REFERENCES batches(id)
);
CREATE TABLE applications (
 id TEXT PRIMARY KEY, batch_id TEXT NOT NULL UNIQUE REFERENCES batches(id),
 schema_version INTEGER NOT NULL CHECK(schema_version=1), applied_at TEXT NOT NULL, result_json TEXT NOT NULL
);
CREATE TABLE audit_events (
 id TEXT PRIMARY KEY, operation_id TEXT NOT NULL, batch_id TEXT REFERENCES batches(id),
 timestamp TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, entity_id TEXT,
 details_json TEXT NOT NULL
);
PRAGMA user_version=1;
