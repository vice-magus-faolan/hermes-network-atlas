-- SPDX-License-Identifier: GPL-3.0-or-later
-- Reserve a successor before traffic. A missing child is intentionally uncertain,
-- never an implicit invitation to repeat effects after a crash.
CREATE TABLE endpoint_continuations (
    parent_batch_id TEXT PRIMARY KEY REFERENCES batches(id),
    child_batch_id TEXT NOT NULL UNIQUE,
    selection_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
PRAGMA user_version=3;
