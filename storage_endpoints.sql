-- SPDX-License-Identifier: GPL-3.0-or-later
-- Additive v1 -> v2. Original batches/probes/observations remain byte-for-byte.
CREATE TABLE endpoint_observations (
 probe_id TEXT PRIMARY KEY REFERENCES probes(id),
 address TEXT NOT NULL, protocol TEXT NOT NULL CHECK(protocol='tcp'),
 port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535 AND port != 4403),
 state TEXT NOT NULL CHECK(state IN ('open','closed','no_response','unavailable','not_started')),
 qualified INTEGER NOT NULL CHECK(qualified IN (0,1))
);
CREATE INDEX endpoint_address ON endpoint_observations(address,port);
PRAGMA user_version=2;
