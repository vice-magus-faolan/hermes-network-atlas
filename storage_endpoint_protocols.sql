-- SPDX-License-Identifier: GPL-3.0-or-later
-- v3 -> v4: widen projection constraints, preserving every immutable value.
CREATE TABLE endpoint_protocols (
 probe_id TEXT PRIMARY KEY REFERENCES probes(id),
 address TEXT NOT NULL, protocol TEXT NOT NULL CHECK(protocol IN ('tcp','udp')),
 port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535 AND port != 4403
                            AND (protocol != 'udp' OR port NOT IN (7,19))),
 state TEXT NOT NULL CHECK(state IN ('open','closed','no_response','unavailable','not_started')),
 qualified INTEGER NOT NULL CHECK(qualified IN (0,1))
);
INSERT INTO endpoint_protocols SELECT * FROM endpoint_observations;
DROP TABLE endpoint_observations;
ALTER TABLE endpoint_protocols RENAME TO endpoint_observations;
CREATE INDEX endpoint_address ON endpoint_observations(address,protocol,port);
PRAGMA user_version=4;
