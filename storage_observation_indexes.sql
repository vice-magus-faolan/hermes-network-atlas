-- SPDX-License-Identifier: GPL-3.0-or-later
-- Bound both reads by batch, with NULL entities in rowid order without a sort.
CREATE INDEX observation_batch ON observations(batch_id,entity_id);
PRAGMA user_version=6;
