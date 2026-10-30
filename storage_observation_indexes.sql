-- SPDX-License-Identifier: GPL-3.0-or-later
-- Bound originals by batch and cover DISTINCT canonical entities at one anchor.
CREATE INDEX observation_batch ON observations(batch_id,subject_kind,subject_anchor,entity_id);
PRAGMA user_version=6;
