-- SPDX-License-Identifier: GPL-3.0-or-later
CREATE INDEX relation_source_device ON relations(source_device);
CREATE INDEX relation_target_device ON relations(target_device);
PRAGMA user_version=5;
