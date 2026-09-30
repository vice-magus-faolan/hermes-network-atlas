# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic Phase 1 evidence for A02/A04/A05/A06/A10/A11/A12; no live data."""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import importlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from helpers import ROOT, load_package, scratch_home
from test_boundaries import synthetic_policy

load_package()
config = importlib.import_module("atlas_test_plugin.config")
storage = importlib.import_module("atlas_test_plugin.storage")
core = importlib.import_module("atlas_test_plugin.core")
updates = importlib.import_module("atlas_test_plugin.updates")
query = importlib.import_module("atlas_test_plugin.query")
identity = importlib.import_module("atlas_test_plugin.identity")
render = importlib.import_module("atlas_test_plugin.render")
batches = importlib.import_module("atlas_test_plugin.batches")
commands = importlib.import_module("atlas_test_plugin.commands")
tools = importlib.import_module("atlas_test_plugin.tools")
facts = importlib.import_module("atlas_test_plugin.facts")
NOW = datetime(2026, 9, 30, 12, tzinfo=timezone.utc)


class AtlasFixture(unittest.TestCase):
    def setUp(self):
        self.temp = scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.raw = synthetic_policy()
        self.raw["limits"] = {"busy_timeout_ms": 100}
        self.policy = config.validate_policy(self.raw, self.home)
        self.store = storage.Store(self.policy, writable=True)
        self.addCleanup(self.store.__exit__)
        self.device = core.create_device(self.store, "Synthetic router", now=NOW)["device_id"]
        (self.home / "network-atlas" / "config.yaml").write_text(json.dumps(self.raw))

    def update(self, field, value, *, operator=True, device=None, now=NOW):
        params = {"device_id": device or self.device, "field": field, "value": value}
        envelope = updates.operator_update(params, self.policy) if operator else updates.inference_update(
            {**params, "explanation": "synthetic inference explanation"}, self.policy)
        return core.apply_update(self.store, envelope, now=now)

    def detail(self, *, now=NOW, device=None):
        return query.query(self.policy, {"device_id": device or self.device}, now=now)["devices"][0]

    def cli(self, argv):
        parser = argparse.ArgumentParser()
        commands.setup_parser(parser)
        output = io.StringIO()
        with redirect_stdout(output):
            code = commands.run_command(parser.parse_args(argv), self.home)
        return code, json.loads(output.getvalue())

    def counts(self):
        return {name: self.store.connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
                for name in ("devices", "interfaces", "addresses", "observations", "relations", "aliases",
                             "access_evidence", "audit_events", "batches", "probes")}


class PersistenceTests(AtlasFixture):
    def test_initial_schema_creation_failure_rolls_back_and_reopens(self):
        policy = config.validate_policy({}, self.home / "initialization-failure")
        original = storage._initialize_locked
        def interrupted(connection):
            original(connection)
            raise RuntimeError("synthetic schema interruption")
        with patch.object(storage, "_initialize_locked", interrupted), self.assertRaises(RuntimeError):
            storage.Store(policy, writable=True)
        with sqlite3.connect(policy.database) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0], 0)
        with storage.Store(policy, writable=True) as reopened:
            self.assertEqual(reopened.connection.execute("PRAGMA user_version").fetchone()[0], 1)

    def test_schema_foreign_keys_private_files_read_only(self):
        self.assertEqual(self.store.connection.execute("PRAGMA user_version").fetchone()[0], 1)
        self.assertEqual(self.store.connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertEqual(self.policy.database.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.policy.database.parent.stat().st_mode & 0o777, 0o700)
        for path in self.policy.database.parent.glob("atlas.sqlite3*"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with storage.Store(self.policy) as reader:
            with self.assertRaises(sqlite3.OperationalError):
                reader.connection.execute("DELETE FROM devices")
        with self.store.transaction(), self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute("INSERT INTO interfaces VALUES (?,?,?,?,?)", ("bad", "missing", None, 0, storage.timestamp(NOW)))
        self.assertEqual(self.detail()["status"], "known")
        self.assertIsNone(self.detail()["last_seen"])

    def test_mutation_audit_failure_rolls_back_all_state(self):
        before = self.counts()
        with patch.object(self.store, "audit", side_effect=RuntimeError("synthetic interruption")), self.assertRaises(RuntimeError):
            self.update("description", "Must roll back")
        self.assertEqual(self.counts(), before)
        with storage.Store(self.policy) as reopened:
            self.assertEqual(reopened.connection.execute("SELECT COUNT(*) FROM observations").fetchone()[0], before["observations"])
        with self.store.transaction():
            self.store.audit(storage.identifier(), "test", "user", storage.timestamp(NOW))

    def test_interrupt_rolls_back_and_busy_writer_is_bounded(self):
        with storage.Store(self.policy, writable=True) as second:
            before = self.counts()
            with self.assertRaises(KeyboardInterrupt):
                with self.store.transaction():
                    self.store.connection.execute("UPDATE devices SET retired=1 WHERE id=?", (self.device,))
                    raise KeyboardInterrupt()
            self.assertFalse(self.detail()["retired"])
            with self.store.transaction():
                started = time.monotonic()
                with self.assertRaises(sqlite3.OperationalError):
                    core.create_device(second, "Blocked writer", now=NOW)
                self.assertLess(time.monotonic() - started, 1.5)
                self.assertEqual(query.query(self.policy, {}, now=NOW)["devices"][0]["id"], self.device)
            self.assertEqual(self.counts(), before)
            core.create_device(second, "Successful second writer", now=NOW)
        self.assertEqual(self.counts()["devices"], before["devices"] + 1)

    def test_version_refusal_does_not_mutate_future_or_unversioned_db(self):
        for version in (0, 2):
            home = self.home / f"bad-{version}"
            policy = config.validate_policy({}, home)
            policy.database.parent.mkdir(parents=True)
            with sqlite3.connect(policy.database) as connection:
                connection.execute("CREATE TABLE sentinel(value TEXT)")
                connection.execute(f"PRAGMA user_version={version}")
            before = policy.database.read_bytes()
            with self.assertRaises(ValueError):
                storage.Store(policy, writable=True)
            self.assertEqual(policy.database.read_bytes(), before)
            with self.assertRaises(ValueError):
                storage.Store(policy)

    def test_immutable_observation_history_and_audit(self):
        old = self.update("description", "Original operator fact")
        self.update("description", "Replacement", now=NOW + timedelta(seconds=1))
        self.assertEqual(self.detail(now=NOW + timedelta(seconds=1))["fields"]["description"]["value"], "Replacement")
        row = self.store.connection.execute("SELECT * FROM observations WHERE id=?", (old["observation_id"],)).fetchone()
        self.assertEqual(json.loads(row["value_json"]), "Original operator fact")
        for table in ("observations", "audit_events"):
            for operation in ("UPDATE", "DELETE"):
                sql = f"UPDATE {table} SET id=id" if operation == "UPDATE" else f"DELETE FROM {table}"
                with self.store.transaction(), self.assertRaises(sqlite3.IntegrityError):
                    self.store.connection.execute(sql)

    def test_fresh_process_reopen_preserves_manual_seed_query_history_access_and_map(self):
        other = core.create_device(self.store, "Synthetic hypervisor", now=NOW)["device_id"]
        core.create_device(self.store, "Synthetic isolated workstation", now=NOW)
        iface = core.add_interface(self.store, self.device, "eth0", "00:11:22:33:44:55", now=NOW)
        core.add_address(self.store, iface, "192.0.2.10", 24, now=NOW)
        self.update("ssh_alias", "lab-router")
        self.update("relationship", {"target_device": other, "relationship_type": "hosted_on"})
        batches.record_access(self.store, self.device, "lab-router", False, "host_key_failed", now=NOW)
        (self.home / "synthetic-phase1-home").touch()
        expected = query.query(self.policy, {}, now=NOW)
        self.assertEqual(len(expected["devices"]), 3)
        expected_map = render.render_map(self.policy, now=NOW)
        child = subprocess.run([sys.executable, str(ROOT / "scripts" / "phase1_reopen.py"), str(self.home)],
                               cwd=self.home, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                                   "TMPDIR": os.environ["TMPDIR"], "HOME": str(self.home / "user"),
                                                   "HERMES_HOME": str(self.home), "PYTHONDONTWRITEBYTECODE": "1"},
                               capture_output=True, text=True, timeout=30)
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        result = json.loads(child.stdout)
        self.assertEqual(result["query"], expected)
        self.assertEqual(result["map"], expected_map)
        self.assertEqual(result["history_count"], self.counts()["observations"])


class IdentityAndProvenanceTests(AtlasFixture):
    def test_unqualified_evidence_not_promoted_by_source_text(self):
        self.update("os", "Operator OS")
        with self.store.transaction():
            observation = core.append_fact(self.store, "device", self.device, "os", "Unqualified OS", "ssh:lab-router",
                                           "observed", storage.timestamp(NOW), evidence_kind="cached_neighbor")
            self.store.audit(storage.identifier(), "unqualified_fixture", "test", storage.timestamp(NOW),
                             details={"observation_id": observation})
        self.assertEqual(self.detail()["fields"]["os"]["value"], "Operator OS")
        self.assertIsNone(self.detail()["last_seen"])
        with self.assertRaises(ValueError):
            core.append_fact(self.store, "device", self.device, "os", "Bad", "user", "user_supplied", storage.timestamp(NOW))
        with self.store.transaction(), self.assertRaises(ValueError):
            core.append_fact(self.store, "device", self.device, "os", "Bad", "ssh:lab-router", "observed", storage.timestamp(NOW),
                             qualified=True, evidence_kind="cached_neighbor")

    def test_ip_hostname_never_merge_and_mac_anchors_interface_only(self):
        other = core.create_device(self.store, "Synthetic router", now=NOW)["device_id"]
        first = core.add_interface(self.store, self.device, "eth0", "00:11:22:33:44:55", now=NOW)
        second = core.add_interface(self.store, other, "eth0", "00:11:22:33:44:66", now=NOW)
        for interface in (first, second):
            core.add_address(self.store, interface, "192.0.2.10", 24, now=NOW)
        for device in (self.device, other):
            self.update("hostname", "same-hostname", device=device)
        self.assertEqual(self.counts()["devices"], 2)
        self.assertTrue(self.detail()["interfaces"][0]["addresses"][0]["ownership_conflict"])
        result = identity.resolve_mac(self.store.connection, "00:11:22:33:44:55")
        self.assertEqual(result["interface_id"], first)
        core.add_address(self.store, first, "192.0.2.11", 24, now=NOW + timedelta(seconds=1))
        self.assertEqual(identity.resolve_mac(self.store.connection, "00:11:22:33:44:55"), result)
        self.assertEqual(len(self.detail()["interfaces"][0]["addresses"]), 2)
        core.add_interface(self.store, self.device, "eth1", "00:11:22:33:44:77", now=NOW)
        self.assertEqual(len(self.detail()["interfaces"]), 2)

    def test_randomized_and_colliding_macs_remain_unresolved(self):
        first = core.add_interface(self.store, self.device, "wifi0", "02:11:22:33:44:55", now=NOW)
        self.assertFalse(identity.resolve_mac(self.store.connection, "02:11:22:33:44:55")["resolved"])
        core.add_interface(self.store, self.device, "eth0", "00:11:22:33:44:55", now=NOW)
        other = core.create_device(self.store, "Other", now=NOW)["device_id"]
        core.add_interface(self.store, other, "eth0", "00:11:22:33:44:55", now=NOW)
        self.assertFalse(identity.resolve_mac(self.store.connection, "00:11:22:33:44:55")["resolved"])
        self.assertIsNotNone(first)
        self.assertTrue(all(item["identity_uncertain"] for item in self.detail()["interfaces"]))

    def test_alias_anchor_requires_operator_same_context_and_no_ambiguity(self):
        self.update("ssh_alias", "lab-router", operator=False)
        self.assertFalse(identity.resolve_alias(self.store.connection, str(self.home), "lab-router")["resolved"])
        self.update("ssh_alias", "lab-router")
        self.assertEqual(identity.resolve_alias(self.store.connection, str(self.home), "lab-router")["device_id"], self.device)
        self.assertFalse(identity.resolve_alias(self.store.connection, str(self.home / "another"), "lab-router")["resolved"])
        other = core.create_device(self.store, "Other", now=NOW)["device_id"]
        self.update("ssh_alias", "lab-router", device=other)
        self.assertFalse(identity.resolve_alias(self.store.connection, str(self.home), "lab-router")["resolved"])
        self.assertEqual(query.query(self.policy, {"access_method": "ssh"}, now=NOW)["devices"], [])

    def test_field_precedence_assertions_preserved_and_same_source_supersession(self):
        self.update("description", "Operator description")
        self.update("description", "Inferred replacement", operator=False, now=NOW + timedelta(seconds=1))
        self.assertEqual(self.detail(now=NOW + timedelta(seconds=1))["fields"]["description"]["value"], "Operator description")
        self.update("os", "Operator OS")
        core.record_direct_fact(self.store, "device", self.device, "os", "Direct OS", "ssh:lab-router", "ssh_response", now=NOW)
        self.assertEqual(self.detail()["fields"]["os"]["value"], "Direct OS")
        later = NOW + timedelta(days=15)
        self.assertEqual(self.detail(now=later)["fields"]["os"]["value"], "Operator OS")
        history = query.query(self.policy, {"view": "history", "device_id": self.device}, now=later)["observations"]
        inferred = next(item for item in history if item["confidence"] == "inferred")
        self.assertEqual(inferred["explanation"], "synthetic inference explanation")
        self.assertTrue(any(item["value"] == "Direct OS" for item in history))
        self.assertEqual(self.detail(now=later)["status"], "stale")
        core.record_direct_fact(self.store, "device", self.device, "os", "Direct OS 2", "ssh:lab-router", "ssh_response", now=later)
        self.assertEqual(self.detail(now=later)["fields"]["os"]["value"], "Direct OS 2")

    def test_equal_rank_cross_source_disagreement_has_no_arbitrary_winner(self):
        for source, value, day in (("ssh:lab-router", "one", 0), ("local_passive", "two", 1)):
            core.record_direct_fact(self.store, "device", self.device, "hostname", value, source, "ssh_response", now=NOW + timedelta(days=day))
        result = self.detail(now=NOW + timedelta(days=1))["fields"]["hostname"]
        self.assertTrue(result["conflict"])
        self.assertIsNone(result["value"])
        self.assertEqual({entry["value"] for entry in result["evidence"]}, {"one", "two"})
        self.assertEqual(query.query(self.policy, {"text": "one"}, now=NOW + timedelta(days=1))["devices"], [])

    def test_retirement_operator_only_sticky_reactivation_and_clocks(self):
        self.update("retired", True)
        for field in ("description", "hostname", "os"):
            self.update(field, "Assertion")
        self.assertIsNone(self.detail()["last_seen"])
        core.record_direct_fact(self.store, "device", self.device, "hostname", "Seen", "ssh:lab-router", "ssh_response", now=NOW)
        self.assertEqual(self.detail()["status"], "retired")
        self.assertEqual(self.detail()["first_seen"], storage.timestamp(NOW))
        self.update("retired", False, now=NOW + timedelta(seconds=1))
        self.assertEqual(self.detail(now=NOW + timedelta(seconds=1))["status"], "observed")

    def test_current_and_historical_addresses_do_not_steal_identity(self):
        interface = core.add_interface(self.store, self.device, "eth0", now=NOW)
        old = core.add_address(self.store, interface, "192.0.2.1", 24, now=NOW)
        core.add_address(self.store, interface, "2001:db8::1", 64, now=NOW)
        core.end_address(self.store, old, now=NOW + timedelta(seconds=1))
        self.assertEqual(len(self.detail()["interfaces"][0]["addresses"]), 2)
        self.assertFalse(next(item for item in self.detail()["interfaces"][0]["addresses"] if item["id"] == old)["current"])
        self.assertEqual(query.query(self.policy, {"address": "192.0.2.1"}, now=NOW)["devices"], [])
        self.assertEqual(query.query(self.policy, {"address": "2001:db8::1"}, now=NOW)["devices"][0]["id"], self.device)


class QueryUpdateMapTests(AtlasFixture):
    def set_output_limit(self, maximum):
        self.raw["limits"]["output_bytes"] = maximum
        (self.home / "network-atlas" / "config.yaml").write_text(json.dumps(self.raw))

    def test_update_receipts_refuse_overflow_without_mutation(self):
        self.set_output_limit(512)
        handler = tools.Handlers(self.home)
        for value, explanation in (("x" * 4096, "e" * 4096), ("雪" * 64, "Unicode expansion"),
                                   ('"\\' * 64, "JSON escaping")):
            with self.subTest(value=value):
                before = self.counts()
                result = handler.update({"device_id": self.device, "field": "os", "value": value,
                                         "explanation": explanation})
                self.assertIn("error", json.loads(result))
                self.assertEqual(self.counts(), before)
                self.assertLessEqual(len(result.encode("utf-8")), 512)

    def test_update_receipt_exact_byte_boundary_and_success_control(self):
        handler = tools.Handlers(self.home)
        params = {"device_id": self.device, "field": "os", "value": "雪", "explanation": 'JSON "\\ 雪'}
        result = handler.update(params)
        receipt = json.loads(result)
        self.assertTrue(receipt["persisted"])
        self.assertEqual(receipt["update"]["value"], "雪")
        size = len(result.encode("utf-8"))
        self.set_output_limit(size - 1)
        before = self.counts()
        self.assertIn("error", json.loads(handler.update(params)))
        self.assertEqual(self.counts(), before)
        self.set_output_limit(size)
        result = handler.update(params)
        self.assertTrue(json.loads(result)["applied"])
        self.assertEqual(len(result.encode("utf-8")), size)
        self.assertEqual(self.counts()["observations"], before["observations"] + 1)
        self.assertEqual(self.counts()["audit_events"], before["audit_events"] + 1)

    def test_cli_update_and_validation_receipt_bounds(self):
        self.set_output_limit(512)
        for action in ("update", "validate-update"):
            for value in ("x" * 4096, "雪" * 64, '"\\' * 128):
                with self.subTest(action=action, value=value):
                    before = self.counts()
                    code, result = self.cli([action, "--device-id", self.device, "--field", "os",
                                             "--value-json", json.dumps(value)])
                    self.assertEqual(code, 2)
                    self.assertIn("error", result)
                    self.assertEqual(self.counts(), before)
        for action in ("update", "validate-update"):
            code, result = self.cli([action, "--device-id", self.device, "--field", "os", "--value-json", '"ok"'])
            self.assertEqual(code, 0)
            self.assertEqual(result["persisted"], action == "update")

    def test_cli_fixed_mutation_receipts_refuse_before_state_changes(self):
        interface = core.add_interface(self.store, self.device, "eth0", now=NOW)
        assignment = core.add_address(self.store, interface, "192.0.2.1", 24, now=NOW)
        self.set_output_limit(32)
        for argv in (["create", "--name", "No partial device"],
                     ["interface", "--device-id", self.device, "--name", "eth1"],
                     ["address", "--interface-id", interface, "--address", "192.0.2.2", "--prefix-length", "24"],
                     ["end-address", "--assignment-id", assignment]):
            with self.subTest(argv=argv):
                before = self.counts()
                code, result = self.cli(argv)
                self.assertEqual(code, 2)
                self.assertFalse(result["applied"])
                self.assertEqual(self.counts(), before)
                self.assertIsNone(self.store.connection.execute("SELECT ended_at FROM addresses WHERE id=?", (assignment,)).fetchone()[0])

    def test_cli_status_respects_output_bound(self):
        self.set_output_limit(128)
        code, result = self.cli(["status"])
        self.assertEqual(code, 2)
        self.assertIn("error", result)
        self.set_output_limit(4096)
        self.assertEqual(self.cli(["status"])[0], 0)

    def test_cli_update_exact_stdout_bound_includes_newline(self):
        argv = ["update", "--device-id", self.device, "--field", "os", "--value-json", json.dumps('雪"\\')]
        code, result = self.cli(argv)
        self.assertEqual(code, 0)
        expected = json.dumps(result, sort_keys=True) + "\n"
        size = len(expected.encode("utf-8"))
        self.set_output_limit(size - 1)
        before = self.counts()
        self.assertEqual(self.cli(argv)[0], 2)
        self.assertEqual(self.counts(), before)
        self.set_output_limit(size)
        parser = argparse.ArgumentParser()
        commands.setup_parser(parser)
        output = io.StringIO()
        with redirect_stdout(output):
            code = commands.run_command(parser.parse_args(argv), self.home)
        self.assertEqual(code, 0)
        self.assertEqual(len(output.getvalue().encode("utf-8")), size)
        self.assertTrue(json.loads(output.getvalue())["persisted"])

    def test_receipt_overflow_rolls_back_alias_retirement_and_relationship(self):
        other = core.create_device(self.store, "Synthetic endpoint", now=NOW)["device_id"]
        self.set_output_limit(32)
        for field, value in (("ssh_alias", "lab-router"), ("retired", True),
                             ("relationship", {"target_device": other, "relationship_type": "hosted_on"})):
            with self.subTest(field=field):
                before = self.counts()
                code, result = self.cli(["update", "--device-id", self.device, "--field", field,
                                         "--value-json", json.dumps(value)])
                self.assertEqual(code, 2)
                self.assertFalse(result["applied"])
                self.assertEqual(self.counts(), before)
                self.assertFalse(self.detail()["retired"])

    def test_alias_ambiguity_visible_in_every_map_and_export(self):
        self.update("ssh_alias", "lab-router")
        control = render.render_map(self.policy, now=NOW)
        for content in control.values():
            self.assertNotIn("uncertain", content)
            self.assertNotIn("ambiguous alias association", content)
        self.assertIn("Atlas SSH inspection authorized: lab-router", control["text"])
        other = core.create_device(self.store, "Alias collision", now=NOW)["device_id"]
        self.update("ssh_alias", "lab-router", device=other)
        before = self.counts()
        outputs = render.render_map(self.policy, now=NOW)
        self.assertEqual(render.render_map(self.policy, now=NOW), outputs)
        for format_name, content in outputs.items():
            with self.subTest(format=format_name):
                self.assertEqual(content.count("uncertain"), 2)
                self.assertEqual(content.count("ambiguous alias association"), 2)
                self.assertNotIn("Atlas SSH inspection authorized:", content)
        self.assertNotIn(" --> ", outputs["mermaid"])
        self.assertEqual(self.counts(), before)
        for device in query.query(self.policy, {}, now=NOW)["devices"]:
            self.assertEqual(device["interfaces"], [])
            self.assertTrue(device["access"][0]["ambiguous_association"])
            self.assertFalse(device["access"][0]["authorized_for_atlas_ssh_inspection"])
        self.assertEqual(query.query(self.policy, {"access_method": "ssh"}, now=NOW)["devices"], [])
        files = render.export_map(self.policy, outputs, now=NOW)
        for path, format_name in zip(files, ("markdown", "mermaid")):
            self.assertEqual(Path(path).read_text(), outputs[format_name])

    def test_golden_text_markdown_mermaid_and_negative_label_cases(self):
        fixture = json.loads((ROOT / "tests" / "fixtures" / "render-golden.json").read_text())
        empty = config.validate_policy({}, self.home / "empty")
        outputs = render.render_map(empty, now=NOW)
        for format_name in ("text", "markdown", "mermaid"):
            self.assertEqual(outputs[format_name], fixture[format_name + "_empty"])
        self.assertEqual(render.markdown(fixture["hostile_label"]), fixture["markdown_label"])
        self.assertEqual(render.mermaid(fixture["hostile_label"]), fixture["mermaid_label"])
        for format_name in ("text", "markdown", "mermaid"):
            self.update("canonical_name", 'Injected\n\x1b[31m\"] --> evil["X"]')
            output = render.render_map(self.policy, now=NOW)[format_name]
            self.assertNotIn("\x1b", output)
        self.assertFalse(empty.home.exists())

    def test_unicode_hostname_search_read_only_files_and_export_preflight(self):
        self.update("hostname", "雪-host")
        self.assertEqual(query.query(self.policy, {"text": "雪"}, now=NOW)["devices"][0]["id"], self.device)
        self.assertEqual(query.query(self.policy, {"name": "雪-host"}, now=NOW)["devices"][0]["id"], self.device)
        before = {path.name: path.read_bytes() for path in self.policy.database.parent.glob("atlas.sqlite3*")}
        self.detail()
        after = {path.name: path.read_bytes() for path in self.policy.database.parent.glob("atlas.sqlite3*")}
        self.assertEqual(before, after)
        self.raw["limits"]["output_bytes"] = 1
        (self.home / "network-atlas" / "config.yaml").write_text(json.dumps(self.raw))
        self.assertIn("error", json.loads(tools.Handlers(self.home).map({"export": True})))
        self.assertFalse(self.policy.exports.exists())

    def test_query_filters_pagination_and_literal_sql_like_injection(self):
        other = core.create_device(self.store, "Synthetic hypervisor", now=NOW)["device_id"]
        self.update("device_type", "router")
        self.update("description", "100%_literal ' OR 1=1 --")
        self.update("ssh_alias", "lab-router")
        interface = core.add_interface(self.store, self.device, "eth0", now=NOW)
        core.add_address(self.store, interface, "192.0.2.10", 24, now=NOW)
        self.update("relationship", {"target_device": other, "relationship_type": "hosted_on"})
        for filters in ({"name": "router"}, {"device_type": "router"}, {"address": "192.0.2.10"},
                        {"access_method": "ssh"}, {"text": "%_literal"}, {"device_id": self.device},
                        {"relationship": "hosted_on", "related_to": other}):
            with self.subTest(filters=filters):
                self.assertEqual(query.query(self.policy, filters, now=NOW)["devices"][0]["id"], self.device)
        self.assertEqual(query.query(self.policy, {"name": "' OR 1=1 --"}, now=NOW)["devices"], [])
        first = query.query(self.policy, {"limit": 1}, now=NOW)
        second = query.query(self.policy, {"limit": 1, "offset": 1}, now=NOW)
        self.assertTrue(first["has_more"])
        self.assertFalse(second["has_more"])
        self.assertNotEqual(first["devices"][0]["id"], second["devices"][0]["id"])
        before = self.counts()
        with patch("subprocess.Popen", side_effect=AssertionError("query must not collect")):
            self.detail()
            render.render_map(self.policy, now=NOW)
        self.assertEqual(self.counts(), before)

    def test_unknown_invalid_lowered_bounds_and_history_pagination(self):
        for params in ({"limit": True}, {"limit": 101}, {"offset": -1}, {"offset": 10001}, {"text": "x" * 4097},
                       {"status": "offline"}, {"source": "user"}, {"network": "lab"}, {"view": "history"},
                       {"view": "status", "name": "x"}):
            with self.subTest(params=params), self.assertRaises(ValueError):
                query.query(self.policy, params, now=NOW)
        lowered = config.validate_policy({"limits": {"result_count": 1, "input_chars": 2}}, self.home)
        with self.assertRaises(ValueError):
            query.query(lowered, {"limit": 2}, now=NOW)
        with self.assertRaises(ValueError):
            query.query(lowered, {"text": "abc"}, now=NOW)
        self.update("os", "one")
        self.update("os", "two", now=NOW + timedelta(seconds=1))
        first = query.query(self.policy, {"view": "history", "device_id": self.device, "limit": 1}, now=NOW)
        self.assertTrue(first["has_more"])
        self.assertEqual(len(first["observations"]), 1)

    def test_tool_provenance_no_policy_edits_existing_reference_required(self):
        handlers = tools.Handlers(self.home)
        params = {"device_id": self.device, "field": "description", "value": "Model proposal", "explanation": "Model rationale"}
        receipt = json.loads(handlers.update(params, source="user", confidence="user_supplied", operator=True))
        self.assertTrue(receipt["persisted"])
        self.assertEqual(receipt["update"]["source"], "inference")
        self.assertNotIn("description", self.detail()["fields"])
        for change in ({"source": "user"}, {"field": "retired", "value": True}, {"field": "limits"},
                       {"device_id": "missing"}, {"field": "ssh_alias", "value": "unauthorized"}):
            before = self.counts()
            self.assertIn("error", json.loads(handlers.update({**params, **change})))
            self.assertEqual(self.counts(), before)
        self.assertIn("error", json.loads(handlers.command("update --source user")))

    def test_cli_create_operator_update_and_validated_interface_relations(self):
        code, created = self.cli(["create", "--name", "Manual seed"])
        self.assertEqual(code, 0)
        code, result = self.cli(["update", "--device-id", created["device_id"], "--field", "description", "--value-json", '"Operator fact"'])
        self.assertEqual(code, 0)
        self.assertEqual(result["update"]["confidence"], "user_supplied")
        interface = core.add_interface(self.store, self.device, "eth0", now=NOW)
        other_interface = core.add_interface(self.store, created["device_id"], "eth0", now=NOW)
        for value in ({"target_device": "missing", "relationship_type": "physical"},
                      {"target_device": self.device, "relationship_type": "parent"},
                      {"target_device": created["device_id"], "source_interface": other_interface, "relationship_type": "virtual"}):
            before = self.counts()
            with self.assertRaises(ValueError):
                self.update("relationship", value)
            self.assertEqual(self.counts(), before)
        self.update("relationship", {"target_device": created["device_id"], "source_interface": interface,
                                    "target_interface": other_interface, "relationship_type": "virtual"})
        self.assertEqual(len(self.detail()["relationships"]), 1)

    def test_render_deterministic_escaped_isolated_stale_and_inferred_edges(self):
        hostile = 'Host\"] --> evil["X\"]\n%%{init: {securityLevel: loose}}%% <script>|`雪'
        self.update("canonical_name", hostile)
        other = core.create_device(self.store, "Isolated node", now=NOW)["device_id"]
        core.record_direct_fact(self.store, "device", self.device, "hostname", "Seen", "ssh:lab-router", "ssh_response", now=NOW)
        before = render.render_map(self.policy, now=NOW + timedelta(days=15))
        self.assertIn("stale", before["text"])
        self.assertIn("isolated", before["text"])
        self.assertNotIn(" --> ", before["mermaid"])
        self.assertNotIn("%%{init", before["mermaid"])
        self.assertNotIn("<script>", before["markdown"])
        self.assertNotIn("|`", before["markdown"])
        self.assertIn("#34;", before["mermaid"])
        self.assertEqual(render.render_map(self.policy, now=NOW + timedelta(days=15)), before)
        self.update("relationship", {"target_device": other, "relationship_type": "hosted_on"}, operator=False)
        after = render.render_map(self.policy, now=NOW + timedelta(days=15))
        self.assertIn("inferred", after["markdown"])
        self.assertEqual(after["mermaid"].count("-.->"), 1)
        files = render.export_map(self.policy, after, now=NOW)
        self.assertEqual([Path(path).name for path in files], ["network_map.md", "network_map.mmd"])
        for path, format_name in zip(files, ("markdown", "mermaid")):
            self.assertEqual(Path(path).read_text(), after[format_name])
            self.assertEqual(Path(path).stat().st_mode & 0o777, 0o600)
        render.export_map(self.policy, after, now=NOW)
        self.assertEqual(Path(files[0]).read_text(), after["markdown"])

    def test_map_rejects_arbitrary_export_path_symlink_and_oversized_output(self):
        handler = tools.Handlers(self.home)
        for params in ({"path": "/bad"}, {"format": []}, {"export": "true"}):
            self.assertIn("error", json.loads(handler.map(params)))
        small = config.validate_policy({"limits": {"output_bytes": 1}}, self.home)
        with self.assertRaises(ValueError):
            render.render_map(small, now=NOW)
        render.export_map(self.policy, render.render_map(self.policy, now=NOW), now=NOW)
        destination = self.policy.exports / "network_map.md"
        destination.unlink()
        outside = self.home / "untouched.txt"
        outside.write_text("sentinel")
        destination.symlink_to(outside)
        with self.assertRaises(ValueError):
            render.export_map(self.policy, render.render_map(self.policy, now=NOW), now=NOW)
        self.assertEqual(outside.read_text(), "sentinel")

    def test_shared_knowledge_never_transfers_inspection_authority(self):
        self.update("ssh_alias", "lab-router")
        batches.record_access(self.store, self.device, "lab-router", False, "timeout", now=NOW)
        second = config.validate_policy({"store": {"shared_sqlite_path": str(self.policy.database)}}, self.home / "second")
        shared = query.query(second, {}, now=NOW)["devices"][0]
        self.assertEqual(shared["id"], self.device)
        self.assertFalse(shared["access"][0]["authorized_for_atlas_ssh_inspection"])
        self.assertIsNone(shared["access"][0]["last_inspection"])
        self.assertFalse(second.home.exists())
        self.assertEqual(query.query(second, {"access_method": "ssh"}, now=NOW)["devices"], [])
        self.assertFalse(self.detail()["access"][0]["last_inspection"]["succeeded"])
        self.assertFalse(query.query(self.policy, {"view": "status"}, now=NOW)["last_inspection"]["succeeded"])
        self.assertIsNone(self.detail()["last_seen"])
        with self.assertRaises(ValueError):
            updates.operator_update({"device_id": self.device, "field": "ssh_alias", "value": "lab-router"}, second)


class BatchTests(AtlasFixture):
    def test_observation_enum_and_alias_scope_validation(self):
        at = storage.timestamp(NOW)
        before = self.counts()
        for kind, field, value in (("device", "device_type", "administrator"),
                                   ("interface", "interface_type", "shell"),
                                   ("interface", "mac_address", "not-a-mac"),
                                   ("device", "retired", "true")):
            observation = batches.Observation(kind, batches.Anchor("unresolved", "synthetic"), field, value, at)
            with self.assertRaises(ValueError):
                batches.store_batch(self.store, "local_passive", "lab", at, at, "complete", (self.probe(observations=(observation,)),))
        observation = batches.Observation("device", batches.Anchor("alias", "lab-router", str(self.home)), "hostname", "test", at)
        with self.assertRaises(ValueError):
            batches.store_batch(self.store, "local_passive", "lab", at, at, "complete", (self.probe(observations=(observation,)),))
        self.assertEqual(self.counts(), before)

    def test_partial_batch_positive_evidence_without_absence_or_state_application(self):
        at = storage.timestamp(NOW)
        observation = batches.Observation("device", batches.Anchor("unresolved", "synthetic-unresolved"),
                                          "hostname", "Synthetic response", at)
        success = batches.Probe("ping", "success", at, at, "exact_network", "192.0.2.0/24", "ping_response", observations=(observation,))
        failure = batches.Probe("optional", "timeout", at, at, "none", "", "none", "timeout")
        batch = batches.store_batch(self.store, "ping", "lab", at, at, "partial", (success, failure))
        rows = self.store.connection.execute("SELECT * FROM probes WHERE batch_id=?", (batch,)).fetchall()
        self.assertTrue(all(not row["absence_eligible"] for row in rows))
        self.assertEqual(self.store.connection.execute("SELECT COUNT(*) FROM observations WHERE batch_id=?", (batch,)).fetchone()[0], 1)
        self.assertIsNone(self.detail()["last_seen"])
        self.assertEqual(self.counts()["devices"], 1)
        with storage.Store(self.policy) as reopened:
            self.assertEqual(reopened.require("batches", batch)["completion"], "partial")

    def test_batch_observation_limits_alias_context_and_duplicate_typed_values(self):
        at = storage.timestamp(NOW)
        too_many = tuple(self.probe() for _ in range(self.policy.limits.observations + 1))
        before = self.counts()
        with self.assertRaises(ValueError):
            batches.store_batch(self.store, "local_passive", "lab", at, at, "complete", too_many)
        for anchor, value in ((batches.Anchor("alias", "lab-router", "foreign-profile"),
                                (("address", "192.0.2.10"), ("prefix_length", 24))),
                              (batches.Anchor("mac", "00:11:22:33:44:55"),
                                (("address", "198.51.100.1"), ("address", "192.0.2.10"), ("prefix_length", 24)))):
            observation = batches.Observation("address", anchor, "assignment", value, at)
            with self.assertRaises(ValueError):
                batches.store_batch(self.store, "local_passive", "lab", at, at, "complete", (self.probe(observations=(observation,)),))
        self.assertEqual(self.counts(), before)

    def probe(self, outcome="success", observations=()):
        at = storage.timestamp(NOW)
        return batches.Probe("neighbor", outcome, at, at, "local_host", "192.0.2.0/24", "cached_neighbor",
                             "ok" if outcome == "success" else "failed", observations)

    def test_batches_atomic_immutable_no_canonical_mutation(self):
        at = storage.timestamp(NOW)
        observation = batches.Observation("address", batches.Anchor("mac", "00:11:22:33:44:55"), "assignment",
                                          (("address", "192.0.2.10"), ("prefix_length", 24)), at, "STALE")
        before_device = self.detail()
        batch = batches.store_batch(self.store, "local_passive", "lab", at, at, "complete", (self.probe(observations=(observation,)),))
        self.assertEqual(self.detail(), before_device)
        self.assertEqual(self.counts()["batches"], 1)
        self.assertEqual(self.counts()["probes"], 1)
        probe = self.store.connection.execute("SELECT * FROM probes WHERE batch_id=?", (batch,)).fetchone()
        self.assertFalse(probe["absence_eligible"])
        obs = self.store.connection.execute("SELECT * FROM observations WHERE batch_id=?", (batch,)).fetchone()
        self.assertFalse(obs["qualified"])
        self.assertEqual(obs["neighbor_state"], "STALE")
        self.assertIsNone(obs["entity_id"])
        for table in ("batches", "probes"):
            with self.store.transaction(), self.assertRaises(sqlite3.IntegrityError):
                self.store.connection.execute(f"DELETE FROM {table}")
        before = self.counts()
        with patch.object(self.store, "audit", side_effect=RuntimeError("batch interruption")), self.assertRaises(RuntimeError):
            batches.store_batch(self.store, "local_passive", "lab", at, at, "failed", (self.probe("timeout"),))
        self.assertEqual(self.counts(), before)

    def test_invalid_batch_times_scope_counts_outcome_values_fail_before_insert(self):
        at = storage.timestamp(NOW)
        bad_address = batches.Observation("address", batches.Anchor("mac", "00:11:22:33:44:55"), "assignment",
                                          (("address", "198.51.100.1"), ("prefix_length", 24)), at)
        cases = [("local_passive", "missing", at, at, "complete", (self.probe(),)),
                 ("local_passive", "lab", at, at, "complete", (self.probe("timeout"),)),
                 ("local_passive", "lab", at, at, "failed", (self.probe("timeout", (bad_address,)),)),
                 ("local_passive", "lab", at, at, "complete", (self.probe(observations=(bad_address,)),)),
                 ("local_passive", "lab", at, at, "complete", (self.probe(), self.probe())),
                 ("ssh", "missing", at, at, "complete", (self.probe(),))]
        before = self.counts()
        for args in cases:
            with self.subTest(args=args), self.assertRaises(ValueError):
                batches.store_batch(self.store, *args)
            self.assertEqual(self.counts(), before)
        with self.assertRaises(ValueError):
            storage.timestamp(datetime(2026, 1, 1))
        with self.assertRaises(ValueError):
            storage.parse_time("2026-09-30")

    def test_application_and_access_evidence_are_immutable_and_unique(self):
        at = storage.timestamp(NOW)
        batch = batches.store_batch(self.store, "local_passive", "lab", at, at, "failed", (self.probe("timeout"),))
        with self.store.transaction():
            self.store.connection.execute("INSERT INTO applications VALUES (?,?,?,?,?)", (storage.identifier(), batch, 1, at, "{}"))
            self.store.audit(storage.identifier(), "application_fixture", "test", at, batch=batch)
        with self.store.transaction(), self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute("INSERT INTO applications VALUES (?,?,?,?,?)", (storage.identifier(), batch, 1, at, "{}"))
        for operation in ("UPDATE applications SET result_json='bad'", "DELETE FROM applications"):
            with self.store.transaction(), self.assertRaises(sqlite3.IntegrityError):
                self.store.connection.execute(operation)
        batches.record_access(self.store, self.device, "lab-router", False, "timeout", now=NOW)
        with self.store.transaction(), self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute("DELETE FROM access_evidence")
