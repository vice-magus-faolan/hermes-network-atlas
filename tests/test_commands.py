# SPDX-License-Identifier: GPL-3.0-or-later
"""Cumulative operator/status contracts, using only synthetic isolated state."""
import argparse
from contextlib import redirect_stderr, redirect_stdout
import importlib
import io
import json
import os
import signal
from pathlib import Path
from datetime import timedelta
import sys
import time
import unittest
from unittest.mock import Mock, patch

if __name__ == "__main__":
    from network_guard import deny_network
    deny_network()

from helpers import ROOT, fixture_command, fixture_handlers, fixture_policy, scratch_home
from test_boundaries import synthetic_policy
from test_core import NOW, batches, core, query, storage, config, tools

commands = importlib.import_module("atlas_test_plugin.commands")
discovery = importlib.import_module("atlas_test_plugin.discovery")
inspection = importlib.import_module("atlas_test_plugin.inspection")
runner = importlib.import_module("atlas_test_plugin.probes")


class OperatorStatusTests(unittest.TestCase):
    def setUp(self):
        self.temp = scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        raw = synthetic_policy()
        directory = self.home / "network-atlas"
        directory.mkdir()
        (directory / "config.yaml").write_text(json.dumps(raw))
        self.policy = fixture_policy(self.home)
        self.handlers = fixture_handlers(self.home)

    def test_cli_and_status_read_one_policy_snapshot_each(self):
        parser = argparse.ArgumentParser(allow_abbrev=False)
        commands.setup_parser(parser)
        for action in ('status', 'query'):
            with self.subTest(action=action), redirect_stdout(io.StringIO()):
                loader = Mock(side_effect=[self.policy, AssertionError('second policy read')])
                self.assertEqual(commands.run_command(parser.parse_args([action]), loader), 0)
                loader.assert_called_once_with()
        loader = Mock(side_effect=[self.policy, AssertionError('second policy read')])
        self.assertNotIn('error', json.loads(tools.Handlers(loader).query({'view': 'status'})))
        loader.assert_called_once_with()

    def test_empty_status_has_consistent_counts_scopes_and_no_file_effects(self):
        before = set(self.home.rglob("*"))
        result = json.loads(self.handlers.command("status"))
        self.assertEqual(result["stage"], "v1")
        self.assertEqual(result["known_devices"], 0)
        self.assertEqual(result["observed_devices"], 0)
        self.assertEqual(result["stale_devices"], 0)
        self.assertEqual(result["authorized_devices_for_atlas_ssh_inspection"], 0)
        self.assertIsNone(result["last_discovery"])
        self.assertEqual(result["configured_scopes"], [{"name": "lab", "cidr": "192.0.2.0/24", "passive": True,
                                                       "ping": True, "icmp_echo": False, "tcp_ports": [80, 443],
                                                       "endpoint_ports": [], "allow_public": True}])
        self.assertEqual(set(self.home.rglob("*")), before)

    def test_cli_invalid_policy_refusal_has_explicit_no_effects_receipt(self):
        parser = argparse.ArgumentParser(allow_abbrev=False)
        commands.setup_parser(parser)
        routes = (["discover", "--network", "lab", "--mode", "ping"],
                  ["status"], ["create", "--name", "Synthetic device"],
                  ["update", "--device-id", "00000000-0000-0000-0000-000000000001",
                   "--field", "description", "--value-json", '"Synthetic assertion"'])
        path = self.home / "network-atlas" / "config.yaml"
        original = path.read_bytes()
        self.addCleanup(path.write_bytes, original)
        for existing_store in (False, True):
            if existing_store:
                with storage.Store(self.policy, writable=True) as store:
                    core.create_device(store, "Existing synthetic device", now=NOW)
            for methods in ({"icmp_echo": 1}, {"tcp_ports": [4403]},
                            {"icmp_echo": True, "options": "-PE"}):
                raw = json.loads(original)
                raw["networks"]["lab"]["discovery"].update(methods)
                path.write_text(json.dumps(raw))
                before = {item.relative_to(self.home): item.read_bytes()
                          for item in self.home.rglob("*") if item.is_file()}
                with patch.object(commands, "_read_command") as read, patch.object(commands, "_write_command") as write:
                    for argv in routes:
                        with self.subTest(existing_store=existing_store, methods=methods, argv=argv):
                            output = io.StringIO()
                            with redirect_stdout(output):
                                code = fixture_command(parser.parse_args(argv), self.home)
                            result = json.loads(output.getvalue())
                            self.assertEqual(code, 2)
                            self.assertIn("error", result)
                            self.assertIs(result["applied"], False)
                            self.assertIs(result["persisted"], False)
                            self.assertEqual({item.relative_to(self.home): item.read_bytes()
                                              for item in self.home.rglob("*") if item.is_file()}, before)
                    read.assert_not_called()
                    write.assert_not_called()

    def test_discovery_and_inspection_are_distinct_local_qualified_summaries(self):
        old = NOW - timedelta(days=20)
        with storage.Store(self.policy, writable=True) as store:
            known = core.create_device(store, "Known", now=old)["device_id"]
            stale = core.create_device(store, "Previously seen", now=old)["device_id"]
            with store.transaction():
                core.append_fact(store, "device", stale, "hostname", "old-host", "ssh:lab-router",
                                 "observed", batches.timestamp(old), evidence_kind="ssh_response", qualified=True)
                core._positive(store, stale, batches.timestamp(old))
            at = batches.timestamp(NOW)
            passive = batches.store_batch(store, "local_passive", "lab", at, at, "partial", (
                batches.Probe(
                    "ip_addr", "success", at, at, "local_host", self.policy.networks[0].cidr, "local_interface"),
                batches.Probe("ip_neigh", "unavailable", at, at, "none", "", "none", "missing_executable")))
            ssh = batches.store_batch(store, "ssh", "lab-router", at, at, "failed", (
                batches.Probe("hostname", "command_failed", at, at, "none", "", "none", "command_failed"),))
        result = query.query(self.policy, {"view": "status"}, now=NOW)
        self.assertEqual(result["known_devices"], 2)
        self.assertEqual(result["stale_devices"], 1)
        self.assertEqual(result["observed_devices"], 0)
        self.assertEqual(result["last_discovery"]["id"], passive)
        self.assertEqual(result["last_discovery"]["completion"], "partial")
        self.assertEqual(result["last_discovery"]["scope_value"], "192.0.2.0/24")
        self.assertFalse(result["last_discovery"]["scope_absence_eligible"])
        self.assertEqual({probe["outcome"] for probe in result["last_discovery"]["probes"]}, {"success", "unavailable"})
        self.assertEqual(result["last_inspection"]["batch_id"], ssh)
        self.assertFalse(result["last_inspection"]["succeeded"])
        self.assertEqual({item["id"] for item in query.query(self.policy, {})["devices"]}, {known, stale})

    def test_shared_foreign_batches_do_not_claim_local_last_discovery(self):
        with storage.Store(self.policy, writable=True) as store:
            at = batches.timestamp(NOW)
            batches.store_batch(store, "ping", "lab", at, at, "complete", (
                batches.Probe("nmap", "success", at, at, "exact_network", "192.0.2.0/24", "ping_response"),))
        raw = {"store": {"shared_sqlite_path": str(self.policy.database)}}
        foreign = config.validate_policy(raw, self.home / "foreign")
        self.assertIsNone(query.query(foreign, {"view": "status"}, now=NOW)["last_discovery"])
        self.assertTrue(
            query.query(self.policy, {"view": "status"}, now=NOW)["last_discovery"]["scope_absence_eligible"])

    def test_slash_exact_arities_and_usage_no_origin_promotion(self):
        for text in ("", "status extra", "show", "show a b", "map text extra", "discover lab", "inspect a b",
                     "reconcile a b"):
            with self.subTest(text=text):
                result = json.loads(self.handlers.command(text))
                self.assertIn("error", result)
                self.assertIn("usage", result)
                self.assertFalse(result["applied"])
        result = json.loads(self.handlers.command('update {"source":"user"}'))
        self.assertIn("operator CLI", result["error"])
        self.assertFalse(result["applied"])
        self.assertEqual(
            json.loads(self.handlers.command("help"))["operator_update_route"], "hermes network-atlas update")
        with patch.object(self.handlers, "query", return_value="fixture-query") as read:
            self.assertEqual(self.handlers.command("show fixture-id"), "fixture-query")
            read.assert_called_once_with({"device_id": "fixture-id"})

    def test_endpoint_cli_exact_positional_selection_before_dispatch(self):
        parser = argparse.ArgumentParser(allow_abbrev=False)
        commands.setup_parser(parser)
        for argv, selection in ((['check-endpoints', 'lab'], {'network': 'lab'}),
                                (['resume-endpoints', 'saved-batch'], {'batch_id': 'saved-batch'})):
            with (patch.object(tools.Handlers, 'check_endpoints', return_value='{}') as check,
                  redirect_stdout(io.StringIO())):
                self.assertEqual(fixture_command(parser.parse_args(argv), self.home), 0)
                check.assert_called_once_with(selection)
        with patch.object(tools.Handlers, 'check_endpoints') as check, redirect_stderr(io.StringIO()):
            for argv in (['check-endpoints'], ['resume-endpoints'], ['check-endpoints', 'lab', 'extra'],
                         ['resume-endpoints', 'saved-batch', 'extra'],
                         ['check-endpoints', '--network', 'lab', '--batch-id', 'saved-batch'],
                         ['resume-endpoints', 'saved-batch', '--network', 'lab']):
                with self.subTest(argv=argv), self.assertRaises(SystemExit) as rejected:
                    parser.parse_args(argv)
                self.assertEqual(rejected.exception.code, 2)
            check.assert_not_called()

    def test_operator_errors_identify_fields_json_and_store_without_private_payloads(self):
        parser = argparse.ArgumentParser(allow_abbrev=False)
        commands.setup_parser(parser)
        cases = ((["query", "--query-json", '{"limit":false}'], "limit"),
                 (["query", "--query-json", "PRIVATE_JSON"], "JSON input"),
                 (["validate-update", "--device-id", "fixture", "--field", "retired",
                   "--value-json", '"PRIVATE_VALUE"'], "value.retired"),
                 (["inspect", "--target", "PRIVATE;id"], "target"))
        cases += ((["update", "--device-id", "fixture", "--field", "PRIVATE_FIELD", "--value-json", '"safe"'], "field"),
                  (["map", "--format", "PRIVATE_FORMAT"], "format"),
                  (["discover", "--network", "lab", "--mode", "PRIVATE_MODE"], "mode"),
                  (["address", "--interface-id", "fixture", "--address", "192.0.2.1",
                    "--prefix-length", "PRIVATE_PREFIX"], "prefix_length"))
        before = {path: path.read_bytes() for path in self.home.rglob("*") if path.is_file()}
        with patch("subprocess.Popen") as spawn:
            for argv, field in cases:
                with self.subTest(argv=argv):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        code = fixture_command(parser.parse_args(argv), self.home)
                    self.assertEqual(code, 2)
                    self.assertIn(field, json.loads(output.getvalue())["error"])
                    self.assertNotIn("PRIVATE", output.getvalue())
            spawn.assert_not_called()
        self.assertEqual(before, {path: path.read_bytes() for path in self.home.rglob("*") if path.is_file()})
        self.policy.database.parent.mkdir(parents=True, exist_ok=True)
        self.policy.database.write_bytes(b"PRIVATE_NOT_SQLITE")
        output = io.StringIO()
        with redirect_stdout(output):
            code = fixture_command(parser.parse_args(["query"]), self.home)
        self.assertEqual(code, 2)
        self.assertTrue(json.loads(output.getvalue())["error"].startswith("store:"))
        self.assertNotIn("PRIVATE", output.getvalue())

    def test_json_errors_identify_the_selected_option_before_mutation(self):
        parser = argparse.ArgumentParser(allow_abbrev=False)
        commands.setup_parser(parser)
        with storage.Store(self.policy, writable=True) as store:
            device = core.create_device(store, "Synthetic retained device", now=NOW)["device_id"]
        path = self.home / "network-atlas" / "config.yaml"
        raw = json.loads(path.read_text())
        raw["limits"] = {"input_chars": 16}
        path.write_text(json.dumps(raw))
        before = self.policy.database.read_bytes()
        for action in ("query", "validate-update", "update"):
            option = "query-json" if action == "query" else "value-json"
            prefix = ([action] if action == "query" else
                      [action, "--device-id", device, "--field", "description"])
            for text in ("PRIVATE_INVALID_JSON", "PRIVATE_" * 80):
                with self.subTest(action=action, oversized=len(text) > 608), \
                        patch("subprocess.Popen") as spawn, patch("socket.socket") as socket:
                    output = io.StringIO()
                    with redirect_stdout(output):
                        code = fixture_command(parser.parse_args([*prefix, "--" + option, text]), self.home)
                    result = json.loads(output.getvalue())
                    self.assertEqual(code, 2)
                    self.assertTrue(result["error"].startswith(option + ":"), result)
                    self.assertIn("JSON", result["error"])
                    self.assertFalse(result["applied"] or result["persisted"])
                    self.assertNotIn("PRIVATE", output.getvalue())
                    self.assertNotIn(str(self.home), output.getvalue())
                    spawn.assert_not_called()
                    socket.assert_not_called()
                self.assertEqual(self.policy.database.read_bytes(), before)
            output = io.StringIO()
            with redirect_stdout(output):
                code = fixture_command(parser.parse_args([*prefix, "--" + option,
                                                          "{}" if action == "query" else '"Restored"']), self.home)
            self.assertEqual(code, 0, output.getvalue())
            self.assertNotIn("error", json.loads(output.getvalue()))
            # Only the explicitly restored update may append history.
            if action != "update":
                self.assertEqual(self.policy.database.read_bytes(), before)

    def test_missing_inspection_target_keeps_public_field_on_all_routes(self):
        parser = argparse.ArgumentParser(allow_abbrev=False)
        commands.setup_parser(parser)
        for populated in (False, True):
            if populated:
                with storage.Store(self.policy, writable=True) as store:
                    core.create_device(store, "Synthetic retained device", now=NOW)
            before = self.policy.database.read_bytes() if populated else None
            with self.subTest(populated=populated), patch("subprocess.Popen") as spawn, \
                    patch("socket.socket") as socket:
                output = io.StringIO()
                with redirect_stdout(output):
                    code = fixture_command(parser.parse_args(["inspect", "--target", "PRIVATE_ABSENT_ID"]), self.home)
                self.assertEqual(code, 2)
                for emitted in (self.handlers.inspect({"target": "PRIVATE_ABSENT_ID"}),
                                self.handlers.command("inspect PRIVATE_ABSENT_ID"), output.getvalue()):
                    result = json.loads(emitted)
                    self.assertTrue(result["error"].startswith("target:"), result)
                    self.assertIn("select", result["error"])
                    self.assertFalse(result["applied"] or result["persisted"])
                    self.assertNotIn("device_id", result["error"])
                    self.assertNotIn("PRIVATE", emitted)
                    self.assertNotIn(str(self.home), emitted)
                spawn.assert_not_called()
                socket.assert_not_called()
            self.assertEqual(self.policy.database.exists(), populated)
            self.assertEqual(self.policy.database.read_bytes() if populated else None, before)
            self.assertNotIn("error", json.loads(self.handlers.command("status")))

    def test_missing_query_ids_name_fields_with_and_without_store(self):
        parser = argparse.ArgumentParser(allow_abbrev=False)
        commands.setup_parser(parser)
        for populated in (False, True):
            if populated:
                with storage.Store(self.policy, writable=True) as store:
                    device = core.create_device(store, "Synthetic retained device", now=NOW)["device_id"]
                    at = storage.timestamp(NOW)
                    batch = batches.store_batch(store, "local_passive", "lab", at, at, "failed", (
                        batches.Probe("ip_addr", "unavailable", at, at, "none", "", "none", "missing_executable"),))
                self.assertTrue(json.loads(self.handlers.query({"view": "history", "device_id": device}))[
                    "observations"])
                self.assertEqual(json.loads(self.handlers.query({"view": "unresolved", "batch_id": batch}))[
                    "evidence"], [])
            before = self.policy.database.read_bytes() if populated else None
            paths = set(self.home.rglob("*"))
            for view, field in (("history", "device_id"), ("unresolved", "batch_id")):
                with self.subTest(populated=populated, view=view), patch("subprocess.Popen") as spawn, \
                        patch("socket.socket") as socket:
                    params = {"view": view, field: "PRIVATE_ABSENT_ID"}
                    output = io.StringIO()
                    with redirect_stdout(output):
                        code = fixture_command(parser.parse_args(["query", "--query-json", json.dumps(params)]),
                                               self.home)
                    self.assertEqual(code, 2)
                    for emitted in (self.handlers.query(params), output.getvalue()):
                        result = json.loads(emitted)
                        self.assertEqual(result["error"], field + ": select an existing atlas entity")
                        self.assertFalse(result["applied"])
                        self.assertNotIn("PRIVATE", emitted)
                        self.assertNotIn(str(self.home), emitted)
                    spawn.assert_not_called()
                    socket.assert_not_called()
            self.assertEqual(self.policy.database.exists(), populated)
            self.assertEqual(self.policy.database.read_bytes() if populated else None, before)
            self.assertEqual(set(self.home.rglob("*")), paths)

    def test_export_directory_failures_are_not_store_errors(self):
        parser = argparse.ArgumentParser(allow_abbrev=False)
        commands.setup_parser(parser)
        with storage.Store(self.policy, writable=True) as store:
            core.create_device(store, "Synthetic retained device", now=NOW)
        before = self.policy.database.read_bytes()
        outside = self.home / "PRIVATE_EXPORT_TARGET"
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_text("PRIVATE_UNCHANGED")
        for symlink in (False, True):
            if symlink:
                self.policy.exports.symlink_to(outside, target_is_directory=True)
            else:
                self.policy.exports.write_text("PRIVATE_NOT_A_DIRECTORY")
            with self.subTest(symlink=symlink), patch("subprocess.Popen") as spawn, \
                    patch("socket.socket") as socket:
                output = io.StringIO()
                with redirect_stdout(output):
                    code = fixture_command(parser.parse_args(["map", "--export"]), self.home)
                self.assertEqual(code, 2)
                for emitted in (self.handlers.map({"export": True}), output.getvalue()):
                    result = json.loads(emitted)
                    self.assertEqual(result["error"],
                                     "export: directory unavailable; check export access and available space")
                    self.assertFalse(result["applied"])
                    self.assertNotIn("PRIVATE", emitted)
                    self.assertNotIn(str(self.home), emitted)
                # Slash map never exports; a broken export directory cannot break reads.
                self.assertNotIn("error", json.loads(self.handlers.command("map markdown")))
                spawn.assert_not_called()
                socket.assert_not_called()
            self.assertEqual(self.policy.database.read_bytes(), before)
            self.assertEqual(sentinel.read_text(), "PRIVATE_UNCHANGED")
            self.assertEqual(list(outside.iterdir()), [sentinel])
            if not symlink:
                self.assertEqual(self.policy.exports.read_text(), "PRIVATE_NOT_A_DIRECTORY")
            self.policy.exports.unlink()
        # Restored access uses the same real export/audit path successfully.
        exported = json.loads(self.handlers.map({"export": True}))
        self.assertNotIn("error", exported)
        self.assertEqual([Path(path).name for path in exported["exports"]], ["network_map.md", "network_map.mmd"])
        with storage.Store(self.policy) as store:
            self.assertEqual([row[0] for row in store.connection.execute(
                "SELECT action FROM audit_events WHERE action LIKE 'map_export%' ORDER BY rowid")],
                ["map_export_requested", "map_exported"])

    def export_history(self):
        with storage.Store(self.policy) as store, store.snapshot():
            # Compare all logical history, separating only the permitted appended
            # audit records. SQLite file bytes can change on a legitimate write.
            history = tuple(line for line in store.connection.iterdump()
                            if not line.startswith('INSERT INTO "audit_events"'))
            audits = [dict(row) for row in store.connection.execute('SELECT * FROM audit_events ORDER BY rowid')]
        return history, audits

    def assert_export_file_symlink_refused(self, filename):
        parser = argparse.ArgumentParser(allow_abbrev=False)
        commands.setup_parser(parser)
        with storage.Store(self.policy, writable=True) as store:
            core.create_device(store, "Synthetic retained device", now=NOW)
        self.assertNotIn("error", json.loads(self.handlers.map({"export": True})))
        outside = self.home / "PRIVATE_EXPORT_TARGET"
        outside.write_bytes(b"PRIVATE_UNCHANGED")
        destination = self.policy.exports / filename
        for route in ("model", "operator"):
            destination.unlink()
            destination.symlink_to(outside)
            outputs = {path.name: path.read_bytes() for path in self.policy.exports.iterdir()}
            history, audits = self.export_history()
            with self.subTest(route=route), patch("subprocess.Popen") as spawn, patch("socket.socket") as socket:
                if route == "model":
                    emitted = self.handlers.map({"export": True})
                else:
                    output = io.StringIO()
                    with redirect_stdout(output):
                        code = fixture_command(parser.parse_args(["map", "--export"]), self.home)
                    self.assertEqual(code, 2)
                    emitted = output.getvalue()
                result = json.loads(emitted)
                self.assertFalse(result["applied"])
                self.assertNotIn("PRIVATE", emitted)
                self.assertNotIn(str(self.home), emitted)
                self.assertLess(len(emitted.encode("utf-8")), self.policy.limits.output_bytes)
                self.assertTrue(destination.is_symlink())
                self.assertEqual(destination.readlink(), outside)
                self.assertEqual(outside.read_bytes(), b"PRIVATE_UNCHANGED")
                # This exact directory inventory also detects a leaked first stage
                # when the second fixed destination refuses.
                self.assertEqual({path.name: path.read_bytes() for path in self.policy.exports.iterdir()}, outputs)
                after, events = self.export_history()
                self.assertEqual(after, history)
                self.assertEqual(events[:-1], audits)
                self.assertEqual(len(events), len(audits) + 1)
                self.assertEqual(events[-1]["action"], "map_export_requested")
                self.assertEqual(events[-1]["actor"], "local_render")
                self.assertEqual(json.loads(events[-1]["details_json"]),
                                 {"files": ["network_map.md", "network_map.mmd"]})
                self.assertNotIn("error", json.loads(self.handlers.command("map markdown")))
                self.assertEqual(self.export_history(), (after, events))
                spawn.assert_not_called()
                socket.assert_not_called()
                self.assertEqual(result["error"],
                                 "export: symlink destination refused; "
                                 "use regular generated files in the export directory")
            destination.unlink()
            # Restoring a regular destination exercises the same adapter's real
            # export and completion audit, not just the private file helper.
            if route == "model":
                restored = json.loads(self.handlers.map({"export": True}))
            else:
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(fixture_command(parser.parse_args(["map", "--export"]), self.home), 0)
                restored = json.loads(output.getvalue())
            self.assertNotIn("error", restored)
            self.assertFalse(destination.is_symlink())
            self.assertEqual({path.name for path in self.policy.exports.iterdir()},
                             {"network_map.md", "network_map.mmd"})
            restored_history, restored_events = self.export_history()
            self.assertEqual(restored_history, history)
            self.assertEqual(restored_events[:-2], events)
            self.assertEqual([row["action"] for row in restored_events[-2:]],
                             ["map_export_requested", "map_exported"])

    def test_export_first_file_symlink_refusal_is_actionable_and_preserves_history(self):
        self.assert_export_file_symlink_refused("network_map.md")

    def test_export_second_file_symlink_refusal_cleans_staging_and_preserves_history(self):
        self.assert_export_file_symlink_refused("network_map.mmd")

    def test_export_preserves_real_store_failure_categories(self):
        parser = argparse.ArgumentParser(allow_abbrev=False)
        commands.setup_parser(parser)
        with storage.Store(self.policy, writable=True) as store:
            core.create_device(store, "Synthetic retained device", now=NOW)
        target = self.home / "PRIVATE_STORE_TARGET.sqlite3"
        self.policy.database.rename(target)
        self.policy.database.symlink_to(target)
        for failure in ("writable_layout", "schema", "sqlite"):
            if failure == "schema":
                self.policy.database.unlink()
                target.rename(self.policy.database)
                with storage.Store(self.policy, writable=True) as store:
                    store.connection.execute("PRAGMA user_version=999")
            elif failure == "sqlite":
                self.policy.database.write_bytes(b"PRIVATE_NOT_SQLITE")
            before = self.policy.database.read_bytes()
            with self.subTest(failure=failure), patch("subprocess.Popen") as spawn, \
                    patch("socket.socket") as socket:
                output = io.StringIO()
                with redirect_stdout(output):
                    code = fixture_command(parser.parse_args(["map", "--export"]), self.home)
                self.assertEqual(code, 2)
                results = [self.handlers.map({"export": True}), output.getvalue()]
                slash = self.handlers.command("map markdown")
                if failure == "writable_layout":
                    # Read rendering succeeds; the actual writable Store refuses its symlink.
                    self.assertNotIn("error", json.loads(slash))
                else:
                    results.append(slash)
                for emitted in results:
                    result = json.loads(emitted)
                    self.assertEqual(result["error"],
                                     "store: database operation failed; check availability and compatible schema")
                    self.assertFalse(result["applied"])
                    self.assertNotIn("PRIVATE", emitted)
                    self.assertNotIn(str(self.home), emitted)
                spawn.assert_not_called()
                socket.assert_not_called()
            self.assertEqual(self.policy.database.read_bytes(), before)
            self.assertEqual(list(self.policy.exports.iterdir()), [])


class RuntimeGuardTests(unittest.TestCase):
    """Also run by ordinary pytest in a fresh -O child; unittest assertions survive."""

    def setUp(self):
        self.temp = scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        path = self.home / "network-atlas" / "config.yaml"
        path.parent.mkdir()
        path.write_text(json.dumps(synthetic_policy()))
        self.policy = fixture_policy(self.home)

    def test_invalid_requests_and_policy_ports_reject_before_effects(self):
        handlers = fixture_handlers(self.home)
        with patch("subprocess.Popen") as spawn, patch.object(storage.Store, "__init__") as open_store:
            for result in (handlers.command("discover PRIVATE_SCOPE passive"),
                           handlers.command("inspect PRIVATE_ALIAS"),
                           handlers.update({"device_id": "fixture", "field": "PRIVATE_FIELD", "value": "safe",
                                            "explanation": "safe"})):
                self.assertIn("error", json.loads(result))
                self.assertNotIn("PRIVATE", result)
            path = self.home / "network-atlas" / "config.yaml"
            raw = synthetic_policy()
            raw["networks"]["lab"]["discovery"]["tcp_ports"] = [4403]
            path.write_text(json.dumps(raw))
            result = json.loads(handlers.discover({"network": "lab", "mode": "ping"}))
            self.assertIn("tcp_ports", result["error"])
            spawn.assert_not_called()
            open_store.assert_not_called()
        self.assertFalse(self.policy.database.exists())

    def test_collection_record_budgets_name_setting_on_all_public_routes_before_effects(self):
        handlers = fixture_handlers(self.home)
        parser = argparse.ArgumentParser(allow_abbrev=False)
        commands.setup_parser(parser)
        path = self.home / "network-atlas" / "config.yaml"
        cases = (("passive", 1, False, "discovery scope"),
                 ("ping", 1, False, "discovery scope"),
                 ("ping", 3, True, "discovery methods and scope"),
                 ("inspect", 1, False, "SSH inspection probes"))
        for mode, budget, sockets, reason in cases:
            raw = synthetic_policy()
            raw["limits"] = {"observations": budget}
            if sockets:
                # Three records fit the legacy address+coverage check, but not
                # the five method+address+coverage records of this valid policy.
                raw["networks"]["lab"]["cidr"] = "192.0.2.8/31"
                raw["networks"]["lab"]["discovery"]["tcp_ports"] = [22]
            path.write_text(json.dumps(raw))
            before = {item: item.read_bytes() for item in self.home.rglob("*") if item.is_file()}
            argv = (["inspect", "--target", "lab-router"] if mode == "inspect" else
                    ["discover", "--network", "lab", "--mode", mode])
            with self.subTest(mode=mode, sockets=sockets), patch("subprocess.Popen") as spawn, \
                    patch("socket.socket") as socket, patch.object(storage.Store, "__init__") as open_store:
                output = io.StringIO()
                with redirect_stdout(output):
                    code = fixture_command(parser.parse_args(argv), self.home)
                model = (handlers.inspect({"target": "lab-router"}) if mode == "inspect" else
                         handlers.discover({"network": "lab", "mode": mode}))
                slash = handlers.command("inspect lab-router" if mode == "inspect" else "discover lab " + mode)
                self.assertEqual(code, 2)
                for emitted in (model, slash, output.getvalue()):
                    result = json.loads(emitted)
                    self.assertIn("limits.observations", result["error"])
                    self.assertIn(reason, result["error"])
                    self.assertIn("record budget", result["error"])
                    self.assertFalse(result["persisted"] or result["applied"])
                    for private in (str(self.home), "192.0.2.", "lab-router"):
                        self.assertNotIn(private, emitted)
                spawn.assert_not_called()
                socket.assert_not_called()
                open_store.assert_not_called()
            self.assertEqual(before, {item: item.read_bytes() for item in self.home.rglob("*") if item.is_file()})
            self.assertFalse(self.policy.database.exists())

    def test_invalid_collector_receipts_fail_closed_at_handlers(self):
        at = storage.timestamp(storage.utc_now())
        probe = batches.Probe("fixture", "unavailable", at, at, "none", "", "none", "executable_missing")
        handlers = fixture_handlers(self.home)
        for module, route, params in ((discovery, handlers.discover, {"network": "lab", "mode": "passive"}),
                                      (inspection, handlers.inspect, {"target": "lab-router"})):
            with self.subTest(route=route.__name__), patch.object(module, "_probe", return_value=probe), \
                    patch.object(module, "store_batch", return_value="not-a-receipt"):
                result = json.loads(route(params))
                self.assertIn("error", result)
                self.assertFalse(result["persisted"] or result["applied"])
        with storage.Store(self.policy) as store:
            self.assertEqual(store.connection.execute("SELECT COUNT(*) FROM batches").fetchone()[0], 0)

    def test_missing_child_pipe_still_kills_reaps_and_closes_owned_streams(self):
        (self.home / "offline-fixture").touch()
        children = []
        real_spawn = runner.subprocess.Popen
        streams = []
        def spawn(*args, **kwargs):
            child = real_spawn(*args, **kwargs)
            children.append(child)
            streams.extend((child.stdout, child.stderr))
            child.stdout.close()
            child.stdout = None
            return child
        with patch.dict(os.environ, {"NETWORK_ATLAS_OFFLINE_FIXTURE_DIR": str(self.home)}), \
                patch.object(runner.subprocess, "Popen", spawn):
            try:
                result = runner.run((sys.executable, str(ROOT / "tests" / "offline_probe.py"), "sleep"),
                                    self.policy.limits, time.monotonic() + 5)
                closed_by_runner = all(stream.closed for stream in streams)
                reaped_by_runner = all(child.returncode is not None for child in children)
            finally:
                # A regressed runner must not strand this test's sleeping child.
                for child in children:
                    if child.returncode is None:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait()
                for stream in streams:
                    stream.close()
        self.assertEqual(result.outcome, "command_failed")
        self.assertEqual(result.diagnostic_code, "missing_output_pipe")
        self.assertTrue(closed_by_runner)
        self.assertTrue(reaped_by_runner)
        self.assertEqual(len(children), 1)
        with self.assertRaises(ChildProcessError):
            os.waitpid(children[0].pid, os.WNOHANG)

    def test_runtime_guard_failure_rolls_back_and_allows_next_transaction(self):
        with storage.Store(self.policy, writable=True) as store:
            device = core.create_device(store, "Before failure")["device_id"]
            before = store.connection.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
        params = {"device_id": device, "field": "description", "value": "Proposed",
                  "explanation": "Synthetic inference"}
        with patch.object(storage.Store, "audit", side_effect=ValueError("PRIVATE_INTERNAL_FAILURE")):
            failed = json.loads(fixture_handlers(self.home).update(params))
        self.assertFalse(failed["applied"])
        self.assertNotIn("PRIVATE", json.dumps(failed))
        with storage.Store(self.policy) as store:
            self.assertFalse(store.connection.in_transaction)
            self.assertEqual(store.connection.execute("SELECT COUNT(*) FROM observations").fetchone()[0], before)
        self.assertTrue(json.loads(fixture_handlers(self.home).update(params))["persisted"])

    def test_store_layout_failure_retains_explicit_exception_cause(self):
        target = self.home / "private-target"
        target.write_text("synthetic")
        self.policy.database.parent.mkdir(parents=True, exist_ok=True)
        self.policy.database.symlink_to(target)
        with self.assertRaises(ValueError) as caught:
            storage.Store(self.policy, writable=True)
        self.assertIsInstance(caught.exception.__cause__, FileExistsError)
        self.assertEqual(target.read_text(), "synthetic")


if __name__ == "__main__":
    unittest.main()
