# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage-1 authority, compatibility and packet-free capability regressions."""
from contextlib import ExitStack, redirect_stdout
from dataclasses import FrozenInstanceError, replace
import argparse
import errno
import importlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, call, patch

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from offline_guard import deny_network
    deny_network()

from helpers import load_package, scratch_home

load_package()
config = importlib.import_module("atlas_test_plugin.config")
discovery = importlib.import_module("atlas_test_plugin.discovery")
tools = importlib.import_module("atlas_test_plugin.tools")
commands = importlib.import_module("atlas_test_plugin.commands")
runner = importlib.import_module("atlas_test_plugin.probes")


def raw_policy(**methods) -> dict:
    return {"networks": {"lab": {"cidr": "192.0.2.0/29",
                               "discovery": {"passive": True, "ping": True, **methods}}}}


class HostDiscoveryPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)

    def policy(self, **methods):
        return config.validate_policy(raw_policy(**methods), self.home)

    def test_legacy_defaults_and_explicit_defaults_preserve_exact_transport(self):
        calls = []
        xml = (b'<nmaprun><runstats><finished exit="success"/>'
               b'<hosts up="0" down="8" total="8"/></runstats></nmaprun>')
        def transport(argv, *args, **kwargs):
            calls.append(argv)
            return runner.CommandResult("success", xml)
        for methods in ({}, {"icmp_echo": False, "tcp_ports": [443, 80]}):
            policy = self.policy(**methods)
            self.assertFalse(policy.networks[0].icmp_echo)
            self.assertEqual(policy.networks[0].tcp_ports, (80, 443))
            with patch.object(discovery, "run", transport), patch("socket.socket", side_effect=AssertionError("no implicit ICMP")):
                result = discovery.collect(policy, {"network": "lab", "mode": "ping"})
            self.assertEqual(result["completion"], "complete")
            self.assertEqual(len(result["probes"]), 9)
        self.assertEqual(calls, [("nmap", "-sn", "-n", "-PS80,443", "--host-timeout", "10s",
                                  "--max-parallelism", "4", "--max-rate", "32", "-oX", "-", "192.0.2.0/29")] * 2)

    def test_strict_enablement_port_types_bounds_duplicates_cap_and_exclusion(self):
        invalid_ports = [None, "80,443", "1-4", {}, {80}, (80,), [True], [False], [1.0], ["80"],
                         [None], [0], [-1], [65536], [80, 80], [1, 2, 3, 4, 5], [4403], [80, 4403], [[80]]]
        for ports in invalid_ports:
            with self.subTest(ports=ports), self.assertRaises(config.ConfigError):
                self.policy(tcp_ports=ports)
        for value in (None, 0, 1, "true", "false", [], {}):
            with self.subTest(value=value), self.assertRaises(config.ConfigError):
                self.policy(icmp_echo=value)
        for ports in ([1], [65535], [80, 443, 2222, 22000], []):
            self.assertEqual(self.policy(icmp_echo=True, tcp_ports=ports).networks[0].tcp_ports, tuple(sorted(ports)))

    def test_method_dependencies_ipv6_scope_and_unknown_authority_fail_closed(self):
        invalid = [raw_policy(tcp_ports=[]), raw_policy(ping=False, icmp_echo=True),
                   raw_policy(helper="ping"), raw_policy(excluded_ports=[]), raw_policy(allow_sensitive=True),
                   raw_policy(options=["-PE"]), {"icmp_echo": True}, {"discovery": {"tcp_ports": [2222]}}]
        for cidr in ("192.0.2.0/23", "192.0.2.1/29", "2001:db8::/64"):
            raw = raw_policy(icmp_echo=True)
            raw["networks"]["lab"]["cidr"] = cidr
            invalid.append(raw)
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(config.ConfigError):
                config.validate_policy(raw, self.home)
        self.policy(ping=False, tcp_ports=[2222])  # staged list grants no active permission
        self.policy(ping=False, tcp_ports=[])

    def test_network_local_immutable_snapshots_and_shared_data_do_not_grant_methods(self):
        ports = [22000, 2222]
        raw = raw_policy(icmp_echo=True, tcp_ports=ports)
        raw["networks"]["other"] = {"cidr": "198.51.100.0/29", "discovery": {"ping": True}}
        raw["store"] = {"shared_sqlite_path": str(self.home / "shared.sqlite3")}
        policy = config.validate_policy(raw, self.home / "one")
        ports.append(4403)
        lab, other = policy.networks
        self.assertEqual(lab.tcp_ports, (2222, 22000))
        self.assertTrue(lab.icmp_echo)
        self.assertEqual(other.tcp_ports, (80, 443))
        self.assertFalse(other.icmp_echo)
        with self.assertRaises(FrozenInstanceError):
            lab.icmp_echo = False
        second = config.validate_policy({"store": raw["store"]}, self.home / "two")
        self.assertEqual(policy.database, second.database)
        self.assertEqual(second.networks, ())
        with self.assertRaises(ValueError):
            discovery.validate_request({"network": "lab", "mode": "ping"}, second)
        self.assertFalse(policy.database.exists())

    def test_yaml_duplicate_unknown_and_null_method_inputs_fail_closed(self):
        directory = self.home / "network-atlas"
        directory.mkdir()
        path = directory / "config.yaml"
        prefix = 'networks:\n  lab:\n    cidr: 192.0.2.0/29\n    discovery:\n      ping: true\n'
        for suffix in ('      icmp_echo: true\n      icmp_echo: false\n',
                       '      tcp_ports: [80]\n      tcp_ports: [443]\n',
                       '      icmp_echo: yes\n', '      tcp_ports: null\n', '      helper: ping\n'):
            path.write_text(prefix + suffix)
            with self.subTest(suffix=suffix), self.assertRaises(config.ConfigError):
                config.load_policy(self.home)
        path.write_text(prefix + '      icmp_echo: true\n      tcp_ports: []\n')
        self.assertEqual(config.load_policy(self.home).networks[0].tcp_ports, ())

    def test_combined_bounds_refuse_before_any_effect_and_report_on_public_routes(self):
        for methods in ({"icmp_echo": True}, {"tcp_ports": [2222]}, {"icmp_echo": True, "tcp_ports": []}):
            policy = replace(self.policy(**methods), limits=replace(self.policy().limits, observations=8))
            with ExitStack() as stack:
                for target in ("subprocess.Popen", "socket.socket", "atlas_test_plugin.discovery.Store"):
                    stack.enter_context(patch(target, side_effect=AssertionError("preflight effects forbidden")))
                with self.assertRaisesRegex(ValueError, "probe count"):
                    discovery.collect(policy, {"network": "lab", "mode": "ping"})
                self.assertEqual(discovery.validate_request({"network": "lab", "mode": "passive"}, policy)[1], "passive")
                with patch.object(tools, "load_policy", return_value=policy):
                    handler = tools.Handlers(self.home)
                    for text in (handler.discover({"network": "lab", "mode": "ping"}, icmp_echo=False),
                                 handler.command("discover lab ping")):
                        result = json.loads(text)
                        self.assertIn("error", result)
                        self.assertFalse(result["persisted"])
                    parser = argparse.ArgumentParser()
                    commands.setup_parser(parser)
                    args = parser.parse_args(["discover", "--network", "lab", "--mode", "ping"])
                    output = io.StringIO()
                    with patch.object(commands, "load_policy", return_value=policy), redirect_stdout(output):
                        self.assertEqual(commands.run_command(args, self.home), 2)
                    self.assertIn("error", json.loads(output.getvalue()))
            self.assertEqual(list(self.home.iterdir()), [])

    def test_unknown_tool_inputs_and_native_invalid_snapshots_refuse_before_effects(self):
        policy = self.policy()
        invalid = [[], {}, {"network": "192.0.2.0/29", "mode": "ping"},
                   {"network": "lab", "mode": "icmp"}, {"network": "lab", "mode": "ping", "tcp_ports": [2222]},
                   {"network": "lab", "mode": "ping", "icmp_echo": True},
                   {"network": "lab", "mode": "ping", "options": "-PE"}]
        with patch("subprocess.Popen", side_effect=AssertionError("invalid effects")), patch("socket.socket", side_effect=AssertionError("invalid effects")):
            for params in invalid:
                with self.subTest(params=params), self.assertRaises(ValueError):
                    discovery.collect(policy, params)
            for changes in ({"tcp_ports": (4403,)}, {"icmp_echo": 1}, {"tcp_ports": (True,)}, {"ping": 1}):
                malformed = replace(policy, networks=(replace(policy.networks[0], **changes),))
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    discovery.collect(malformed, {"network": "lab", "mode": "ping"})
        self.assertEqual(list(self.home.iterdir()), [])

    def test_missing_nmap_remains_explicit_failure_without_icmp_fallback(self):
        with patch.object(runner.subprocess, "Popen", side_effect=FileNotFoundError), \
                patch("socket.socket", side_effect=AssertionError("no ICMP fallback")):
            result = discovery.collect(self.policy(), {"network": "lab", "mode": "ping"})
        self.assertEqual(result["completion"], "failed")
        self.assertEqual({p["outcome"] for p in result["probes"][:-1]}, {"unavailable"})


class ICMPCapabilityTests(unittest.TestCase):
    def setUp(self):
        self.module = importlib.import_module("atlas_test_plugin.host_discovery")
        self.temp = scratch_home()
        self.addCleanup(self.temp.cleanup)
        self.policy = config.validate_policy(raw_policy(icmp_echo=True), Path(self.temp.name))
        self.network = self.policy.networks[0]

    def capability(self, network=None, **kwargs):
        with patch.object(self.module.time, "monotonic", return_value=1.0):
            return self.module.icmp_capability(network or self.network, 10.0, **kwargs)

    def test_disabled_expired_unsupported_are_packet_free_no_open(self):
        factory = MagicMock(side_effect=AssertionError("must not open"))
        for network, deadline, platform, state, code in (
                (replace(self.network, icmp_echo=False), 10.0, "linux", "disabled", "icmp_disabled"),
                (replace(self.network, ping=False, icmp_echo=False), 10.0, "linux", "disabled", "icmp_disabled"),
                (self.network, 1.0, "linux", "not_started", "operation_deadline_exceeded"),
                (self.network, 10.0, "darwin", "unavailable", "icmp_platform_unsupported")):
            with patch.object(self.module.time, "monotonic", return_value=1.0):
                result = self.module.icmp_capability(network, deadline, platform=platform, socket_factory=factory)
            self.assertEqual((result.state, result.diagnostic_code), (state, code))
        factory.assert_not_called()

    def test_open_success_only_unverified_and_socket_closed_no_packet_operations(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        factory = MagicMock(return_value=sock)
        result = self.capability(platform="linux", socket_factory=factory)
        self.assertEqual((result.state, result.diagnostic_code), ("unverified", "icmp_socket_opened_transport_unverified"))
        factory.assert_called_once_with(self.module.socket.AF_INET, self.module.socket.SOCK_DGRAM, self.module.socket.IPPROTO_ICMP)
        self.assertEqual(sock.mock_calls, [call.__enter__(), call.__exit__(None, None, None)])
        with self.assertRaises(FrozenInstanceError):
            result.state = "available"

    def test_malformed_native_grants_and_unbounded_deadlines_refuse_no_open(self):
        factory = MagicMock(side_effect=AssertionError("invalid snapshot must not open"))
        for changes in ({"icmp_echo": "true"}, {"ping": 1}, {"tcp_ports": (4403,)}, {"cidr": "192.0.2.0/23"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.capability(replace(self.network, **changes), platform="linux", socket_factory=factory)
        for deadline in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(deadline=deadline), self.assertRaises(ValueError):
                self.module.icmp_capability(self.network, deadline, platform="linux", socket_factory=factory)
        factory.assert_not_called()

    def test_permission_protocol_resource_failures_are_bounded_no_retry_or_helper(self):
        for number, code in ((errno.EPERM, "icmp_permission_denied"), (errno.EACCES, "icmp_permission_denied"),
                             (errno.EPROTONOSUPPORT, "icmp_protocol_unsupported"), (errno.EAFNOSUPPORT, "icmp_protocol_unsupported"),
                             (errno.EMFILE, "icmp_socket_open_failed")):
            factory = MagicMock(side_effect=OSError(number, "private untrusted error"))
            with self.subTest(number=number), patch("subprocess.Popen", side_effect=AssertionError("no helper")):
                result = self.capability(platform="linux", socket_factory=factory)
                self.assertEqual((result.state, result.diagnostic_code), ("unavailable", code))
                self.assertNotIn("private", repr(result))
                self.assertEqual(factory.call_count, 1)

    def test_interruption_closes_owned_socket_and_propagates(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.__exit__.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.capability(platform="linux", socket_factory=MagicMock(return_value=sock))
        sock.__exit__.assert_called_once()

    def test_capability_is_rechecked_not_cached_and_never_grants_transport(self):
        sock = MagicMock()
        factory = MagicMock(side_effect=[sock, PermissionError(errno.EACCES, "denied")])
        self.assertEqual(self.capability(platform="linux", socket_factory=factory).state, "unverified")
        self.assertEqual(self.capability(platform="linux", socket_factory=factory).state, "unavailable")
        with patch.object(self.module, "icmp_capability", side_effect=AssertionError("query never checks")):
            self.assertEqual(json.loads(tools.Handlers(self.policy.home).query({}))["devices"], [])


if __name__ == "__main__":
    unittest.main()
