# SPDX-License-Identifier: GPL-3.0-or-later
"""Named policy-only LAN collection. Collect first, atomically store evidence second."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from ipaddress import ip_network
import time

from . import discovery_parse as parse
from .batches import Observation, Probe, store_batch
from .config import LEGACY_TCP_PORTS, Network, Policy, validate_network
from .host_schedule import collect_methods, validate_count
from .probes import run
from .storage import Store, timestamp, utc_now

PASSIVE = (("ip_addr", ("ip", "-j", "addr"), "local_interface", parse.addresses),
           ("ip_route", ("ip", "-j", "route"), "none", parse.routes),
           ("ip_neigh", ("ip", "-j", "neigh"), "cached_neighbor", parse.neighbors))

# One child at a time: internal parallelism consumes, not multiplies, the
# existing concurrency budget. Rate is an additional code-owned restriction.
PING_CHUNK_PREFIX = 28
PING_RATE_PER_SLOT = 8


Parser = Callable[[bytes, str, str, Policy], tuple[Observation, ...]]


def validate_request(params: object, policy: Policy) -> tuple[Network, str]:
    """Names and enabled modes only; no raw targets/options/probe/policy inputs."""
    if not isinstance(params, dict) or set(params) != {"network", "mode"}:
        raise ValueError("network and mode required, no other arguments")
    name, mode = params["network"], params["mode"]
    if not isinstance(name, str) or not isinstance(mode, str) or mode not in {"passive", "ping"}:
        raise ValueError("invalid network or mode")
    network = next((item for item in policy.networks if item.name == name), None)
    if network is not None:
        validate_network(network)
    if network is None or not getattr(network, mode):
        raise ValueError("network/mode not authorized by local policy")
    _validate_scope(network.cidr, mode, policy)
    if mode == "ping" and (network.icmp_echo or network.tcp_ports != LEGACY_TCP_PORTS):
        validate_count(network, policy)
    return network, mode


def _validate_scope(cidr: str, mode: str, policy: Policy) -> None:
    """Defend native invocation against malformed scope and probe count overflow."""
    scope = ip_network(cidr, strict=True)
    if str(scope) != cidr or scope.version == 4 and scope.num_addresses > 256:
        raise ValueError("noncanonical or excessive configured scope")
    if mode == "ping" and scope.version != 4:
        raise ValueError("active discovery is IPv4 only")
    count = 3 if mode == "passive" else scope.num_addresses + 1
    if count > policy.limits.observations:
        raise ValueError("configured probe count too small for complete scope")


def _probe(name: str, argv: tuple[str, ...], evidence: str, parser: Parser, scope: str,
           policy: Policy, deadline: float, *, host: bool = False) -> Probe:
    start = timestamp(utc_now())
    result = run(argv, policy.limits, deadline, host=host)
    at = timestamp(utc_now())
    observations = ()
    if result.outcome == "success":
        try:
            observations = parser(result.stdout, scope, at, policy)
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeError, parse.ElementTree.ParseError):
            result = replace(result, outcome="parse_failed", diagnostic_code="invalid_bounded_output")
    if result.outcome == "success" and time.monotonic() >= deadline:
        result = replace(result, diagnostic_code="completed_at_boundary")
    return Probe(name, result.outcome, start, timestamp(utc_now()), "none" if host else "local_host",
                 "" if host else scope, evidence, result.diagnostic_code, observations)


def _ping(chunk: str, policy: Policy, deadline: float) -> Probe:
    # Explicit TCP SYN/connect discovery on fixed ports, not a port/service scan.
    # Nmap may substitute ARP on directly attached LANs when already privileged.
    argv = ("nmap", "-sn", "-n", "-PS80,443", "--host-timeout", str(policy.limits.host_timeout_seconds) + "s",
            "--max-parallelism", str(policy.limits.concurrent_probes),
            "--max-rate", str(PING_RATE_PER_SLOT * policy.limits.concurrent_probes), "-oX", "-", chunk)
    return _probe("ping_chunk", argv, "ping_response", parse.nmap,
                  chunk, policy, deadline, host=True)


def collect(policy: Policy, params: object) -> dict:
    """Fixed passive/Nmap or opt-in host sockets; no DB lock while probing.

    Every address in the configured range is accounted for, including network and
    broadcast addresses. Legacy child runs with at most concurrent_probes internal
    outstanding probes; the entire chunk has a host/command wall deadline.
    Only all-success coverage can report non-observation.
    """
    network, mode = validate_request(params, policy)
    started = timestamp(utc_now())
    deadline = time.monotonic() + policy.limits.operation_timeout_seconds
    reserve = min(policy.limits.busy_timeout_ms / 1000, policy.limits.operation_timeout_seconds / 4)
    transport_deadline = deadline - reserve
    if mode == "passive":
        probes = tuple(_probe(name, argv, evidence, parser, network.cidr, policy, transport_deadline)
                       for name, argv, evidence, parser in PASSIVE)
    else:
        probes = (collect_methods(network, policy, transport_deadline)
                  if network.icmp_echo or network.tcp_ports != LEGACY_TCP_PORTS
                  else _active(network.cidr, policy, transport_deadline))
    probes = _batch_bound(probes, policy)
    successes = sum(probe.outcome == "success" for probe in probes)
    completion = "complete" if successes == len(probes) else "partial" if successes else "failed"
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("operation deadline before persistence")
    with Store(policy, writable=True, deadline=deadline) as store:
        result = store_batch(store, "local_passive" if mode == "passive" else "ping", network.name,
                             started, timestamp(utc_now()), completion, probes, receipt=True, deadline=deadline)
        assert isinstance(result, dict)
        return result


def _active(scope: str, policy: Policy, deadline: float) -> tuple[Probe, ...]:
    network = ip_network(scope)
    chunks = (network,) if network.prefixlen >= PING_CHUNK_PREFIX else network.subnets(new_prefix=PING_CHUNK_PREFIX)
    results = []
    for chunk in chunks:
        if time.monotonic() >= deadline:
            at = timestamp(utc_now())
            probe = Probe("ping_chunk", "not_started", at, at, "none", "", "ping_response", "operation_deadline_exceeded")
        else:
            probe = _ping(str(chunk), policy, deadline)
        results.extend(_chunk_addresses(chunk, probe, len(results)))
    at = timestamp(utc_now())
    success = all(probe.outcome == "success" for probe in results)
    coverage = Probe("ping_coverage", "success" if success else "command_failed", at, at,
                     "exact_network" if success else "none", scope if success else "", "ping_response",
                     "ok" if success else "incomplete_scope")
    return tuple(results) + (coverage,)


def _chunk_addresses(chunk, probe: Probe, offset: int) -> tuple[Probe, ...]:
    """Derive address checks from complete chunk XML, never synthetic hosts.

    An omitted address is checked-not-observed only after a successful complete
    parse. All addresses inherit an unsuccessful chunk's unknown outcome.
    """
    observations = {}
    for observation in probe.observations:
        assert isinstance(observation.value, tuple)
        observations[dict(observation.value)["address"]] = observation
    return tuple(replace(probe, probe_name="ping_" + str(offset + index),
                         observations=(observations[str(address)],) if str(address) in observations else ())
                 for index, address in enumerate(chunk))


def _batch_bound(probes: tuple[Probe, ...], policy: Policy) -> tuple[Probe, ...]:
    remaining = policy.limits.observations
    result = []
    overflow = False
    for probe in probes:
        if len(probe.observations) > remaining:
            probe = replace(probe, outcome="parse_failed", observations=(), diagnostic_code="batch_observation_limit")
            overflow = True
        remaining -= len(probe.observations)
        if overflow and probe.probe_name == "ping_coverage":
            probe = replace(probe, outcome="parse_failed", coverage_kind="none", coverage_value="", diagnostic_code="batch_observation_limit")
        result.append(probe)
    return tuple(result)
