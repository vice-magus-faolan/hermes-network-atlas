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
from .errors import RequestError
from .host_schedule import collect_methods, validate_count
from .host_transport import excluded
from .probes import run
from .storage import Store, require_current_schema, timestamp, utc_now

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
        raise RequestError("discovery arguments: network and mode required, no other arguments")
    name, mode = params["network"], params["mode"]
    if not isinstance(name, str):
        raise RequestError("network: configured network name required")
    if not isinstance(mode, str) or mode not in {"passive", "ping"}:
        raise RequestError("mode: choose passive or ping")
    network = next((item for item in policy.networks if item.name == name), None)
    if network is not None:
        validate_network(network, active=mode == "ping")
    if network is None or not getattr(network, mode):
        raise RequestError("network/mode: select a configured network and an enabled discovery mode")
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
        raise RequestError("limits.observations: selected discovery scope exceeds configured record budget")


def _probe(name: str, argv: tuple[str, ...], evidence: str, parser: Parser, scope: str,
           policy: Policy, deadline: float) -> Probe:
    start = timestamp(utc_now())
    result = run(argv, policy.limits, deadline)
    at = timestamp(utc_now())
    observations = ()
    if result.outcome == "success":
        try:
            observations = parser(result.stdout, scope, at, policy)
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeError, parse.ElementTree.ParseError):
            result = replace(result, outcome="parse_failed", diagnostic_code="invalid_bounded_output")
    if result.outcome == "success" and time.monotonic() >= deadline:
        result = replace(result, diagnostic_code="completed_at_boundary")
    return Probe(name, result.outcome, start, timestamp(utc_now()), "local_host",
                 scope, evidence, result.diagnostic_code, observations)


def _ping(chunk: str, policy: Policy, deadline: float,
          blocked: tuple[str, ...]) -> tuple[Probe, tuple[tuple[str, str], ...]]:
    # Explicit TCP SYN/connect discovery on fixed ports, not a port/service scan.
    # Nmap may substitute ARP on directly attached LANs when already privileged.
    # Verbosity makes Nmap emit down-host reasons, including local no-route
    # failures that otherwise look identical to completed no-response checks.
    argv = ("nmap", "-sn", "-n", "-PS80,443", "-v", "--host-timeout", str(policy.limits.host_timeout_seconds) + "s",
            "--max-parallelism", str(policy.limits.concurrent_probes),
            "--max-rate", str(PING_RATE_PER_SLOT * policy.limits.concurrent_probes), "-oX", "-")
    argv += (("--exclude", ",".join(blocked)) if blocked else ()) + (chunk,)
    start = timestamp(utc_now())
    result = run(argv, policy.limits, deadline, host=True)
    scan = parse.NmapScan((), ())
    if result.outcome == "success":
        try:
            scan = parse.nmap(result.stdout, chunk, timestamp(utc_now()), policy, excluded=blocked)
        except parse.NmapCoverageError as error:
            result = replace(result, outcome="unavailable", diagnostic_code=error.diagnostic_code)
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeError, parse.ElementTree.ParseError):
            result = replace(result, outcome="parse_failed", diagnostic_code="invalid_bounded_output")
    if result.outcome == "success" and time.monotonic() >= deadline:
        result = replace(result, diagnostic_code="completed_at_boundary")
    probe = Probe("ping_chunk", result.outcome, start, timestamp(utc_now()), "none", "", "ping_response",
                  result.diagnostic_code, scan.observations)
    return probe, scan.unavailable


def collect(policy: Policy, params: object) -> dict:
    """Fixed passive/Nmap or opt-in host sockets; no DB lock while probing.

    Every address in the configured range is accounted for, including network and
    broadcast addresses as excluded/unavailable. Legacy children run with at most
    concurrent_probes internal outstanding probes; each chunk has a host/command wall deadline.
    Only all-success coverage can report non-observation.
    """
    network, mode = validate_request(params, policy)
    started = timestamp(utc_now())
    deadline = time.monotonic() + policy.limits.operation_timeout_seconds
    require_current_schema(policy, deadline=deadline)
    reserve = min(policy.limits.busy_timeout_ms / 1000, policy.limits.operation_timeout_seconds / 4)
    transport_deadline = deadline - reserve
    if mode == "passive":
        probes = tuple(_probe(name, argv, evidence, parser, network.cidr, policy, transport_deadline)
                       for name, argv, evidence, parser in PASSIVE)
    else:
        probes = (collect_methods(network, policy, transport_deadline)
                  if network.icmp_echo or network.tcp_ports != LEGACY_TCP_PORTS
                  else _active(network, policy, transport_deadline))
    probes = _batch_bound(probes, policy)
    successes = sum(probe.outcome == "success" for probe in probes)
    completion = "complete" if successes == len(probes) else "partial" if successes else "failed"
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("operation deadline before persistence")
    with Store(policy, writable=True, deadline=deadline) as store:
        result = store_batch(store, "local_passive" if mode == "passive" else "ping", network.name,
                             started, timestamp(utc_now()), completion, probes, receipt=True, deadline=deadline)
        if not isinstance(result, dict):
            raise ValueError("discovery persistence receipt missing")
        return result


def _active(network: Network, policy: Policy, deadline: float) -> tuple[Probe, ...]:
    scope = ip_network(network.cidr)
    chunks = (scope,) if scope.prefixlen >= PING_CHUNK_PREFIX else scope.subnets(new_prefix=PING_CHUNK_PREFIX)
    results = []
    for chunk in chunks:
        # Exclusions belong to the configured scope, not artificial /28 edges.
        blocked = tuple(str(address) for address in chunk if excluded(network, str(address)))
        unavailable = ()
        if len(blocked) == chunk.num_addresses or time.monotonic() >= deadline:
            # All-excluded chunks use only the timestamps below: _chunk_addresses
            # replaces every placeholder outcome with destination_excluded.
            # Otherwise this is genuine work not started before the deadline.
            at = timestamp(utc_now())
            probe = Probe(
                "ping_chunk", "not_started", at, at, "none", "", "ping_response", "operation_deadline_exceeded")
        else:
            probe, unavailable = _ping(str(chunk), policy, deadline, blocked)
        results.extend(_chunk_addresses(chunk, probe, len(results), blocked, unavailable))
    at = timestamp(utc_now())
    success = all(probe.outcome == "success" for probe in results)
    coverage = Probe("ping_coverage", "success" if success else "command_failed", at, at,
                     "exact_network" if success else "none", network.cidr if success else "", "ping_response",
                     "ok" if success else "incomplete_scope")
    return tuple(results) + (coverage,)


def _chunk_addresses(chunk, probe: Probe, offset: int, blocked: tuple[str, ...],
                     unavailable: tuple[tuple[str, str], ...]) -> tuple[Probe, ...]:
    """Derive address checks from complete chunk XML, never synthetic hosts.

    Only explicitly checked no-response addresses inherit success. Excluded
    destinations were never checked. Valid XML can also identify individual
    unavailable checks without invalidating other addresses; corrupt chunks
    and unsuccessful commands remain unknown as a whole.
    """
    observations = {}
    for observation in probe.observations:
        if not isinstance(observation.value, tuple):
            raise ValueError("invalid parsed address observation")
        observations[dict(observation.value)["address"]] = observation
    diagnostics = dict(unavailable)
    diagnostics.update((address, "destination_excluded") for address in blocked)
    return tuple(replace(probe, probe_name="ping_" + str(offset + index),
                         outcome="unavailable" if str(address) in diagnostics else probe.outcome,
                         diagnostic_code=diagnostics.get(str(address), probe.diagnostic_code),
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
            probe = replace(probe, outcome="parse_failed", coverage_kind="none", coverage_value="",
                            diagnostic_code="batch_observation_limit")
        result.append(probe)
    return tuple(result)
