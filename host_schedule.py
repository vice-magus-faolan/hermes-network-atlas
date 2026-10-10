# SPDX-License-Identifier: GPL-3.0-or-later
"""One fair rate/concurrency/deadline/receive budget for every opted-in method."""
from __future__ import annotations

from dataclasses import replace
from collections.abc import Iterator
from ipaddress import ip_network
import math
import selectors
import time

from .batches import Anchor, Observation, Probe
from .config import Network, Policy, validate_network
from .host_discovery import icmp_capability
from . import host_transport as transport
from .storage import timestamp, utc_now


def method_count(network: Network) -> int:
    return len(network.tcp_ports) + int(network.icmp_echo)


def validate_count(network: Network, policy: Policy) -> None:
    """Worst-case method + address + coverage records must fit before any effect."""
    validate_network(network)
    count = ip_network(network.cidr).num_addresses * (method_count(network) + 1) + 1
    if count > policy.limits.observations:
        raise ValueError('configured probe count too small for complete method scope')


def _plans(network: Network, window: int) -> Iterator[tuple[int, str, int | None]]:
    """Rotate first methods by address, then round-robin addresses on each pass.

    Use a window no larger than the shared concurrency ceiling. Within each
    window a slow method cannot monopolize all methods; unlike range-wide
    passes, later methods do not wait behind 256 initial attempts. A host deadline
    begins at its first attempt and never resets. No retries.
    """
    methods = ([None] if network.icmp_echo else []) + list(network.tcp_ports)
    addresses = list(ip_network(network.cidr))
    for offset in range(0, len(addresses), window):
        for turn in range(len(methods)):
            for index, address in enumerate(addresses[offset:offset + window], offset):
                yield index, str(address), methods[(turn + index) % len(methods)]


def _name(index: int, port: int | None) -> str:
    return 'icmp_' + str(index) if port is None else 'tcp_' + str(port) + '_' + str(index)


def _probe(index: int, address: str, port: int | None, started: str, result: transport.Outcome) -> Probe:
    outcome, code, positive = result
    at = timestamp(utc_now())
    observations = ()
    if positive:
        observations = (Observation('address', Anchor('unresolved', 'ping_' + address.replace('.', '_')),
                                    'assignment', (('address', address), ('prefix_length', 32)), at),)
    return Probe(_name(index, port), outcome, started, at, 'none', '', 'ping_response', code, observations)


class Scheduler:
    """Internal single-threaded owner; selector and all sockets close on interruption."""
    def __init__(self, network: Network, policy: Policy, deadline: float):
        self.network, self.policy, self.deadline = network, policy, deadline
        self.host_deadlines: dict[int, float] = {}
        self.results: dict[tuple[int, int | None], Probe] = {}
        self.active: dict[object, tuple[transport.Attempt, int, str]] = {}
        self.plans = iter(_plans(network, policy.limits.concurrent_probes))
        self.pending = next(self.plans, None)
        self.next_start = time.monotonic()
        self.remaining_bytes = policy.limits.output_bytes
        self.capability = icmp_capability(network, deadline)

    def run(self) -> tuple[Probe, ...]:
        with selectors.DefaultSelector() as selector:
            try:
                while self.pending is not None or self.active:
                    self._step(selector)
            finally:
                for attempt, _, _ in self.active.values():
                    attempt.sock.close()
        return _aggregates(self.network, self.results)

    def _preflight(self, index, address, port):
        if transport.excluded(self.network, address):
            return 'unavailable', 'destination_excluded', False
        if port is None and self.capability.state != 'unverified':
            return self.capability.state, self.capability.diagnostic_code, False
        if time.monotonic() >= self.deadline:
            return 'not_started', 'operation_deadline_exceeded', False
        if self.remaining_bytes <= 0:
            return 'output_limit', 'shared_receive_limit', False
        if time.monotonic() >= self.host_deadlines.get(index, math.inf):
            return 'not_started', 'host_deadline_before_start', False
        return None

    def _launch(self, selector):
        assert self.pending is not None
        index, address, port = self.pending
        started = timestamp(utc_now())
        result = self._preflight(index, address, port)
        if result is None:
            now = time.monotonic()
            self.host_deadlines.setdefault(index, min(self.deadline, now + min(
                self.policy.limits.host_timeout_seconds, self.policy.limits.command_timeout_seconds)))
            self.next_start = now + 1 / (8 * self.policy.limits.concurrent_probes)
            # Reserve a fair slice for later methods within this host's ONE wall
            # deadline. Slices are reductions, never independent renewed budgets.
            bound = min(self.policy.limits.host_timeout_seconds, self.policy.limits.command_timeout_seconds)
            attempt_deadline = min(self.host_deadlines[index], now + bound / (method_count(self.network) + 1))
            attempt, result = transport.begin(self.network, address, port, attempt_deadline)
            if attempt is not None:
                # Own before registration so even a selector failure closes it.
                self.active[attempt.sock] = (attempt, index, started)
                selector.register(attempt.sock, transport.event_mask(port))
        if result is not None:
            self.results[(index, port)] = _probe(index, address, port, started, result)
        self.pending = next(self.plans, None)

    def _finish(self, selector, sock, result):
        attempt, index, started = self.active.pop(sock)
        try:
            selector.unregister(sock)
        finally:
            sock.close()
        self.results[(index, attempt.port)] = _probe(index, attempt.address, attempt.port, started, result)

    def _expire(self, selector):
        for sock, (attempt, _, _) in list(self.active.items()):
            if self.remaining_bytes <= 0:
                self._finish(selector, sock, ('output_limit', 'shared_receive_limit', False))
            elif time.monotonic() >= attempt.deadline:
                self._finish(selector, sock, ('timeout', 'effective_transport_deadline', False))

    def _step(self, selector):
        self._expire(selector)
        while self.pending is not None and len(self.active) < self.policy.limits.concurrent_probes:
            # Diagnostic-only records do not consume rate tokens or open sockets.
            if self._preflight(*self.pending) is None and time.monotonic() < self.next_start:
                break
            self._launch(selector)
        delay = self._delay()
        if not self.active:
            if delay > 0:
                time.sleep(delay)
            return
        for key, _ in selector.select(delay):
            attempt, _, _ = self.active[key.fileobj]
            # Expiry wins over late readiness: never fabricate a response at timeout.
            if time.monotonic() >= attempt.deadline:
                self._finish(selector, key.fileobj, ('timeout', 'effective_transport_deadline', False))
                continue
            result, size = transport.ready(attempt, self.remaining_bytes)
            self.remaining_bytes -= size
            if result is not None:
                self._finish(selector, key.fileobj, result)
            if self.remaining_bytes <= 0:
                break

    def _delay(self):
        if self.pending is None and not self.active:
            return 0
        boundaries = [self.deadline]
        boundaries.extend(attempt.deadline for attempt, _, _ in self.active.values())
        if self.pending is not None and len(self.active) < self.policy.limits.concurrent_probes:
            boundaries.append(self.next_start)
        return max(0, min(boundaries) - time.monotonic())


def _aggregates(network: Network, results: dict) -> tuple[Probe, ...]:
    probes = []
    methods = ([None] if network.icmp_echo else []) + list(network.tcp_ports)
    for index, _ in enumerate(ip_network(network.cidr)):
        checks = [results[(index, port)] for port in methods]
        probes.extend(checks)
        failed = next((probe for probe in checks if probe.outcome != 'success'), None)
        aggregate = replace(failed or checks[0], probe_name='ping_' + str(index),
                            started_at=min(p.started_at for p in checks), ended_at=max(p.ended_at for p in checks),
                            diagnostic_code='incomplete_methods' if failed else 'methods_completed', observations=())
        probes.append(aggregate)
    at = timestamp(utc_now())
    success = all(probe.outcome == 'success' for probe in probes)
    probes.append(Probe('ping_coverage', 'success' if success else 'command_failed', at, at,
                        'exact_network' if success else 'none', network.cidr if success else '',
                        'ping_response', 'ok' if success else 'incomplete_scope'))
    return tuple(probes)


def collect_methods(network: Network, policy: Policy, deadline: float) -> tuple[Probe, ...]:
    """Validated numeric-only socket transport under the collector's reserved budget."""
    validate_count(network, policy)
    if not math.isfinite(deadline) or not network.ping:
        raise ValueError('authorized finite transport deadline required')
    return Scheduler(network, policy, deadline).run()
