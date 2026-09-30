# SPDX-License-Identifier: GPL-3.0-or-later
"""One explicitly authorized host, fixed read-only Linux probes, bounded SSH transport.

OpenSSH config/credentials/known_hosts and executables are operator-trusted, not
sandboxed. The model selects only an alias/device. Collect first; store an atomic
immutable attempt batch second. Canonical identity is changed only by reconcile.
"""
from __future__ import annotations

from dataclasses import replace
from collections.abc import Callable
import time

from . import inspection_parse as parse
from .batches import Anchor, Observation, Probe, store_batch
from .config import Policy
from .discovery import _batch_bound
from .probes import run
from .ssh_identity import resolve_target
from .storage import Store, timestamp, utc_now

Parser = Callable[[bytes, str, str, Policy], tuple[Observation, ...]]
ProbeDefinition = tuple[str, tuple[str, ...], Parser]

PROBES: tuple[ProbeDefinition, ...] = (("ssh_hostname", ("hostname",), parse.hostname),
          ("ssh_hostnamectl", ("hostnamectl", "--static"), parse.hostname),
          ("ssh_os_release", ("cat", "/etc/os-release"), parse.os_release),
          ("ssh_address", ("ip", "-j", "address"), parse.addresses),
          ("ssh_link", ("ip", "-j", "link"), parse.links),
          ("ssh_route", ("ip", "-j", "route"), parse.routes),
          ("ssh_neigh", ("ip", "-j", "neigh"), parse.neighbors))

SSH_OPTIONS = ("BatchMode=yes", "StrictHostKeyChecking=yes", "UpdateHostKeys=no", "VerifyHostKeyDNS=no",
               "NoHostAuthenticationForLocalhost=no", "KnownHostsCommand=none",
               "RequestTTY=no", "StdinNull=yes", "PermitLocalCommand=no", "LocalCommand=none",
               "ClearAllForwardings=yes", "ForwardAgent=no", "ForwardX11=no", "ForwardX11Trusted=no",
               "Tunnel=no", "ControlMaster=no", "ControlPath=none", "ControlPersist=no",
               "RemoteCommand=none", "SessionType=default", "ForkAfterAuthentication=no", "AddKeysToAgent=no",
               "ConnectionAttempts=1", "LogLevel=ERROR")


def ssh_argv(policy: Policy, alias: str, command: tuple[str, ...]) -> tuple[str, ...]:
    """No caller text reaches the remote command, flags, user, port, or jump path."""
    if alias not in policy.authorized_aliases or command not in tuple(probe[1] for probe in PROBES):
        raise ValueError("unauthorized alias or non-code-owned probe")
    options = SSH_OPTIONS + ("ConnectTimeout=" + str(policy.limits.host_timeout_seconds),)
    return ("ssh", "-T", "-n", "-a", "-x", *(part for option in options for part in ("-o", option)),
            alias, " ".join(command))


def _probe(policy: Policy, alias: str, definition: ProbeDefinition, deadline: float) -> Probe:
    name, command, parser = definition
    start = timestamp(utc_now())
    result = run(ssh_argv(policy, alias, command), policy.limits, deadline, host=True)
    at = timestamp(utc_now())
    observations = ()
    if result.outcome == "success":
        try:
            observations = parser(result.stdout, alias, at, policy)
            # A parsed empty ip result still proves a successful exact-target
            # inspection. This code-owned alias fact is not supplied by output.
            observations += (Observation("device", Anchor("alias", alias, str(policy.home)), "ssh_alias", alias, at),)
            if len(observations) > policy.limits.observations:
                raise ValueError("probe observation count exceeded")
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
            result = replace(result, outcome="parse_failed", diagnostic_code="invalid_bounded_output")
            observations = ()
    if time.monotonic() >= deadline:
        result = replace(result, outcome="timeout", diagnostic_code="host_operation_deadline_exceeded")
        observations = ()
    return Probe(name, result.outcome, start, timestamp(utc_now()),
                 "exact_target" if result.outcome == "success" else "none",
                 alias if result.outcome == "success" else "", "ssh_response", result.diagnostic_code, observations)


def collect(policy: Policy, params: object) -> dict:
    """Use one host-wide and whole-operation deadline; no write lock during transport.

    Invocation policy is immutable and reloaded by all public surfaces. Seven
    sequential commands never exceed configured concurrency. Reserve persistence
    time inside the operation budget, rather than restarting it after collection.
    """
    deadline = time.monotonic() + policy.limits.operation_timeout_seconds
    alias = resolve_target(policy, params, deadline)
    assert isinstance(params, dict)
    if len(PROBES) > policy.limits.observations:
        raise ValueError("probe count exceeds configured bound")
    started = timestamp(utc_now())
    reserve = min(policy.limits.busy_timeout_ms / 1000, policy.limits.operation_timeout_seconds / 4)
    host_deadline = min(deadline - reserve, time.monotonic() + policy.limits.host_timeout_seconds)
    probes = _batch_bound(tuple(_probe(policy, alias, definition, host_deadline) for definition in PROBES), policy)
    successes = sum(probe.outcome == "success" for probe in probes)
    completion = "complete" if successes == len(probes) else "partial" if successes else "failed"
    with Store(policy, writable=True, deadline=deadline) as store:
        # Recheck mapping under the persistence lock. A concurrent operator may
        # invalidate a device's association while SSH is running; never reroute it.
        result = store_batch(store, "ssh", alias, started, timestamp(utc_now()), completion,
                             probes, receipt=True, deadline=deadline, inspection_target=params["target"])
        assert isinstance(result, dict)
        return result
