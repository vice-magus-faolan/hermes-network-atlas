# SPDX-License-Identifier: GPL-3.0-or-later
"""Typed immutable batch/application/access persistence for subsequent collectors.

This module stores validated evidence only. It executes no probes and performs no
canonical reconciliation. IDs, source, confidence and absence eligibility are
assigned by native code, never extracted from remote output or model arguments.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime
from ipaddress import ip_address, ip_network
import re
import time

from .facts import DEVICE_FIELDS, INTERFACE_FIELDS
from .identity import mac_address
from .storage import Store, encode, identifier, parse_time, response_json, timestamp, utc_now
from .updates import DEVICE_TYPES, _text
from .core import INTERFACE_TYPES

OUTCOMES = ("success", "unavailable", "timeout", "output_limit", "command_failed", "parse_failed")
EVIDENCE_KINDS = ("local_interface", "cached_neighbor", "ping_response", "ssh_response", "none")


@dataclass(frozen=True)
class Anchor:
    """Explicit anchor type; alias identity is qualified by local policy context."""
    kind: str
    value: str
    policy_context: str | None = None


@dataclass(frozen=True)
class Observation:
    """Bounded parsed evidence attached to one probe, not canonical entity identity."""
    subject_kind: str
    subject_anchor: Anchor
    field: str
    value: str | tuple[tuple[str, str | int], ...]
    observed_at: str
    neighbor_state: str | None = None


@dataclass(frozen=True)
class Probe:
    """One fixed native probe outcome with typed coverage and parsed observations."""
    probe_name: str
    outcome: str
    started_at: str
    ended_at: str
    coverage_kind: str
    coverage_value: str
    evidence_kind: str
    diagnostic_code: str = "ok"
    observations: tuple[Observation, ...] = ()


def _code(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value) is None:
        raise ValueError("bounded native diagnostic/probe code required")
    return value


def _scope(store: Store, collector: str, scope_name: str) -> tuple[str, str, str]:
    _code(scope_name)
    if collector == "ssh":
        if scope_name not in store.policy.authorized_aliases:
            raise ValueError("unauthorized SSH scope")
        return "ssh_alias", scope_name, "ssh:" + scope_name
    mode = {"local_passive": "passive", "ping": "ping"}.get(collector)
    if mode is None:
        raise ValueError("unknown collector")
    network = next((net for net in store.policy.networks if net.name == scope_name), None)
    if network is None or not getattr(network, mode):
        raise ValueError("disabled/out-of-policy network scope")
    return "network", network.cidr, collector


def _times(start: str, end: str, outer_start: str, outer_end: str) -> None:
    for value in (start, end, outer_start, outer_end):
        parse_time(value)
    if not outer_start <= start <= end <= outer_end:
        raise ValueError("inconsistent evidence times")


def _probe(probe: Probe, collector: str, scope: str, start: str, end: str) -> None:
    _code(probe.probe_name)
    _code(probe.diagnostic_code)
    _times(probe.started_at, probe.ended_at, start, end)
    if probe.outcome not in OUTCOMES or probe.evidence_kind not in EVIDENCE_KINDS:
        raise ValueError("invalid probe outcome/evidence")
    permitted = {"local_passive": {"local_host", "none"}, "ping": {"exact_network", "none"}, "ssh": {"exact_target", "none"}}
    if probe.coverage_kind not in permitted[collector]:
        raise ValueError("invalid collector coverage")
    if probe.coverage_kind != "none" and probe.coverage_value != scope:
        raise ValueError("out-of-scope probe")
    if probe.coverage_kind == "none" and probe.coverage_value != "":
        raise ValueError("unexamined coverage must be empty")
    expected = {"local_passive": {"local_interface", "cached_neighbor", "none"}, "ping": {"ping_response", "none"}, "ssh": {"ssh_response", "none"}}
    if probe.evidence_kind not in expected[collector]:
        raise ValueError("inconsistent collector evidence")
    if probe.outcome != "success" and probe.observations:
        raise ValueError("unsuccessful probe cannot produce positive evidence")


def _anchor(anchor: Anchor, store: Store) -> None:
    if anchor.kind == "mac":
        mac, _ = mac_address(anchor.value)
        if mac != anchor.value or anchor.policy_context is not None:
            raise ValueError("noncanonical MAC anchor")
    elif anchor.kind == "alias":
        if anchor.value not in store.policy.authorized_aliases or anchor.policy_context != str(store.policy.home):
            raise ValueError("out-of-policy alias anchor")
    elif anchor.kind == "unresolved":
        _code(anchor.value)
        if anchor.policy_context is not None:
            raise ValueError("invalid unresolved anchor context")
    else:
        raise ValueError("unknown typed anchor")


def _address_value(value: object, scope_kind: str, scope: str) -> None:
    if not isinstance(value, tuple):
        raise ValueError("typed address required")
    data = dict(value)
    if len(data) != len(value) or set(data) != {"address", "prefix_length"}:
        raise ValueError("invalid address fields")
    ip = ip_address(data["address"])
    if str(ip) != data["address"] or "%" in str(ip):
        raise ValueError("noncanonical unscoped address")
    prefix = data["prefix_length"]
    if type(prefix) is not int or not 0 <= prefix <= ip.max_prefixlen:
        raise ValueError("invalid prefix")
    if scope_kind == "network" and ip not in ip_network(scope):
        raise ValueError("out-of-scope address evidence")


def _observation(obs: Observation, probe: Probe, store: Store, kind: str, scope: str) -> None:
    _anchor(obs.subject_anchor, store)
    if obs.subject_anchor.kind == "alias" and (kind != "ssh_alias" or obs.subject_anchor.value != scope):
        raise ValueError("alias evidence outside exact inspected target")
    _times(obs.observed_at, obs.observed_at, probe.started_at, probe.ended_at)
    fields = {"device": DEVICE_FIELDS, "interface": INTERFACE_FIELDS,
              "address": ("assignment",), "relationship": ("relationship",)}
    if obs.subject_kind not in fields or obs.field not in fields[obs.subject_kind]:
        raise ValueError("invalid observation field")
    if obs.subject_kind == "address":
        _address_value(obs.value, kind, scope)
    elif obs.subject_kind == "relationship":
        raise ValueError("collector relationship parsing is deferred; use validated operator relations")
    else:
        _scalar_value(obs, store)
    if obs.neighbor_state is not None:
        if probe.evidence_kind != "cached_neighbor" or obs.neighbor_state not in {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP", "INCOMPLETE", "FAILED", "NONE"}:
            raise ValueError("invalid neighbor evidence state")


def _scalar_value(obs: Observation, store: Store) -> None:
    text = _text(obs.value, store.policy.limits.input_chars)
    if obs.field == "retired":
        raise ValueError("retirement is not collector-owned")
    if obs.field == "device_type" and text not in DEVICE_TYPES:
        raise ValueError("invalid device type evidence")
    if obs.field == "interface_type" and text not in INTERFACE_TYPES:
        raise ValueError("invalid interface type evidence")
    if obs.field == "mac_address" and mac_address(text)[0] != text:
        raise ValueError("noncanonical interface MAC evidence")


def store_batch(store: Store, collector: str, scope_name: str, started_at: str, ended_at: str,
                completion: str, probes: tuple[Probe, ...], *, receipt: bool = False,
                deadline: float | None = None) -> str | dict:
    """Validate all evidence first, then atomically append batch, probes, facts and event."""
    kind, scope, source = _scope(store, collector, scope_name)
    _times(started_at, ended_at, started_at, ended_at)
    _validate_probes(store, collector, kind, scope, started_at, ended_at, completion, probes)
    batch, operation = identifier(), identifier()
    with store.transaction():
        store.connection.execute("INSERT INTO batches VALUES (?,?,?,?,?,?,?,?,?,?,?)",
          (batch, 1, collector, source, str(store.policy.home), kind, scope_name, scope, started_at, ended_at, completion))
        for probe in probes:
            _insert_probe(store, batch, probe, collector, source, completion)
        store.audit(operation, "batch_stored", source, ended_at, batch=batch,
                    details={"completion": completion, "probe_count": len(probes)})
        result = batch_receipt(batch, completion, probes)
        if receipt:
            response_json(result, store.policy.limits.output_bytes)
        if deadline is not None and time.monotonic() >= deadline:
            raise ValueError("operation deadline during persistence")
    return result if receipt else batch


def batch_receipt(batch: str, completion: str, probes: tuple[Probe, ...]) -> dict:
    """Code-owned exact receipt checked before commit; no raw command output."""
    return {"batch_id": batch, "completion": completion, "persisted": True, "applied": False,
            "probes": [{"name": probe.probe_name, "outcome": probe.outcome,
                        "diagnostic_code": probe.diagnostic_code,
                        "observation_count": len(probe.observations)} for probe in probes]}


def _validate_probes(store: Store, collector: str, kind: str, scope: str, start: str, end: str,
                     completion: str, probes: tuple[Probe, ...]) -> None:
    if not isinstance(probes, tuple) or not 1 <= len(probes) <= store.policy.limits.observations:
        raise ValueError("invalid/bounded probe count")
    successes = sum(probe.outcome == "success" for probe in probes)
    expected = "complete" if successes == len(probes) else "partial" if successes else "failed"
    if completion != expected or len({probe.probe_name for probe in probes}) != len(probes):
        raise ValueError("inconsistent completion or duplicate probe")
    if sum(len(probe.observations) for probe in probes) > store.policy.limits.observations:
        raise ValueError("observation count exceeded")
    for probe in probes:
        _probe(probe, collector, scope, start, end)
        if not isinstance(probe.observations, tuple):
            raise ValueError("immutable observations required")
        for observation in probe.observations:
            _observation(observation, probe, store, kind, scope)


def _insert_probe(store: Store, batch: str, probe: Probe, collector: str, source: str, completion: str) -> None:
    probe_id = identifier()
    absence = (collector == "ping" and completion == "complete" and probe.outcome == "success"
               and probe.coverage_kind == "exact_network" and probe.evidence_kind == "ping_response")
    store.connection.execute("INSERT INTO probes VALUES (?,?,?,?,?,?,?,?,?,?,?)",
      (probe_id, batch, probe.probe_name, probe.outcome, probe.started_at, probe.ended_at,
       probe.coverage_kind, probe.coverage_value, probe.evidence_kind, int(absence), probe.diagnostic_code))
    for observation in probe.observations:
        value = dict(observation.value) if isinstance(observation.value, tuple) else observation.value
        qualified = probe.evidence_kind in {"local_interface", "ping_response", "ssh_response"}
        store.connection.execute("""INSERT INTO observations
          (id,batch_id,probe_id,subject_kind,subject_anchor,field,value_json,source,confidence,
           observed_at,evidence_kind,neighbor_state,qualified) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (identifier(), batch, probe_id, observation.subject_kind, encode(asdict(observation.subject_anchor)),
           observation.field, encode(value), source, "observed", observation.observed_at,
           probe.evidence_kind, observation.neighbor_state, int(qualified)))


def record_access(store: Store, device: str, alias: str, succeeded: bool, diagnostic_code: str, *,
                  batch: str | None = None, now: datetime | None = None) -> str:
    """Persist inspection outcome without manufacturing reachability or granting access."""
    if alias not in store.policy.authorized_aliases or type(succeeded) is not bool:
        raise ValueError("unauthorized access evidence")
    _code(diagnostic_code)
    at, record, operation = timestamp(now or utc_now()), identifier(), identifier()
    with store.transaction():
        store.require("devices", device)
        if batch is not None:
            row = store.require("batches", batch)
            if row["collector"] != "ssh" or row["scope_value"] != alias or row["policy_context"] != str(store.policy.home):
                raise ValueError("access batch mismatch")
        store.connection.execute("INSERT INTO access_evidence VALUES (?,?,?,?,?,?,?,?)",
          (record, device, str(store.policy.home), alias, int(succeeded), at, diagnostic_code, batch))
        store.audit(operation, "inspection_outcome", "ssh:" + alias, at, entity=device, batch=batch,
                    details={"access_evidence_id": record})
    return record
