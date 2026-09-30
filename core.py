# SPDX-License-Identifier: GPL-3.0-or-later
"""Audited native mutations and typed seeding primitives; no transport or policy edits."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from ipaddress import ip_address

from .facts import DEVICE_FIELDS, INTERFACE_FIELDS
from .identity import mac_address
from .storage import Store, encode, identifier, parse_time, timestamp, utc_now
from .updates import Update, _text, inference_update, operator_update

INTERFACE_TYPES = ("ethernet", "wifi", "bridge", "vlan", "virtual", "loopback", "unknown")
POSITIVE_EVIDENCE = ("local_interface", "ping_response", "ssh_response")


def append_fact(store: Store, kind: str, entity: str, field: str, value: object,
                source: str, confidence: str, at: str, *, qualified: bool = False,
                evidence_kind: str = "none", explanation: str | None = None) -> str:
    """Append validated native evidence in an existing transaction; not a tool import API."""
    if not store.connection.in_transaction or not store.writable:
        raise ValueError("facts require an explicit writable transaction")
    parse_time(at)
    allowed = {"device": DEVICE_FIELDS, "interface": INTERFACE_FIELDS,
               "address": ("assignment",), "relationship": ("relationship",)}
    if kind not in allowed or field not in allowed[kind]:
        raise ValueError("unsupported fact")
    if confidence not in {"observed", "inferred", "user_supplied"}:
        raise ValueError("invalid confidence")
    if confidence == "inferred":
        _text(explanation, store.policy.limits.input_chars)
    if qualified and (confidence != "observed" or evidence_kind not in POSITIVE_EVIDENCE):
        raise ValueError("unqualified direct evidence")
    _text(source, 64)
    if len(encode(value)) > store.policy.limits.input_chars * 6 + 512:
        raise ValueError("oversized fact")
    fact = identifier()
    store.connection.execute("""INSERT INTO observations
      (id,subject_kind,subject_anchor,entity_id,field,value_json,source,confidence,
       observed_at,evidence_kind,explanation,qualified) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
      (fact, kind, entity, entity, field, encode(value), source, confidence, at,
       evidence_kind, explanation, int(qualified)))
    return fact


def _positive(store: Store, device: str, at: str) -> None:
    store.connection.execute("""UPDATE devices SET
      first_seen=CASE WHEN first_seen IS NULL OR first_seen>? THEN ? ELSE first_seen END,
      last_seen=CASE WHEN last_seen IS NULL OR last_seen<? THEN ? ELSE last_seen END,
      last_checked=CASE WHEN last_checked IS NULL OR last_checked<? THEN ? ELSE last_checked END WHERE id=?""",
      (at, at, at, at, at, at, device))


def create_device(store: Store, name: str, *, now: datetime | None = None) -> dict:
    """Create an operator-owned known record, never an artificial sighting."""
    name = _text(name, store.policy.limits.input_chars)
    at = timestamp(now or utc_now())
    device, operation = identifier(), identifier()
    with store.transaction():
        store.connection.execute("INSERT INTO devices(id,created_at) VALUES (?,?)", (device, at))
        observation = append_fact(store, "device", device, "canonical_name", name, "user", "user_supplied", at)
        event = store.audit(operation, "device_created", "user", at, entity=device,
                            details={"observation_id": observation})
    return {"device_id": device, "operation_id": operation, "audit_event_ids": [event],
            "applied": True, "persisted": True}


def _relationship(store: Store, update: Update, at: str) -> str:
    if not isinstance(update.value, tuple):
        raise ValueError("typed relationship required")
    value = dict(update.value)
    target = value["target_device"]
    store.require("devices", target)
    if target == update.device_id:
        raise ValueError("self relationship refused")
    for key, device in (("source_interface", update.device_id), ("target_interface", target)):
        if key in value and store.require("interfaces", value[key])["device_id"] != device:
            raise ValueError("interface does not belong to relationship endpoint")
    existing = store.connection.execute("""SELECT id FROM relations WHERE source_device=? AND target_device=?
      AND source_interface IS ? AND target_interface IS ? AND relationship_type=?""",
      (update.device_id, target, value.get("source_interface"), value.get("target_interface"),
       value["relationship_type"])).fetchone()
    relation = existing[0] if existing else identifier()
    observation = append_fact(store, "relationship", relation, "relationship", value,
                              update.source, update.confidence, at, explanation=update.explanation)
    if existing is None:
        store.connection.execute("INSERT INTO relations VALUES (?,?,?,?,?,?,?)",
                                 (relation, update.device_id, value.get("source_interface"), target,
                                  value.get("target_interface"), value["relationship_type"], observation))
    return observation


def _associate_alias(store: Store, update: Update, observation: str) -> None:
    # Inference is retained but cannot become an identity anchor or an access grant.
    if update.confidence == "inferred":
        return
    store.connection.execute("""INSERT INTO aliases VALUES (?,?,?,?,?)
      ON CONFLICT(device_id,policy_context,alias) DO UPDATE SET observation_id=excluded.observation_id""",
      (identifier(), update.device_id, str(store.policy.home), update.value, observation))


def apply_update(store: Store, update: Update, *, now: datetime | None = None) -> dict:
    """Apply validated assertions atomically; canonical selection remains field-specific."""
    at, operation = timestamp(now or utc_now()), identifier()
    value = dict(update.value) if isinstance(update.value, tuple) else update.value
    params = {"device_id": update.device_id, "field": update.field, "value": value}
    if update.source == "inference" and update.confidence == "inferred":
        checked = inference_update({**params, "explanation": update.explanation}, store.policy)
    elif update.source == "user" and update.confidence == "user_supplied":
        checked = operator_update(params, store.policy)
    else:
        raise ValueError("invalid native update envelope")
    with store.transaction():
        store.require("devices", checked.device_id)
        observation = _apply_fact(store, checked, at)
        event = store.audit(operation, "fact_asserted", checked.source, at, entity=checked.device_id,
                            details={"field": checked.field, "observation_id": observation})
    return {"validated": True, "applied": True, "persisted": True, "update": asdict(checked),
            "operation_id": operation, "observation_id": observation, "audit_event_ids": [event]}


def _apply_fact(store: Store, update: Update, at: str) -> str:
    if update.field == "relationship":
        return _relationship(store, update, at)
    observation = append_fact(store, "device", update.device_id, update.field, update.value,
                              update.source, update.confidence, at, explanation=update.explanation)
    if update.field == "retired":
        store.connection.execute("UPDATE devices SET retired=? WHERE id=?", (update.value is True, update.device_id))
    if update.field == "ssh_alias":
        _associate_alias(store, update, observation)
    return observation


def add_interface(store: Store, device: str, name: str, mac: str | None = None, *,
                  interface_type: str = "unknown", now: datetime | None = None) -> str:
    """Explicit operator same-device association; MAC collisions are retained, not merged."""
    _text(name, store.policy.limits.input_chars)
    if interface_type not in INTERFACE_TYPES:
        raise ValueError("invalid interface type")
    normalized, stable = mac_address(mac) if mac is not None else (None, False)
    at, interface, operation = timestamp(now or utc_now()), identifier(), identifier()
    with store.transaction():
        store.require("devices", device)
        store.connection.execute("INSERT INTO interfaces VALUES (?,?,?,?,?)",
                                 (interface, device, normalized, int(stable), at))
        for field, value in (("name", name), ("interface_type", interface_type)):
            append_fact(store, "interface", interface, field, value, "user", "user_supplied", at)
        if normalized is not None:
            append_fact(store, "interface", interface, "mac_address", normalized, "user", "user_supplied", at)
        store.audit(operation, "interface_associated", "user", at, entity=interface,
                    details={"device_id": device})
    return interface


def record_direct_fact(store: Store, kind: str, entity: str, field: str, value: str,
                       source: str, evidence_kind: str, *, now: datetime | None = None) -> str:
    """Trusted collector/test primitive for parsed same-subject positive evidence.

    No source string alone can qualify a fact; code must supply a supported
    evidence kind. Future collectors validate their scope before calling this.
    The model-facing update path cannot reach this method.
    """
    _text(value, store.policy.limits.input_chars)
    table = {"device": "devices", "interface": "interfaces"}.get(kind)
    if table is None:
        raise ValueError("invalid direct subject")
    if field in {"canonical_name", "description", "device_type", "retired", "ssh_alias", "mac_address"}:
        raise ValueError("direct collectors cannot change operator ownership or alias policy")
    at, operation = timestamp(now or utc_now()), identifier()
    with store.transaction():
        row = store.require(table, entity)
        observation = append_fact(store, kind, entity, field, value, source, "observed", at,
                                  qualified=True, evidence_kind=evidence_kind)
        _positive(store, entity if kind == "device" else row["device_id"], at)
        store.audit(operation, "direct_fact_recorded", source, at, entity=entity,
                    details={"observation_id": observation})
    return observation


def add_address(store: Store, interface: str, address: str, prefix_length: int, *,
                now: datetime | None = None) -> str:
    """Operator assertion of an assignment; multi-address sets and collisions survive."""
    ip = ip_address(address)
    if str(ip) != address or "%" in address:
        raise ValueError("canonical unscoped IP required")
    if type(prefix_length) is not int or not 0 <= prefix_length <= ip.max_prefixlen:
        raise ValueError("invalid address prefix")
    at, assignment, operation = timestamp(now or utc_now()), identifier(), identifier()
    with store.transaction():
        store.require("interfaces", interface)
        observation = append_fact(store, "address", assignment, "assignment",
                                  {"address": address, "prefix_length": prefix_length}, "user", "user_supplied", at)
        store.connection.execute("INSERT INTO addresses VALUES (?,?,?,?,?,?,?,?,?,NULL)",
          (assignment, interface, address, prefix_length, ip.version, "user", at, at, observation))
        store.audit(operation, "address_asserted", "user", at, entity=assignment,
                    details={"interface_id": interface, "observation_id": observation})
    return assignment


def end_address(store: Store, assignment: str, *, now: datetime | None = None) -> None:
    """Explicit operator historical transition; observing a different IP never calls this."""
    at, operation = timestamp(now or utc_now()), identifier()
    with store.transaction():
        row = store.connection.execute("SELECT * FROM addresses WHERE id=?", (assignment,)).fetchone()
        if row is None or row["ended_at"] is not None or at < row["first_seen"]:
            raise ValueError("invalid assignment transition")
        store.connection.execute("UPDATE addresses SET ended_at=? WHERE id=?", (at, assignment))
        store.audit(operation, "address_ended", "user", at, entity=assignment)
