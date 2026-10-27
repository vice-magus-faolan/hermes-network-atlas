# SPDX-License-Identifier: GPL-3.0-or-later
"""Conservative configured-next-hop inference over retained SSH evidence.

No identity creation, collection or authority lives here. The same resolver gates
application and all current query/map edges; immutable history is never repaired
into present certainty. A configured route is not cabling or live reachability.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
import json

from .facts import evidence
from .discovery_parse import NEIGHBOR_STATES
from .identity import mac_address
from .storage import Store, encode, identifier, timestamp
from .updates import _text

ROUTE_KEYS = {"dst", "gateway", "dev", "type", "table", "metric", "unsupported"}
NEIGHBOR_KEYS = {"dst", "lladdr", "dev", "state"}

ASSERTED_RELATION = ("EXISTS (SELECT 1 FROM observations asserted WHERE asserted.entity_id=r.id "
                     "AND asserted.subject_kind='relationship' AND asserted.evidence_kind!='configured_route')")


def validate_record(kind: str, value: dict, maximum: int) -> None:
    """Validate the normalized bounded subset, also at native batch insertion."""
    keys = ROUTE_KEYS if kind == "route" else NEIGHBOR_KEYS
    if set(value) != keys:
        raise ValueError("invalid topology fields")
    for key in keys - {"metric", "unsupported"}:
        if value[key] != "":
            _text(value[key], maximum)
        elif key not in {"gateway", "lladdr", "dev"}:
            raise ValueError("missing topology value")
    for key in ({"gateway"} if kind == "route" else {"dst"}):
        if value[key] and (str(ip_address(value[key])) != value[key] or "%" in value[key]):
            raise ValueError("canonical unscoped topology address required")
    if kind == "route":
        _validate_route(value)
    else:
        if value["state"] not in NEIGHBOR_STATES:
            raise ValueError("invalid neighbor state")
        if value["lladdr"] and mac_address(value["lladdr"])[0] != value["lladdr"]:
            raise ValueError("noncanonical neighbor MAC")


def _validate_route(value: dict) -> None:
    if value["dst"] != "default" and str(ip_network(value["dst"], strict=True)) != value["dst"]:
        raise ValueError("canonical route destination required")
    if type(value["metric"]) is not int or not 0 <= value["metric"] <= 4294967295:
        raise ValueError("invalid route metric")
    if type(value["unsupported"]) is not int or value["unsupported"] not in (0, 1):
        raise ValueError("invalid route qualification")


def _rows(store: Store, sql: str, args: tuple = ()) -> list:
    store.check_deadline()
    rows = store.connection.execute(sql + " LIMIT ?", (*args, store.policy.limits.observations + 1)).fetchall()
    if len(rows) > store.policy.limits.observations:
        raise ValueError("topology evidence exceeds configured observation bound")
    return rows


def _batch_records(store: Store, batch: str, kind: str) -> list:
    return _rows(store, "SELECT * FROM observations WHERE batch_id=? AND subject_kind=? "
                 "AND entity_id IS NULL ORDER BY rowid", (batch, kind))


def _origin(store: Store, row, batch) -> str | None:
    # Shared evidence is resolved in its originating context, never the reader's
    # identically spelled alias or current collection grants.
    owners = _rows(store, "SELECT DISTINCT a.device_id FROM aliases a JOIN observations o "
                   "ON o.id=a.observation_id WHERE a.policy_context=? AND a.alias=? "
                   "AND (o.confidence='user_supplied' OR (o.confidence='observed' AND o.qualified=1))",
                   (batch["policy_context"], batch["scope_value"]))
    copies = _rows(store, "SELECT DISTINCT entity_id FROM observations WHERE batch_id=? "
                  "AND subject_kind=? AND subject_anchor=? AND entity_id IS NOT NULL",
                  (batch["id"], row["subject_kind"], row["subject_anchor"]))
    if len(owners) != 1 or len(copies) != 1 or owners[0][0] != copies[0][0]:
        return None
    return owners[0][0]


def _interface(store: Store, mac: str) -> list:
    if not mac or not mac_address(mac)[1]:
        return []
    return _rows(store, "SELECT * FROM interfaces WHERE mac_address=? ORDER BY id", (mac,))


def _source_interface(store: Store, row, device: str, name: str) -> str | None:
    rows = _rows(store, "SELECT subject_anchor,value_json FROM observations WHERE batch_id=? "
                 "AND subject_kind='interface' AND field='name' AND entity_id IS NULL", (row["batch_id"],))
    anchors = {item["subject_anchor"] for item in rows if json.loads(item["value_json"]) == name}
    if len(anchors) != 1:
        return None
    anchor = json.loads(next(iter(anchors)))
    if anchor["kind"] != "mac":
        return None
    # A shared MAC under different output names is not one unambiguous interface.
    names = {item["value_json"] for item in rows if item["subject_anchor"] in anchors}
    matches = _interface(store, anchor["value"])
    if len(names) != 1 or len(matches) != 1 or matches[0]["device_id"] != device:
        return None
    return matches[0]["id"]


def _peer(store: Store, route: dict, neighbors: list, now: datetime) -> dict:
    matches = [row for row in neighbors if json.loads(row["value_json"])["dst"] == route["gateway"]
               and json.loads(row["value_json"])["dev"] == route["dev"]]
    values = {row["value_json"] for row in matches}
    if not values:
        return {"reason": "missing_neighbor"}
    if len(values) != 1:
        return {"reason": "conflicting_neighbors"}
    cutoff, current = timestamp(now - timedelta(days=store.policy.stale_after_days)), timestamp(now)
    if any(not cutoff <= item["observed_at"] <= current for item in matches):
        return {"reason": "stale_or_future_neighbor"}
    neighbor = json.loads(matches[0]["value_json"])
    if neighbor["state"] not in {"REACHABLE", "PERMANENT"}:
        return {"reason": "unusable_neighbor_state"}
    interfaces = _interface(store, neighbor["lladdr"])
    if len(interfaces) != 1:
        return {"reason": "no_unique_stable_peer"}
    peer = interfaces[0]
    assignments = _rows(store, "SELECT a.*,o.confidence,o.qualified,o.evidence_kind,o.observed_at "
                        "FROM addresses a JOIN observations o ON o.id=a.observation_id "
                        "WHERE a.address=? AND a.ended_at IS NULL", (route["gateway"],))
    owners = {item["interface_id"] for item in assignments}
    if owners != {peer["id"]}:
        return {"reason": "ambiguous_or_missing_gateway_assignment"}
    support = [item for item in assignments if cutoff <= item["observed_at"] <= current
               and (item["confidence"] == "user_supplied" or (item["confidence"] == "observed"
                    and item["qualified"] and item["evidence_kind"] in {"ssh_response", "local_interface"}))]
    if not support:
        return {"reason": "unqualified_or_stale_gateway_assignment"}
    return {"reason": "supported", "target_device": peer["device_id"], "target_interface": peer["id"],
            "supporting_evidence_ids": [item["id"] for item in matches] + [item["observation_id"] for item in support]}


def resolve_route(store: Store, row, now: datetime) -> dict:
    """Explain one original route without creating identities or mutating evidence."""
    batch = store.require("batches", row["batch_id"])
    current = timestamp(now)
    cutoff = timestamp(now - timedelta(days=store.policy.stale_after_days))
    if not cutoff <= row["observed_at"] <= current:
        return {"reason": "stale_or_future_route"}
    latest = store.connection.execute("SELECT id FROM batches WHERE collector='ssh' AND policy_context=? "
                                      "AND scope_value=? ORDER BY ended_at DESC,rowid DESC LIMIT 1",
                                      (batch["policy_context"], batch["scope_value"])).fetchone()
    if latest is None or latest[0] != batch["id"]:
        return {"reason": "superseded_inspection"}
    device = _origin(store, row, batch)
    if device is None:
        return {"reason": "unapplied_or_ambiguous_origin"}
    route = json.loads(row["value_json"])
    reason = _route_reason(route, _batch_records(store, batch["id"], "route"))
    if reason:
        return {"reason": reason, "source_device": device}
    source = _source_interface(store, row, device, route["dev"])
    if source is None:
        return {"reason": "unresolved_source_interface", "source_device": device}
    peer = _peer(store, route, _batch_records(store, batch["id"], "neighbor"), now)
    if peer["reason"] != "supported":
        return {**peer, "source_device": device}
    if peer["target_device"] == device:
        return {"reason": "self_next_hop", "source_device": device}
    if any(store.require("devices", endpoint)["retired"] for endpoint in (device, peer["target_device"])):
        return {"reason": "retired_endpoint", "source_device": device}
    return {**peer, "source_device": device, "source_interface": source, "relationship_type": "routes_via"}


def _route_reason(route: dict, rows: list) -> str | None:
    if (not route["gateway"] or not route["dev"] or route["type"] != "unicast"
            or route["table"] not in {"main", "254"} or route["unsupported"]
            or ip_address(route["gateway"]).version != 4
            or (route["dst"] != "default" and ip_network(route["dst"]).version != 4)):
        return "unsupported_route"
    candidates = [json.loads(row["value_json"]) for row in rows]
    variants = {(item["gateway"], item["dev"], item["type"], item["unsupported"])
                for item in candidates if item["dst"] == route["dst"] and item["table"] == route["table"]}
    return "conflicting_routes" if len(variants) != 1 else None


def retain_and_derive(app, observations: list) -> None:
    """Join the existing atomic application; route/cache evidence never sights peers."""
    rows = [row for row in observations if row["subject_kind"] in {"route", "neighbor"}]
    if app.ssh_device is not None:
        for row in rows:
            app.store.connection.execute("""INSERT INTO observations SELECT ?,batch_id,probe_id,subject_kind,
              subject_anchor,?,field,value_json,source,confidence,observed_at,evidence_kind,explanation,
              neighbor_state,qualified FROM observations WHERE id=?""", (identifier(), app.ssh_device, row["id"]))
    for row in rows:
        if row["subject_kind"] != "route":
            continue
        resolution = resolve_route(app.store, row, app.now)
        if resolution["reason"] != "supported":
            app.result["unresolved"].append({"evidence_id": row["id"], **resolution})
            continue
        relation = _persist_relation(app.store, row, resolution)
        app.result.setdefault("relationships", []).append(relation)
        app.changed.add(resolution["source_device"])
        app.event("logical_relationship_inferred", relation, {"evidence_id": row["id"]})


def _persist_relation(store: Store, route, resolution: dict) -> str:
    relation, observation = identifier(), identifier()
    value = {key: resolution[key] for key in ("target_device", "source_interface", "target_interface",
                                             "relationship_type", "supporting_evidence_ids")}
    value["route_evidence_id"] = route["id"]
    store.connection.execute("""INSERT INTO observations
      (id,batch_id,probe_id,subject_kind,subject_anchor,entity_id,field,value_json,source,confidence,
       observed_at,evidence_kind,explanation,qualified) VALUES (?,?,?,'relationship',?,?,'relationship',?,?,'inferred',
       ?,'configured_route',?,0)
      """, (observation, route["batch_id"], route["probe_id"], route["subject_anchor"], relation, encode(value),
            route["source"], route["observed_at"],
            "Configured next hop inferred from route, same-host neighbor and existing stable identity."))
    store.connection.execute("INSERT INTO relations VALUES (?,?,?,?,?,?,?)",
                             (relation, resolution["source_device"], resolution["source_interface"],
                              resolution["target_device"], resolution["target_interface"], "routes_via", observation))
    return relation


def relation_supported(store: Store, relation, now: datetime) -> bool:
    """Gate only collector-derived edges; operator/inference assertions keep their semantics."""
    fact = store.connection.execute("SELECT * FROM observations WHERE id=?", (relation["observation_id"],)).fetchone()
    if fact is None:
        raise ValueError("relationship lacks supporting observation")
    if fact["evidence_kind"] != "configured_route":
        return True
    if store.connection.execute("SELECT 1 FROM observations WHERE entity_id=? AND subject_kind='relationship' "
                                "AND evidence_kind!='configured_route' LIMIT 1", (relation["id"],)).fetchone():
        return True
    route = store.connection.execute("SELECT * FROM observations WHERE id=?",
                                    (json.loads(fact["value_json"])["route_evidence_id"],)).fetchone()
    if route is None:
        raise ValueError("relationship lacks route evidence")
    resolved = resolve_route(store, route, now)
    return resolved["reason"] == "supported" and all(resolved[key] == relation[key] for key in
               ("source_device", "source_interface", "target_device", "target_interface", "relationship_type"))


def relation_condition(store: Store, now: datetime) -> tuple[str, list]:
    """One eligibility rule for relationship filters and isolated-device guidance."""
    rows = _candidate_relations(store, now)
    accepted = [row["id"] for row in rows if relation_supported(store, row, now)]
    marks = ",".join("?" for _ in accepted) or "NULL"
    return ("(r.observation_id NOT IN (SELECT id FROM observations WHERE evidence_kind='configured_route') "
            f"OR {ASSERTED_RELATION} OR r.id IN ({marks}))", accepted)


def _candidate_relations(store: Store, now: datetime, device: str | None = None) -> list:
    # Prune obsolete *relationship projections*, never immutable observations
    # before selection. Failed/empty/latest attempts still supersede old routes.
    where = """o.evidence_kind='configured_route' AND o.observed_at BETWEEN ? AND ? AND
      b.id=(SELECT id FROM batches latest WHERE latest.collector='ssh'
            AND latest.policy_context=b.policy_context AND latest.scope_value=b.scope_value
            ORDER BY latest.ended_at DESC,latest.rowid DESC LIMIT 1)"""
    args = (timestamp(now - timedelta(days=store.policy.stale_after_days)), timestamp(now))
    if device is not None:
        where = "(o.evidence_kind!='configured_route' OR " + ASSERTED_RELATION + " OR (" + where + "))"
        where += " AND (r.source_device=? OR r.target_device=?)"
        args += (device, device)
    return _rows(store, "SELECT r.* FROM relations r JOIN observations o ON o.id=r.observation_id "
                 "LEFT JOIN batches b ON b.id=o.batch_id WHERE " + where + " ORDER BY r.id", args)


def supported_relationships(store: Store, device: str, now: datetime) -> list:
    rows = [row for row in _candidate_relations(store, now, device) if relation_supported(store, row, now)]
    if len(rows) > store.policy.limits.result_count:
        raise ValueError("relationship detail exceeds configured result bound; use history pagination")
    return rows


def _route_answer(store: Store, row, now: datetime) -> dict:
    answer = resolve_route(store, row, now)
    if answer["reason"] != "supported":
        return answer
    relation = store.connection.execute("SELECT r.id FROM relations r JOIN observations o ON o.id=r.observation_id "
        "WHERE o.evidence_kind='configured_route' AND json_extract(o.value_json,'$.route_evidence_id')=?",
        (row["id"],)).fetchone()
    return {**answer, "relationship_id": relation[0]} if relation else {
        **answer, "reason": "not_derived_at_application"}


def query_topology(policy, params: dict, now: datetime) -> dict:
    """Page original observations, including unapplied/foreign/unresolved history."""
    if not policy.database.exists():
        return {"observations": [], "has_more": False, "limit": params["limit"], "offset": params["offset"],
                "discovery_performed": False}
    where = "o.subject_kind IN ('route','neighbor') AND o.entity_id IS NULL"
    values = []
    for key, column in (("batch_id", "o.batch_id"), ("address", "json_extract(o.value_json,'$.gateway')")):
        if key in params:
            if key == "address":
                where += " AND (json_extract(o.value_json,'$.gateway')=? OR json_extract(o.value_json,'$.dst')=?)"
                values.extend((params[key], params[key]))
            else:
                where += " AND " + column + "=?"
                values.append(params[key])
    with Store(policy) as store, store.snapshot():
        rows = store.connection.execute("SELECT o.*,b.policy_context,b.scope_value AS origin_alias "
            "FROM observations o JOIN batches b ON b.id=o.batch_id WHERE " + where +
            " ORDER BY o.observed_at,o.id LIMIT ? OFFSET ?",
            (*values, params["limit"] + 1, params["offset"])).fetchall()
        items = [{**evidence(row), "batch_id": row["batch_id"], "probe_id": row["probe_id"],
                  "kind": row["subject_kind"], "origin_alias": row["origin_alias"],
                  "policy_context": row["policy_context"], "local_context": row["policy_context"] == str(policy.home),
                  "origin_device": _origin(store, row, store.require("batches", row["batch_id"])),
                  "stale": row["observed_at"] < timestamp(now - timedelta(days=policy.stale_after_days)),
                  "resolution": _route_answer(store, row, now) if row["subject_kind"] == "route"
                                else {"reason": "support_only_not_owned_inventory"}}
                 for row in rows[:params["limit"]]]
    return {"observations": items, "has_more": len(rows) > params["limit"], "limit": params["limit"],
            "offset": params["offset"], "discovery_performed": False}
