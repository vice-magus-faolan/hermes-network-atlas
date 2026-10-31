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


ENDPOINT_KEYS = ("source_device", "source_interface", "target_device", "target_interface", "relationship_type")


class BatchIndex:
    """One bounded load/parse of originals, indexed for constant-time route joins."""

    def __init__(self, store: Store, batch_id: str):
        self.batch = store.require("batches", batch_id)
        self.routes, self.variants, self.neighbors = {}, {}, {}
        self.names, self.anchor_names = {}, {}
        rows = _rows(store, "SELECT * FROM observations WHERE batch_id=? AND entity_id IS NULL ORDER BY rowid",
                     (batch_id,))
        for row in rows:
            store.check_deadline()
            self._index(row)
        latest = store.connection.execute("SELECT id FROM batches WHERE collector='ssh' AND policy_context=? "
            "AND scope_value=? ORDER BY ended_at DESC,rowid DESC LIMIT 1",
            (self.batch["policy_context"], self.batch["scope_value"])).fetchone()
        self.latest = latest is not None and latest[0] == batch_id

    def _index(self, row) -> None:
        if row["subject_kind"] == "route":
            value = json.loads(row["value_json"])
            self.routes[row["id"]] = (row, value)
            self.variants.setdefault((value["dst"], value["table"]), set()).add(
                (value["gateway"], value["dev"], value["type"], value["unsupported"]))
        elif row["subject_kind"] == "neighbor":
            value = json.loads(row["value_json"])
            self.neighbors.setdefault((value["dst"], value["dev"]), []).append((row, value))
        elif row["subject_kind"] == "interface" and row["field"] == "name":
            name = json.loads(row["value_json"])
            self.names.setdefault(name, set()).add(row["subject_anchor"])
            self.anchor_names.setdefault(row["subject_anchor"], set()).add(name)


class TopologySnapshot:
    """Disposable read indexes; construct after inventory writes or inside a snapshot.

    Explicitly shared by query filters/details/status and map devices. A device
    scope restricts candidate edges at SQL selection, not after materialization.
    Never kept across requests: later evidence and identity changes must be visible.
    """

    def __init__(self, store: Store, now: datetime, *, device: str | None = None):
        self.store = store
        self.device = device
        self.current = timestamp(now)
        self.cutoff = timestamp(now - timedelta(days=store.policy.stale_after_days))
        self.batches, self.origins, self.sources, self.peers = {}, {}, {}, {}
        self.interfaces, self.assignments, self.retirements = {}, {}, {}
        self.answers, self.memberships = {}, {}
        self.by_device = {}
        self.current_relations = None

    def batch(self, batch_id: str) -> BatchIndex:
        if batch_id not in self.batches:
            self.batches[batch_id] = BatchIndex(self.store, batch_id)
        return self.batches[batch_id]

    def origin(self, row) -> str | None:
        key = (row["batch_id"], row["subject_kind"], row["subject_anchor"])
        if key not in self.origins:
            self.origins[key] = _origin(self.store, row, self.batch(row["batch_id"]).batch)
        return self.origins[key]

    def source(self, row, device: str, name: str) -> str | None:
        key = (row["batch_id"], device, name)
        if key not in self.sources:
            self.sources[key] = _source_interface(self, row, device, name)
        return self.sources[key]

    def interface(self, mac: str) -> list:
        if mac not in self.interfaces:
            self.interfaces[mac] = _interface(self.store, mac)
        return self.interfaces[mac]

    def gateway_assignments(self, address: str) -> list:
        if address not in self.assignments:
            self.assignments[address] = _rows(self.store,
                "SELECT a.*,o.confidence,o.qualified,o.evidence_kind,o.observed_at "
                "FROM addresses a JOIN observations o ON o.id=a.observation_id "
                "WHERE a.address=? AND a.ended_at IS NULL", (address,))
        return self.assignments[address]

    def peer(self, batch_id: str, route: dict) -> dict:
        key = (batch_id, route["gateway"], route["dev"])
        if key not in self.peers:
            matches = self.batch(batch_id).neighbors.get((route["gateway"], route["dev"]), [])
            self.peers[key] = _peer(self, route, matches)
        return self.peers[key]

    def retired(self, device: str) -> bool:
        if device not in self.retirements:
            self.retirements[device] = bool(self.store.require("devices", device)["retired"])
        return self.retirements[device]

    def resolve(self, row) -> dict:
        self.store.check_deadline()
        if row["id"] not in self.answers:
            self.answers[row["id"]] = resolve_route(self, row)
        return self.answers[row["id"]]

    def relations(self) -> list:
        """Index only eligible collector edges, not the operator's entire graph."""
        if self.current_relations is None:
            self.current_relations = [row for row in _candidate_relations(self)
                                      if relation_supported(self, row)]
            self.by_device = {}
            for row in self.current_relations:
                for device in {row["source_device"], row["target_device"]}:
                    self.by_device.setdefault(device, []).append(row)
        return self.current_relations

    def relationship_for(self, row) -> tuple | None:
        batch_id = row["batch_id"]
        if batch_id not in self.memberships:
            # Start from this batch's projected evidence, not the store-wide
            # relation graph. Match the original receipt, never a later fact.
            rows = _rows(self.store, "SELECT r.*,o.value_json FROM observations o JOIN relations r "
                         "ON r.id=o.entity_id AND r.observation_id=o.id WHERE o.batch_id=? "
                         "AND o.subject_kind='relationship' AND o.entity_id IS NOT NULL "
                         "AND o.evidence_kind='configured_route' "
                         "ORDER BY r.id", (batch_id,))
            members = {}
            for relation in rows:
                for member in json.loads(relation["value_json"])["route_evidence_ids"]:
                    self.store.check_deadline()
                    members[member] = (_endpoints(relation), relation["id"])
            self.memberships[batch_id] = members
        return self.memberships[batch_id].get(row["id"])


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


def _source_interface(snapshot: TopologySnapshot, row, device: str, name: str) -> str | None:
    batch = snapshot.batch(row["batch_id"])
    anchors = batch.names.get(name, set())
    if len(anchors) != 1:
        return None
    anchor = json.loads(next(iter(anchors)))
    if anchor["kind"] != "mac":
        return None
    # A shared MAC under different output names is not one unambiguous interface.
    names = batch.anchor_names[next(iter(anchors))]
    matches = snapshot.interface(anchor["value"])
    if len(names) != 1 or len(matches) != 1 or matches[0]["device_id"] != device:
        return None
    return matches[0]["id"]


def _peer(snapshot: TopologySnapshot, route: dict, matches: list) -> dict:
    values = {row["value_json"] for row, _ in matches}
    if not values:
        return {"reason": "missing_neighbor"}
    if len(values) != 1:
        return {"reason": "conflicting_neighbors"}
    cutoff, current = snapshot.cutoff, snapshot.current
    if any(not cutoff <= row["observed_at"] <= current for row, _ in matches):
        return {"reason": "stale_or_future_neighbor"}
    neighbor = matches[0][1]
    if neighbor["state"] not in {"REACHABLE", "PERMANENT"}:
        return {"reason": "unusable_neighbor_state"}
    interfaces = snapshot.interface(neighbor["lladdr"])
    if len(interfaces) != 1:
        return {"reason": "no_unique_stable_peer"}
    peer = interfaces[0]
    assignments = snapshot.gateway_assignments(route["gateway"])
    owners = {item["interface_id"] for item in assignments}
    if owners != {peer["id"]}:
        return {"reason": "ambiguous_or_missing_gateway_assignment"}
    support = [item for item in assignments if cutoff <= item["observed_at"] <= current
               and (item["confidence"] == "user_supplied" or (item["confidence"] == "observed"
                    and item["qualified"] and item["evidence_kind"] in {"ssh_response", "local_interface"}))]
    if not support:
        return {"reason": "unqualified_or_stale_gateway_assignment"}
    return {"reason": "supported", "target_device": peer["device_id"], "target_interface": peer["id"],
            "supporting_evidence_ids": sorted({row["id"] for row, _ in matches}
                                              | {item["observation_id"] for item in support})}


def resolve_route(snapshot: TopologySnapshot, row) -> dict:
    """Explain one original route without creating identities or mutating evidence."""
    batch = snapshot.batch(row["batch_id"])
    if not snapshot.cutoff <= row["observed_at"] <= snapshot.current:
        return {"reason": "stale_or_future_route"}
    if not batch.latest:
        return {"reason": "superseded_inspection"}
    device = snapshot.origin(row)
    if device is None:
        return {"reason": "unapplied_or_ambiguous_origin"}
    route = batch.routes[row["id"]][1]
    reason = _route_reason(route, batch.variants[(route["dst"], route["table"])])
    if reason:
        return {"reason": reason, "source_device": device}
    source = snapshot.source(row, device, route["dev"])
    if source is None:
        return {"reason": "unresolved_source_interface", "source_device": device}
    if not route["gateway"]:
        return {"reason": "no_next_hop", "source_device": device, "source_interface": source}
    peer = snapshot.peer(row["batch_id"], route)
    if peer["reason"] != "supported":
        return {**peer, "source_device": device}
    if peer["target_device"] == device:
        return {"reason": "self_next_hop", "source_device": device}
    if snapshot.retired(device) or snapshot.retired(peer["target_device"]):
        return {"reason": "retired_endpoint", "source_device": device}
    return {**peer, "source_device": device, "source_interface": source, "relationship_type": "routes_via"}


def _route_reason(route: dict, variants: set) -> str | None:
    if (not route["dev"] or route["type"] != "unicast"
            or route["table"] not in {"main", "254"} or route["unsupported"]
            or (route["gateway"] and ip_address(route["gateway"]).version != 4)
            or (route["dst"] != "default" and ip_network(route["dst"]).version != 4)):
        return "unsupported_route"
    return "conflicting_routes" if len(variants) != 1 else None


def _endpoints(value) -> tuple:
    return tuple(value[key] for key in ENDPOINT_KEYS)


def retain_and_derive(app, observations: list) -> None:
    """Join the existing atomic application; route/cache evidence never sights peers."""
    rows = [row for row in observations if row["subject_kind"] in {"route", "neighbor"}]
    if app.ssh_device is not None:
        for row in rows:
            app.store.check_deadline()
            app.store.connection.execute("""INSERT INTO observations SELECT ?,batch_id,probe_id,subject_kind,
              subject_anchor,?,field,value_json,source,confidence,observed_at,evidence_kind,explanation,
              neighbor_state,qualified FROM observations WHERE id=?""", (identifier(), app.ssh_device, row["id"]))
    snapshot = TopologySnapshot(app.store, app.now)
    groups = {}
    for row in rows:
        if row["subject_kind"] != "route":
            continue
        resolution = snapshot.resolve(row)
        if resolution["reason"] == "no_next_hop":
            continue  # Retained connected configuration has no peer identity to resolve.
        if resolution["reason"] != "supported":
            app.result["unresolved"].append({"evidence_id": row["id"], **resolution})
            continue
        groups.setdefault(_endpoints(resolution), []).append((row, resolution))
    for key in sorted(groups):
        members = sorted(groups[key], key=lambda member: member[0]["id"])
        relation = _persist_relation(app.store, members)
        app.result.setdefault("relationships", []).append(relation)
        app.changed.add(key[0])
        app.event("logical_relationship_inferred", relation, {"route_evidence_count": len(members)})


def _persist_relation(store: Store, members: list) -> str:
    route, resolution = members[0]
    relation, observation = identifier(), identifier()
    value = {key: resolution[key] for key in ENDPOINT_KEYS}
    value["route_evidence_ids"] = [row["id"] for row, _ in members]
    value["route_evidence_count"] = len(members)
    value["supporting_evidence_ids"] = sorted({item for _, answer in members
                                              for item in answer["supporting_evidence_ids"]})
    value["evidence_query"] = {"view": "topology", "batch_id": route["batch_id"]}
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


def relation_supported(snapshot: TopologySnapshot, relation) -> bool:
    """Gate only collector-derived edges; operator/inference assertions keep their semantics."""
    store = snapshot.store
    fact = store.connection.execute("SELECT * FROM observations WHERE id=?", (relation["observation_id"],)).fetchone()
    if fact is None:
        raise ValueError("relationship lacks supporting observation")
    if fact["evidence_kind"] != "configured_route":
        return True
    if store.connection.execute("SELECT 1 FROM observations WHERE entity_id=? AND subject_kind='relationship' "
                                "AND evidence_kind!='configured_route' LIMIT 1", (relation["id"],)).fetchone():
        return True
    batch = snapshot.batch(fact["batch_id"])
    for member in json.loads(fact["value_json"])["route_evidence_ids"]:
        store.check_deadline()
        if member not in batch.routes:
            raise ValueError("relationship lacks route evidence")
        resolved = snapshot.resolve(batch.routes[member][0])
        if resolved["reason"] == "supported" and _endpoints(resolved) == _endpoints(relation):
            return True
    return False


def relation_condition(snapshot: TopologySnapshot, device: str | None = None) -> tuple[str, list]:
    """Shared eligibility SQL; detail reuses the device's indexed collector IDs."""
    rows = snapshot.relations()
    if device is not None:
        rows = snapshot.by_device.get(device, [])
    accepted = [row["id"] for row in rows]
    marks = ",".join("?" for _ in accepted) or "NULL"
    # Correlate by the observation PK: enumerating every configured-route ID
    # would make even an isolated device query scan unrelated stored history.
    return ("(NOT EXISTS (SELECT 1 FROM observations origin WHERE origin.id=r.observation_id "
            "AND origin.evidence_kind='configured_route') "
            f"OR {ASSERTED_RELATION} OR r.id IN ({marks}))", accepted)


def _candidate_relations(snapshot: TopologySnapshot) -> list:
    # Prune obsolete *relationship projections*, never immutable observations
    # before selection. Failed/empty/latest attempts still supersede old routes.
    # A representative member's time cannot suppress a healthy sibling member;
    # current support/age is checked on each original, not on the group receipt.
    where = """b.started_at<=? AND b.ended_at>=? AND
      b.id=(SELECT id FROM batches latest WHERE latest.collector='ssh'
            AND latest.policy_context=b.policy_context AND latest.scope_value=b.scope_value
            ORDER BY latest.ended_at DESC,latest.rowid DESC LIMIT 1)"""
    # Assertions bypass collector eligibility in relation_condition. They must
    # not consume its route-evidence bound, even when attached to an old edge.
    where = "o.evidence_kind='configured_route' AND NOT " + ASSERTED_RELATION + " AND (" + where + ")"
    bindings = [snapshot.current, snapshot.cutoff]
    if snapshot.device is not None:
        where += " AND (r.source_device=? OR r.target_device=?)"
        bindings.extend((snapshot.device, snapshot.device))
    return _rows(snapshot.store, "SELECT r.* FROM relations r JOIN observations o ON o.id=r.observation_id "
                 "JOIN batches b ON b.id=o.batch_id WHERE " + where + " ORDER BY r.id",
                 tuple(bindings))


def route_answer(snapshot: TopologySnapshot, row) -> dict:
    """Explain current route support against its immutable application membership."""
    answer = snapshot.resolve(row)
    membership = snapshot.relationship_for(row)
    if answer["reason"] != "supported":
        return {**answer, "relationship_id": membership[1]} if membership else answer
    if membership and membership[0] == _endpoints(answer):
        return {**answer, "relationship_id": membership[1]}
    return {**answer, "reason": "not_derived_at_application"}


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
        snapshot = TopologySnapshot(store, now)
        rows = store.connection.execute("SELECT o.*,b.policy_context,b.scope_value AS origin_alias "
            "FROM observations o JOIN batches b ON b.id=o.batch_id WHERE " + where +
            " ORDER BY o.observed_at,o.id LIMIT ? OFFSET ?",
            (*values, params["limit"] + 1, params["offset"])).fetchall()
        items = [{**evidence(row), "batch_id": row["batch_id"], "probe_id": row["probe_id"],
                  "kind": row["subject_kind"], "origin_alias": row["origin_alias"],
                  "policy_context": row["policy_context"],
                  "local_policy_context": row["policy_context"] == str(policy.home),
                  "origin_device": snapshot.origin(row),
                  "stale": row["observed_at"] < timestamp(now - timedelta(days=policy.stale_after_days)),
                  "resolution": route_answer(snapshot, row) if row["subject_kind"] == "route"
                                else {"reason": "support_only_not_owned_inventory"}}
                 for row in rows[:params["limit"]]]
    return {"observations": items, "has_more": len(rows) > params["limit"], "limit": params["limit"],
            "offset": params["offset"], "discovery_performed": False}
