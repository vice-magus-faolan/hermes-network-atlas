# SPDX-License-Identifier: GPL-3.0-or-later
"""Parameterized bounded inventory queries. Read-only SQLite, no collectors/imports."""
from __future__ import annotations

from datetime import datetime, timedelta
from ipaddress import ip_address
import re

from .config import NAME_PATTERN, Policy
from .errors import RequestError
from .facts import RELATION_TYPES, evidence, freshness, selected_facts, selection_cte
from .storage import Store, timestamp, utc_now
from .updates import DEVICE_TYPES, _text
from .inspection_evidence import latest_inspection, most_recent_inspection
from .batches import OUTCOMES, reconciliation_scopes
from .ssh_identity import alias_is_ambiguous
from .unresolved import query_evidence
from .endpoints import endpoint_counts, query_endpoints
from .topology import TopologySnapshot, query_topology, relation_condition

QUERY_KEYS = {"view", "device_id", "name", "address", "device_type", "status", "access_method",
              "relationship", "related_to", "text", "limit", "offset", "batch_id"}
STATUSES = ("known", "observed", "stale", "retired", "unknown")


def validate_query(params: object, policy: Policy) -> dict:
    """Unknown arguments, invalid types, oversized text and pagination fail closed."""
    if not isinstance(params, dict) or not set(params) <= QUERY_KEYS:
        raise RequestError("query arguments: object with documented filters required")
    result = dict(params)
    for key, value in result.items():
        if key not in {"limit", "offset"}:
            _text(value, policy.limits.input_chars, key)
    _enum(result, "view", ("devices", "status", "history", "unresolved", "endpoints", "topology"))
    _enum(result, "device_type", DEVICE_TYPES)
    _enum(result, "status", STATUSES)
    _enum(result, "access_method", ("ssh",))
    _enum(result, "relationship", RELATION_TYPES)
    for key in ("device_id", "related_to", "batch_id"):
        if key in result and re.fullmatch(NAME_PATTERN, result[key]) is None:
            raise RequestError(f"{key}: stable atlas reference required")
    if "address" in result:
        try:
            if str(ip_address(result["address"])) != result["address"] or "%" in result["address"]:
                raise ValueError("noncanonical address")
        except ValueError as exc:
            raise RequestError("address: canonical unscoped IP address required") from exc
    result["limit"] = _page(result.get("limit", policy.limits.result_count), 1, policy.limits.result_count, "limit")
    result["offset"] = _page(result.get("offset", 0), 0, policy.limits.page_offset, "offset")
    _validate_view(params)
    return result


def _validate_view(params: dict) -> None:
    view = params.get("view", "devices")
    allowed = {"status": {"view"}, "history": {"view", "device_id", "limit", "offset"},
               "unresolved": {"view", "address", "batch_id", "limit", "offset"},
               "endpoints": {"view", "address", "batch_id", "limit", "offset"},
               "topology": {"view", "address", "batch_id", "limit", "offset"},
               "devices": QUERY_KEYS - {"batch_id"}}
    if not set(params) <= allowed[view]:
        raise RequestError("view: use only filters supported by the selected query view")
    if params.get("view") == "history" and "device_id" not in params:
        raise RequestError("device_id: history view requires an existing device ID")


def _enum(params: dict, key: str, choices: tuple[str, ...]) -> None:
    if key in params and params[key] not in choices:
        raise RequestError(f"{key}: choose a documented query option")


def _page(value: object, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise RequestError(f"{label}: integer within configured pagination bounds required")
    return value


def _like(value: str) -> str:
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _fact_filter(field: str, value: str, *, search: bool = False) -> tuple[str, list]:
    operation = "LIKE ? ESCAPE '\\'" if search else "= ?"
    return ("EXISTS (SELECT 1 FROM canonical c WHERE c.subject_kind='device' AND c.entity_id=d.id "
            f"AND c.field=? AND c.conflict=0 AND json_extract(c.value_json,'$') {operation})",
            [field, _like(value) if search else value])


def _access_filter(policy: Policy) -> tuple[str, list]:
    aliases = policy.authorized_aliases
    if not aliases:
        return "0", []
    marks = ",".join("?" for _ in aliases)
    return ("EXISTS (SELECT 1 FROM aliases a JOIN observations o ON o.id=a.observation_id "
            f"WHERE a.device_id=d.id AND a.policy_context=? AND a.alias IN ({marks}) "
            "AND (o.confidence='user_supplied' OR (o.confidence='observed' AND o.qualified=1)) "
            "AND (SELECT COUNT(DISTINCT device_id) FROM aliases b "
            "WHERE b.policy_context=a.policy_context AND b.alias=a.alias)=1)",
            [str(policy.home), *aliases])


def _status_sql(now: datetime, stale_days: int) -> tuple[str, str]:
    return ("CASE WHEN d.retired=1 THEN 'retired' WHEN d.last_seen IS NULL THEN 'known' "
            "WHEN d.last_seen<? THEN 'stale' ELSE 'observed' END", timestamp(now - timedelta(days=stale_days)))


def _filters(params: dict, policy: Policy, now: datetime) -> tuple[list[str], list]:
    clauses, values = [], []
    for key, field in (("name", "canonical_name"), ("device_type", "device_type")):
        if key in params:
            sql, bindings = _fact_filter(field, params[key], search=key == "name")
            if key == "name":
                hostname_sql, hostname_bindings = _fact_filter("hostname", params[key], search=True)
                sql = "(" + sql + " OR " + hostname_sql + ")"
                bindings.extend(hostname_bindings)
            clauses.append(sql)
            values.extend(bindings)
    if "device_id" in params:
        clauses.append("d.id=?")
        values.append(params["device_id"])
    if "address" in params:
        clauses.append("EXISTS (SELECT 1 FROM interfaces i JOIN addresses a ON a.interface_id=i.id "
                       "WHERE i.device_id=d.id AND a.ended_at IS NULL AND a.address=?)")
        values.append(params["address"])
    if "status" in params:
        sql, cutoff = _status_sql(now, policy.stale_after_days)
        clauses.append(sql + "=?")
        values.extend((cutoff, params["status"]))
    if "access_method" in params:
        sql, bindings = _access_filter(policy)
        clauses.append(sql)
        values.extend(bindings)
    return clauses, values


def _additional_filters(params: dict, topology: TopologySnapshot) -> tuple[list[str], list]:
    clauses, values = [], []
    if "text" in params:
        clauses.append("EXISTS (SELECT 1 FROM canonical c WHERE c.subject_kind='device' AND c.entity_id=d.id "
                       "AND c.conflict=0 AND json_extract(c.value_json,'$') LIKE ? ESCAPE '\\')")
        values.append(_like(params["text"]))
    if "relationship" in params or "related_to" in params:
        sql = "EXISTS (SELECT 1 FROM relations r WHERE (r.source_device=d.id OR r.target_device=d.id)"
        supported, bindings = relation_condition(topology)
        sql += " AND " + supported
        values.extend(bindings)
        if "relationship" in params:
            sql += " AND r.relationship_type=?"
            values.append(params["relationship"])
        if "related_to" in params:
            sql += " AND ((r.source_device=d.id AND r.target_device=?) OR (r.target_device=d.id AND r.source_device=?))"
            values.extend((params["related_to"], params["related_to"]))
        clauses.append(sql + ")")
    return clauses, values


def bounded_rows(store: Store, sql: str, params: tuple = ()) -> list:
    """Never silently omit child evidence when one entity exceeds the page ceiling."""
    rows = store.connection.execute(sql + " LIMIT ?", (*params, store.policy.limits.result_count + 1)).fetchall()
    if len(rows) > store.policy.limits.result_count:
        raise ValueError("entity detail exceeds configured result bound; use history pagination")
    return rows


def access_answers(store: Store, device: str) -> list[dict]:
    rows = bounded_rows(store, "SELECT * FROM aliases WHERE device_id=? ORDER BY policy_context,alias", (device,))
    answers = []
    for row in rows:
        local = row["policy_context"] == str(store.policy.home)
        anchors = store.connection.execute(
            "SELECT COUNT(DISTINCT device_id) FROM aliases WHERE policy_context=? AND alias=?",
            (row["policy_context"], row["alias"])).fetchone()[0]
        latest = store.connection.execute(
            "SELECT * FROM access_evidence WHERE device_id=? AND policy_context=? AND alias=? "
            "ORDER BY checked_at DESC,rowid DESC LIMIT 1",
            (device, str(store.policy.home), row["alias"])).fetchone() if local else None
        attempt = latest_inspection(store, row["alias"]) if local else None
        answers.append({"alias": row["alias"], "policy_context": row["policy_context"],
                        "authorized_for_atlas_ssh_inspection": (
                            local and anchors == 1 and row["alias"] in store.policy.authorized_aliases),
                        "ambiguous_association": anchors != 1,
                        "last_inspection": most_recent_inspection(attempt, latest),
                        "reachability": "not established by configuration"})
    return answers


def device_detail(store: Store, row, now: datetime, topology: TopologySnapshot | None = None) -> dict:
    """Return independent IDs, selected values, actual provenance and explicit collisions."""
    result = dict(row)
    result["status"] = freshness(row, now, store.policy.stale_after_days)
    result["fields"] = selected_facts(store.connection, "device", row["id"], now,
                                      store.policy.stale_after_days, store.policy.limits.result_count)
    result["access"] = access_answers(store, row["id"])
    result["interfaces"] = []
    for interface in bounded_rows(store, "SELECT * FROM interfaces WHERE device_id=? ORDER BY id", (row["id"],)):
        item = dict(interface)
        item["fields"] = selected_facts(store.connection, "interface", interface["id"], now,
                                        store.policy.stale_after_days, store.policy.limits.result_count)
        item["addresses"] = _addresses(store, interface["id"])
        count = store.connection.execute(
            "SELECT COUNT(*) FROM interfaces WHERE mac_address=?", (interface["mac_address"],)).fetchone()[0]
        item["identity_uncertain"] = not interface["stable_mac"] or count > 1
        result["interfaces"].append(item)
    result["relationships"] = relationships(store, row["id"], now, topology or TopologySnapshot(store, now))
    return result


def _addresses(store: Store, interface: str) -> list[dict]:
    rows = bounded_rows(
        store, "SELECT a.*,o.confidence,o.evidence_kind,o.qualified,o.batch_id,o.neighbor_state FROM addresses a "
        "JOIN observations o ON o.id=a.observation_id WHERE a.interface_id=? ORDER BY address,id", (interface,))
    result = []
    for row in rows:
        item = dict(row)
        owners = store.connection.execute(
                                         "SELECT DISTINCT i.device_id FROM addresses a "
                                         "JOIN interfaces i ON i.id=a.interface_id "
                                         "WHERE a.address=? AND a.ended_at IS NULL ORDER BY i.device_id LIMIT ?",
                                         (row["address"], store.policy.limits.result_count + 1)).fetchall()
        if len(owners) > store.policy.limits.result_count:
            raise ValueError("address conflict candidates exceed configured result bound")
        item["current"] = row["ended_at"] is None
        item["observed_in_batch"] = row["batch_id"] is not None
        # SSH inventory establishes owned configuration, not contact with each
        # address. Its successful inspection belongs to the alias/access evidence.
        item["reachable_by_this_probe"] = bool(row["qualified"] and row["evidence_kind"] == "ping_response")
        item["ownership_conflict"] = item["current"] and len(owners) > 1
        item["candidate_device_ids"] = [owner[0] for owner in owners]
        result.append(item)
    return result


def relationships(store: Store, device: str, now: datetime, topology: TopologySnapshot) -> list[dict]:
    supported, bindings = relation_condition(topology, device)
    rows = bounded_rows(store, "SELECT r.* FROM relations r WHERE (r.source_device=? OR r.target_device=?) AND "
                        + supported + " ORDER BY r.id", (device, device, *bindings))
    result = []
    for row in rows:
        item = dict(row)
        item["facts"] = selected_facts(store.connection, "relationship", row["id"], now,
                                       store.policy.stale_after_days, store.policy.limits.result_count)
        result.append(item)
    return result


def _inventory(store: Store, params: dict, now: datetime) -> dict:
    topology = TopologySnapshot(store, now)
    cte, bindings = selection_cte(now, store.policy.stale_after_days)
    first, values = _filters(params, store.policy, now)
    second, extra = _additional_filters(params, topology)
    clauses = first + second
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    rows = store.connection.execute(cte + "SELECT d.* FROM devices d" + where + " ORDER BY d.id LIMIT ? OFFSET ?",
      (*bindings, *values, *extra, params["limit"] + 1, params["offset"])).fetchall()
    return {"devices": [device_detail(store, row, now, topology) for row in rows[:params["limit"]]],
            "limit": params["limit"], "offset": params["offset"], "has_more": len(rows) > params["limit"],
            "discovery_performed": False}


def _probe_totals(store: Store, batch: str) -> dict:
    """Aggregate the whole batch into fixed enums, independently of inventory pages."""
    outcomes = dict.fromkeys(OUTCOMES, 0)
    coverage = dict.fromkeys(("none", "local_host", "exact_network", "exact_target"), 0)
    group_bound = len(outcomes) * len(coverage) * 2
    rows = store.connection.execute(
        "SELECT outcome,coverage_kind,absence_eligible,COUNT(*) AS count FROM probes WHERE batch_id=? "
        "GROUP BY outcome,coverage_kind,absence_eligible LIMIT ?", (batch, group_bound + 1)).fetchall()
    if len(rows) > group_bound:
        raise ValueError("invalid probe summary groups")
    eligible = 0
    for row in rows:
        if row["outcome"] not in outcomes or row["coverage_kind"] not in coverage:
            raise ValueError("invalid stored probe summary enum")
        outcomes[row["outcome"]] += row["count"]
        coverage[row["coverage_kind"]] += row["count"]
        eligible += row["absence_eligible"] * row["count"]
    total = sum(outcomes.values())
    return {"total_count": total, "outcome_counts": outcomes, "coverage_counts": coverage,
            "failure_count": total - outcomes["success"], "absence_eligible_count": eligible,
            **_address_totals(store, batch)}


def _address_totals(store: Store, batch: str) -> dict:
    """Count native per-address ping records, excluding synthetic coverage.

    Legacy per-address names remain valid; aggregate-only legacy evidence has
    zero such records, not an invented address count derived from its CIDR.
    """
    outcomes = dict.fromkeys(OUTCOMES, 0)
    rows = store.connection.execute(
        "SELECT outcome,COUNT(*) AS count FROM probes WHERE batch_id=? "
        "AND batch_id IN (SELECT id FROM batches WHERE collector='ping') "
        "AND probe_name GLOB 'ping_[0-9]*' AND substr(probe_name,6) NOT GLOB '*[^0-9]*' "
        "GROUP BY outcome LIMIT ?", (batch, len(outcomes) + 1)).fetchall()
    for row in rows:
        if row["outcome"] not in outcomes:
            raise ValueError("invalid address outcome enum")
        outcomes[row["outcome"]] = row["count"]
    responses = store.connection.execute(
        "SELECT COUNT(DISTINCT json_extract(o.value_json,'$.address')) FROM observations o "
        "JOIN probes p ON p.id=o.probe_id WHERE o.batch_id=? AND o.entity_id IS NULL "
        "AND o.subject_kind='address' AND o.evidence_kind='ping_response' AND o.qualified=1 "
        "AND p.outcome='success'", (batch,)).fetchone()[0]
    return {"address_count": sum(outcomes.values()), "address_outcome_counts": outcomes,
            "responding_address_count": responses}


def _last_collection(store: Store, *, discovery_only: bool = False) -> dict | None:
    """Report this profile's immutable completion/coverage, not another profile's run."""
    restriction = " AND collector IN ('local_passive','ping')" if discovery_only else ""
    row = store.connection.execute("SELECT * FROM batches WHERE policy_context=?" + restriction +
                                   " ORDER BY ended_at DESC,rowid DESC LIMIT 1", (str(store.policy.home),)).fetchone()
    if row is None:
        return None
    totals = _probe_totals(store, row["id"])
    # Details are an explicit bounded sample, failures first. Counts and absence
    # qualification above cover every probe, including any omitted from the sample.
    probes = store.connection.execute(
        "SELECT probe_name,outcome,diagnostic_code,coverage_kind,coverage_value,absence_eligible "
        "FROM probes WHERE batch_id=? ORDER BY (outcome='success'),absence_eligible DESC,probe_name LIMIT ?",
        (row["id"], store.policy.limits.result_count)).fetchall()
    shown_failures = sum(probe["outcome"] != "success" for probe in probes)
    totals.update({"detail_limit": store.policy.limits.result_count, "returned_count": len(probes),
                   "omitted_count": totals["total_count"] - len(probes),
                   "omitted_failure_count": totals["failure_count"] - shown_failures})
    return {**dict(row), "probes": [dict(probe) for probe in probes],
            "probe_summary": totals,
            "scope_absence_eligible": row["completion"] == "complete" and totals["absence_eligible_count"] > 0}


def _guidance_page(items: list, limit: int) -> dict:
    """Give exact omission counts for a deliberately small set of next actions."""
    return {"items": items[:limit], "total_count": len(items), "omitted_count": max(0, len(items) - limit)}


def _pending_guidance(store: Store, limit: int) -> tuple[int, dict]:
    """Suggest only unapplied LAN/SSH batches matching current local grants."""
    pending = (" FROM batches b WHERE b.policy_context=? AND b.collector IN ('local_passive','ping','ssh') "
               "AND NOT EXISTS (SELECT 1 FROM applications a WHERE a.batch_id=b.id)")
    context = str(store.policy.home)
    total = store.connection.execute("SELECT COUNT(*)" + pending, (context,)).fetchone()[0]
    scopes = reconciliation_scopes(store.policy)
    match = " OR ".join("(b.collector=? AND b.scope_name=? AND b.scope_value=?)" for _ in scopes) or "0"
    eligible = pending + " AND (" + match + ")"
    bindings = (context, *(value for scope in scopes for value in scope))
    count = store.connection.execute("SELECT COUNT(*)" + eligible, bindings).fetchone()[0]
    rows = store.connection.execute("SELECT b.id" + eligible + " ORDER BY b.ended_at DESC,b.id DESC LIMIT ?",
                                    (*bindings, limit)).fetchall()
    return total, {"items": [{"tool": "network_reconcile", "parameters": {"batch_id": row["id"]}} for row in rows],
                   "total_count": count, "omitted_count": count - len(rows)}


def _guidance_state(store: Store | None, limit: int, now: datetime) -> dict:
    """Read summary counters from the caller's snapshot, never initialize a store."""
    if store is None:
        return {"local_collection_state": "none", "unapplied_local_batches": 0,
                "reconcilable_batches": _guidance_page([], limit),
                "historical_unresolved_applications": 0, "devices_without_relationships": 0}
    pending, batches = _pending_guidance(store, limit)
    unresolved = store.connection.execute(
        "SELECT COUNT(*) FROM applications WHERE json_array_length(result_json,'$.unresolved')>0").fetchone()[0]
    supported, bindings = relation_condition(TopologySnapshot(store, now))
    isolated = store.connection.execute(
        "SELECT COUNT(*) FROM devices d WHERE NOT EXISTS "
        "(SELECT 1 FROM relations r WHERE (r.source_device=d.id OR r.target_device=d.id) AND " +
        supported + ")", bindings).fetchone()[0]
    collected = bool(store.connection.execute(
        "SELECT 1 FROM batches WHERE policy_context=? LIMIT 1", (str(store.policy.home),)).fetchone())
    return {"local_collection_state": "recorded" if collected else "none",
            "unapplied_local_batches": pending, "reconcilable_batches": batches,
            "historical_unresolved_applications": unresolved, "devices_without_relationships": isolated}


def _guidance_notes(state: dict, known_devices: int, inspections: list) -> list[str]:
    """Explain inventory gaps without turning missing evidence into conclusions."""
    notes = []
    if not known_devices:
        notes.append("Canonical inventory is empty, not proof of an empty network. IP-only and TCP endpoint "
                     "responses do not establish device identity.")
    if state["local_collection_state"] == "none":
        notes.append("No collection is recorded for this profile. Reads do not collect evidence.")
    if state["unapplied_local_batches"]:
        notes.append("Stored LAN/SSH batches await application; only currently eligible local batches are suggested.")
    if state["historical_unresolved_applications"]:
        notes.append("Historical applications recorded unresolved identity/topology. Query view=unresolved for "
                     "address lineage or view=topology for next-hop reasons; "
                     "do not assign IP evidence to a device by address alone.")
    if not inspections:
        notes.append("No unambiguous currently authorized SSH inspection target is available; "
                     "stored queries remain usable.")
    if state["devices_without_relationships"]:
        notes.append("Devices without supported relationships remain isolated on maps, not disconnected. "
                     "SSH topology requires unambiguous supported next-hop evidence; "
                     "query view=topology for unresolved configuration. Do not invent physical links.")
    return notes


def inventory_guidance(policy: Policy, store: Store | None, known_devices: int, now: datetime) -> dict:
    """Project state and authorized choices; saved unresolved results are historical.

    The unresolved view remains authoritative for subsequent identity lineage.
    No collectors, policy writes or reconciliation are invoked here.
    """
    limit = min(5, policy.limits.result_count)
    inspections = [{"tool": "network_inspect", "parameters": {"target": alias}}
                   for alias in policy.authorized_aliases
                   if store is None or not alias_is_ambiguous(store, alias)]
    discoveries = [{"tool": "network_discover", "parameters": {"network": network.name, "mode": mode}}
                   for network in policy.networks
                   for mode, enabled in (("passive", network.passive), ("ping", network.ping)) if enabled]
    state = _guidance_state(store, limit, now)
    return {**state, "inventory_state": "empty" if not known_devices else "recorded",
            "inspection_targets": _guidance_page(inspections, limit),
            "discovery_options": _guidance_page(discoveries, limit),
            "notes": _guidance_notes(state, known_devices, inspections),
            "inventory_workflow": "When an inspection target is listed, inspect that authorized alias even "
                                  "without a device ID; reconcile its returned "
                                  "batch_id, then query the returned device ID and render a stored map. "
                                  "Actions are suggestions only and remain subject to current policy and limits.",
            "evidence_query": {"tool": "network_query", "parameters": {"view": "unresolved"}}}


def summary(store: Store, now: datetime) -> dict:
    sql, cutoff = _status_sql(now, store.policy.stale_after_days)
    counts = {row[0]: row[1] for row in store.connection.execute(
        "SELECT " + sql + ",COUNT(*) FROM devices d GROUP BY 1", (cutoff,))}
    access_sql, bindings = _access_filter(store.policy)
    accessible = store.connection.execute("SELECT COUNT(*) FROM devices d WHERE " + access_sql, bindings).fetchone()[0]

    inspection = store.connection.execute(
        "SELECT * FROM access_evidence WHERE policy_context=? "
        "ORDER BY checked_at DESC,rowid DESC LIMIT 1", (str(store.policy.home),)).fetchone()
    attempt = latest_inspection(store)
    return {"known_devices": sum(counts.values()), "status_counts": counts,
            **endpoint_counts(store),
            "observed_devices": counts.get("observed", 0), "stale_devices": counts.get("stale", 0),
            "authorized_devices_for_atlas_ssh_inspection": accessible,
            "last_collection": _last_collection(store), "last_discovery": _last_collection(store, discovery_only=True),
            "last_inspection": most_recent_inspection(attempt, inspection),
            "guidance": inventory_guidance(store.policy, store, sum(counts.values()), now)}


def _history(store: Store, params: dict) -> dict:
    store.require("devices", params["device_id"])
    rows = store.connection.execute("""SELECT * FROM observations WHERE entity_id=? OR entity_id IN
      (SELECT id FROM interfaces WHERE device_id=?) OR entity_id IN
      (SELECT a.id FROM addresses a JOIN interfaces i ON i.id=a.interface_id WHERE i.device_id=?) OR entity_id IN
      (SELECT id FROM relations WHERE source_device=? OR target_device=?) ORDER BY observed_at,id LIMIT ? OFFSET ?""",
      (params["device_id"],) * 5 + (params["limit"] + 1, params["offset"])).fetchall()
    return {"observations": [evidence(row) for row in rows[:params["limit"]]],
            "has_more": len(rows) > params["limit"], "limit": params["limit"], "offset": params["offset"]}


def query(policy: Policy, params: object, *, now: datetime | None = None) -> dict:
    """Query an existing store using one read snapshot. A missing store is empty, not created."""
    args = validate_query(params, policy)
    clock = now or utc_now()
    if args.get("view") == "unresolved":
        return query_evidence(policy, args, clock)
    if args.get("view") == "endpoints":
        return query_endpoints(policy, args)
    if args.get("view") == "topology":
        return query_topology(policy, args, clock)
    if not policy.database.exists():
        if args.get("view") == "history":
            raise RequestError("device_id: select an existing atlas entity")
        return {"devices": [], "has_more": False, "discovery_performed": False,
                "known_devices": 0, "observed_devices": 0, "stale_devices": 0, "status_counts": {},
                "authorized_devices_for_atlas_ssh_inspection": 0,
                "endpoint_count": 0,
                "responding_endpoint_count": 0,
                "endpoint_observation_count": 0, "endpoint_evidence_batches": 0, "unprojected_endpoint_batches": 0,
                "last_collection": None, "last_discovery": None, "last_inspection": None,
                **({"guidance": inventory_guidance(policy, None, 0, clock)} if args.get("view") == "status" else {})}
    with Store(policy) as store, store.snapshot():
        if args.get("view") == "status":
            return summary(store, clock)
        if args.get("view") == "history":
            return _history(store, args)
        return _inventory(store, args, clock)
