# SPDX-License-Identifier: GPL-3.0-or-later
"""Small bounded iproute2 JSON / Nmap XML parsers; source text is data only."""
from __future__ import annotations

from ipaddress import ip_address, ip_network
import json
from xml.etree import ElementTree

from .batches import Anchor, Observation
from .config import Policy
from .identity import mac_address
from .updates import _text

NEIGHBOR_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP", "INCOMPLETE", "FAILED", "NONE"}


def _pairs(pairs: list) -> dict:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate JSON keys")
    return result


def _records(data: bytes, policy: Policy) -> list[dict]:
    rows = json.loads(data, object_pairs_hook=_pairs)
    if not isinstance(rows, list) or len(rows) > policy.limits.observations:
        raise ValueError("invalid or excessive records")
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("object records required")
    return rows


def _ip(value: object):
    if not isinstance(value, str):
        raise ValueError("address string required")
    result = ip_address(value)
    if str(result) != value or "%" in value:
        raise ValueError("canonical unscoped address required")
    return result


def _anchor(value: object, fallback: str) -> Anchor:
    if value is None:
        return Anchor("unresolved", fallback)
    mac, _ = mac_address(value)
    return Anchor("mac", mac)


def _address(anchor: Anchor, ip: str, prefix: int, at: str, state: str | None = None) -> Observation:
    return Observation("address", anchor, "assignment", (("address", ip), ("prefix_length", prefix)), at, state)


def addresses(data: bytes, scope: str, at: str, policy: Policy) -> tuple[Observation, ...]:
    """Only scoped local addresses; metadata does not authorize other ranges."""
    network = ip_network(scope)
    observations = []
    for index, row in enumerate(_records(data, policy)):
        name = _text(row.get("ifname"), policy.limits.input_chars)
        anchor = _anchor(row.get("address"), "local_" + str(index))
        entries = row.get("addr_info")
        if not isinstance(entries, list) or len(entries) > policy.limits.observations:
            raise ValueError("bounded address entries required")
        scoped = _local_addresses(entries, anchor, network, at)
        if scoped:
            observations.extend(scoped)
            observations.append(Observation("interface", anchor, "name", name, at))
            if "operstate" in row:
                observations.append(Observation("interface", anchor, "state", _text(row["operstate"], 32), at))
    return _bounded(observations, policy)


def _local_addresses(entries: list, anchor: Anchor, network, at: str) -> list[Observation]:
    result = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("address object required")
        ip = _ip(entry.get("local"))
        prefix = entry.get("prefixlen")
        if type(prefix) is not int or not 0 <= prefix <= ip.max_prefixlen:
            raise ValueError("invalid prefix")
        if ip in network:
            result.append(_address(anchor, str(ip), prefix, at))
    return result


def neighbors(data: bytes, scope: str, at: str, policy: Policy) -> tuple[Observation, ...]:
    """Cached entries, including FAILED/INCOMPLETE, never establish reachability."""
    network = ip_network(scope)
    observations = []
    for index, row in enumerate(_records(data, policy)):
        ip = _ip(row.get("dst"))
        states = row.get("state", ["NONE"])
        if not isinstance(states, list) or len(states) != 1 or states[0] not in NEIGHBOR_STATES:
            raise ValueError("invalid neighbor state")
        anchor = _anchor(row.get("lladdr"), "neighbor_" + str(index))
        if ip in network:
            observations.append(_address(anchor, str(ip), ip.max_prefixlen, at, states[0]))
    return _bounded(observations, policy)


def routes(data: bytes, scope: str, at: str, policy: Policy) -> tuple[Observation, ...]:
    """Validate local route metadata without inventing topology or scan targets."""
    del scope, at
    for row in _records(data, policy):
        if "gateway" in row:
            _ip(row["gateway"])
        if "dev" in row:
            _text(row["dev"], policy.limits.input_chars)
        destination = row.get("dst", "default")
        if destination != "default":
            ip_network(destination, strict=True)
    return ()


def _bounded(observations: list[Observation], policy: Policy) -> tuple[Observation, ...]:
    if len(observations) > policy.limits.observations:
        raise ValueError("observation count exceeded")
    return tuple(observations)


def nmap(data: bytes, target: str, at: str, policy: Policy) -> tuple[Observation, ...]:
    """Require successful complete one-target numeric XML; no entity expansion.

    Nmap's empty DOCTYPE is accepted, but internal/external entities are refused.
    Prefix /32 records a host address, not a claimed interface subnet mask.
    """
    if b"<!ENTITY" in data.upper() or b"<!DOCTYPE" in data.upper() and b"[" in data:
        raise ValueError("XML entities refused")
    root = ElementTree.fromstring(data)
    if root.tag != "nmaprun" or len(list(root.iter())) > policy.limits.observations * 16 + 32:
        raise ValueError("invalid/bounded Nmap XML")
    stats = root.find("runstats")
    if stats is None:
        raise ValueError("incomplete scan")
    up = _scan_stats(stats)
    hosts = root.findall("host")
    if len(hosts) > 1:
        raise ValueError("unexpected target count")
    statuses = [host.find("status") for host in hosts]
    positive_hosts = sum(status is not None and status.get("state") == "up" for status in statuses)
    if positive_hosts != up:
        raise ValueError("host evidence disagrees with coverage summary")
    observations = []
    for host in hosts:
        observations.extend(_nmap_host(host, target, at))
    return _bounded(observations, policy)


def _scan_stats(stats) -> int:
    finished, hosts = stats.find("finished"), stats.find("hosts")
    if finished is None or hosts is None or finished.get("exit") != "success":
        raise ValueError("unsuccessful scan")
    up, down, total = (int(hosts.get(key, "-1")) for key in ("up", "down", "total"))
    if total != 1 or up not in (0, 1) or down != 1 - up:
        raise ValueError("inconsistent coverage")
    return up


def _nmap_host(host, target: str, at: str) -> list[Observation]:
    if host.get("timedout") == "true":
        raise ValueError("timed out host")
    status = host.find("status")
    if status is None or status.get("state") not in {"up", "down"}:
        raise ValueError("invalid host status")
    addresses = host.findall("address")
    ips = [element.get("addr") for element in addresses if element.get("addrtype") == "ipv4"]
    macs = [element.get("addr") for element in addresses if element.get("addrtype") == "mac"]
    if ips != [target] or len(macs) > 1:
        raise ValueError("out-of-target or duplicate address evidence")
    _ip(ips[0])
    if status.get("state") == "down":
        return []
    anchor = _anchor(macs[0] if macs else None, "ping_" + target.replace(".", "_"))
    return [_address(anchor, target, 32, at)]
