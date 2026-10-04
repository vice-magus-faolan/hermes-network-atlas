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
    rows = _records(data, policy)
    collisions = _duplicate_local_macs(rows)
    observations = []
    names = set()
    for index, row in enumerate(rows):
        name = _text(row.get("ifname"), policy.limits.input_chars)
        if name in names:
            raise ValueError("duplicate local interface name")
        names.add(name)
        anchor = _anchor(row.get("address"), "local_" + str(index))
        entries = row.get("addr_info")
        if not isinstance(entries, list) or len(entries) > policy.limits.observations:
            raise ValueError("bounded address entries required")
        scoped = _local_addresses(entries, anchor, network, at)
        # Retain colliding local names even when the other interface has no
        # scoped IP. Metadata is local-only; out-of-scope IPs stay excluded.
        if scoped or anchor.value in collisions:
            observations.extend(scoped)
            observations.append(Observation("interface", anchor, "name", name, at))
            if "operstate" in row:
                observations.append(Observation("interface", anchor, "state", _text(row["operstate"], 32), at))
    return _bounded(observations, policy)


def _duplicate_local_macs(rows: list[dict]) -> set[str]:
    seen, collisions = set(), set()
    for row in rows:
        if row.get("address") is not None:
            mac, _ = mac_address(row["address"])
            if mac in seen:
                collisions.add(mac)
            seen.add(mac)
    return collisions


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
    """Require successful complete numeric chunk XML; no entity expansion.

    Only Nmap's literal empty DOCTYPE is accepted; other declarations are refused.
    Prefix /32 records a host address, not a claimed interface subnet mask.
    """
    network = ip_network(target, strict=True)
    if network.version != 4 or network.num_addresses > 16:
        raise ValueError("bounded IPv4 chunk required")
    root = _nmap_xml(data, policy)
    if root.tag != "nmaprun" or len(list(root.iter())) > policy.limits.observations * 16 + 32:
        raise ValueError("invalid/bounded Nmap XML")
    stats = root.findall("runstats")
    if len(stats) != 1:
        raise ValueError("incomplete scan")
    up, down = _scan_stats(stats[0], network.num_addresses)
    hosts = root.findall("host")
    if len(hosts) > network.num_addresses:
        raise ValueError("unexpected target count")
    observations = []
    seen = set()
    for host in hosts:
        address, parsed = _nmap_host(host, network, at)
        if address in seen:
            raise ValueError("duplicate host address")
        seen.add(address)
        observations.extend(parsed)
    if len(observations) != up or len(hosts) - up > down:
        raise ValueError("host evidence disagrees with coverage summary")
    return _bounded(observations, policy)


def _nmap_xml(data: bytes, policy: Policy):
    if len(data) > policy.limits.output_bytes:
        raise ValueError("XML output bound exceeded")
    # Decode before checking declarations so UTF-16/NUL tricks cannot bypass
    # entity refusal. Numeric XML needs only UTF-8, never an external DTD.
    text = data.decode("utf-8")
    checked = text.replace("<!DOCTYPE nmaprun>", "", 1).upper()
    if "<!DOCTYPE" in checked or "<!ENTITY" in checked or "\x00" in text:
        raise ValueError("XML declarations/entities refused")
    return ElementTree.fromstring(text)


def _scan_stats(stats, expected: int) -> tuple[int, int]:
    finished, hosts = stats.findall("finished"), stats.findall("hosts")
    if len(finished) != 1 or len(hosts) != 1 or finished[0].get("exit") != "success":
        raise ValueError("unsuccessful scan")
    up, down, total = (int(hosts[0].get(key, "-1")) for key in ("up", "down", "total"))
    if total != expected or not 0 <= up <= total or down != total - up:
        raise ValueError("inconsistent coverage")
    return up, down


def _nmap_host(host, network, at: str) -> tuple[str, list[Observation]]:
    if host.get("timedout", "false") != "false":
        raise ValueError("timed out host")
    statuses = host.findall("status")
    if len(statuses) != 1 or statuses[0].get("state") not in {"up", "down"}:
        raise ValueError("invalid host status")
    addresses = host.findall("address")
    if any(element.get("addrtype") not in {"ipv4", "mac"} for element in addresses):
        raise ValueError("unexpected address family")
    ips = [element.get("addr") for element in addresses if element.get("addrtype") == "ipv4"]
    macs = [element.get("addr") for element in addresses if element.get("addrtype") == "mac"]
    if len(ips) != 1 or len(macs) > 1:
        raise ValueError("out-of-target or duplicate address evidence")
    target = str(_ip(ips[0]))
    if _ip(target) not in network:
        raise ValueError("out-of-chunk address")
    if statuses[0].get("state") == "down":
        return target, []
    anchor = _anchor(macs[0] if macs else None, "ping_" + target.replace(".", "_"))
    return target, [_address(anchor, target, 32, at)]
