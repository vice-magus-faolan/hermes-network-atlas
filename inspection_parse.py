# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded Linux SSH output parsers. Text is data, never sourced or evaluated."""
from __future__ import annotations

import re

from .batches import Anchor, Observation
from .config import Policy
from . import discovery_parse as local
from .updates import _text


def _text_data(data: bytes, policy: Policy) -> str:
    if len(data) > policy.limits.output_bytes:
        raise ValueError("output bound exceeded")
    text = data.decode("utf-8")
    if any(ord(char) < 32 and char not in "\n\t" for char in text):
        raise ValueError("control characters in scalar output")
    return text


def _device(alias: str, field: str, value: str, at: str, policy: Policy) -> Observation:
    return Observation("device", Anchor("alias", alias, str(policy.home)), field, value, at)


def hostname(data: bytes, alias: str, at: str, policy: Policy) -> tuple[Observation, ...]:
    """A single scalar, not a command or a device merge key."""
    value = _text(_text_data(data, policy).rstrip("\n"), policy.limits.input_chars)
    if "\n" in value or "\t" in value:
        raise ValueError("one hostname line required")
    return (_device(alias, "hostname", value, at, policy),)


def _release_value(raw: str, policy: Policy) -> str:
    # os-release permits one unquoted or single/double-quoted shell-compatible
    # string. Decode the documented escapes only; no substitution or execution.
    pattern = r'''(?:"(?:[^"\\]|\\["\\$`])*"|'[^']*'|[A-Za-z0-9._/+-]*)'''
    if re.fullmatch(pattern, raw) is None:
        raise ValueError("invalid os-release quoting")
    value = raw
    if raw.startswith('"'):
        value = re.sub(r'\\(["\\$`])', r'\1', raw[1:-1])
    elif raw.startswith("'"):
        value = raw[1:-1]
    if len(value) > policy.limits.input_chars:
        raise ValueError("os-release scalar bound")
    return value


def os_release(data: bytes, alias: str, at: str, policy: Policy) -> tuple[Observation, ...]:
    """Parse assignments without sourcing the file or obeying embedded shell text."""
    lines = _text_data(data, policy).splitlines()
    if len(lines) > policy.limits.observations:
        raise ValueError("os-release record bound")
    values = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)", line)
        if match is None or match[1] in values:
            raise ValueError("invalid or duplicate os-release assignment")
        values[match[1]] = _release_value(match[2], policy)
    value = values.get("PRETTY_NAME", values.get("NAME"))
    return (_device(alias, "os", _text(value, policy.limits.input_chars), at, policy),)


def _interfaces(data: bytes, at: str, policy: Policy, *, addresses: bool) -> tuple[Observation, ...]:
    if len(data) > policy.limits.output_bytes:
        raise ValueError("output bound exceeded")
    observations, names = [], set()
    for index, row in enumerate(local._records(data, policy)):
        name = _text(row.get("ifname"), policy.limits.input_chars)
        if name in names:
            raise ValueError("duplicate interface name")
        names.add(name)
        anchor = local._anchor(row.get("address"), "ssh_interface_" + str(index))
        observations.append(Observation("interface", anchor, "name", name, at))
        if "operstate" in row:
            observations.append(Observation("interface", anchor, "state", _text(row["operstate"], 32), at))
        if addresses:
            observations.extend(_assignments(row.get("addr_info"), anchor, at, policy))
    return local._bounded(observations, policy)


def _assignments(entries: object, anchor: Anchor, at: str, policy: Policy) -> list[Observation]:
    if not isinstance(entries, list) or len(entries) > policy.limits.observations:
        raise ValueError("bounded address entries required")
    result = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("address object required")
        ip = local._ip(entry.get("local"))
        prefix = entry.get("prefixlen")
        if type(prefix) is not int or not 0 <= prefix <= ip.max_prefixlen:
            raise ValueError("invalid prefix")
        result.append(local._address(anchor, str(ip), prefix, at))
    return result


def addresses(data: bytes, alias: str, at: str, policy: Policy) -> tuple[Observation, ...]:
    """Observe IPv4/IPv6 ownership, not address reachability or scan authority."""
    del alias
    return _interfaces(data, at, policy, addresses=True)


def links(data: bytes, alias: str, at: str, policy: Policy) -> tuple[Observation, ...]:
    """Only stable noncolliding MACs can later resolve an owned remote interface."""
    del alias
    return _interfaces(data, at, policy, addresses=False)


def routes(data: bytes, alias: str, at: str, policy: Policy) -> tuple[Observation, ...]:
    """Validate route metadata only; no fabricated relationships or range expansion."""
    if len(data) > policy.limits.output_bytes:
        raise ValueError("output bound exceeded")
    return local.routes(data, alias, at, policy)


def neighbors(data: bytes, alias: str, at: str, policy: Policy) -> tuple[Observation, ...]:
    """Validate cached remote neighbors but do not import them as host-owned interfaces."""
    del alias, at
    if len(data) > policy.limits.output_bytes:
        raise ValueError("output bound exceeded")
    for row in local._records(data, policy):
        local._ip(row.get("dst"))
        if "lladdr" in row:
            local._anchor(row["lladdr"], "neighbor")
        states = row.get("state", ["NONE"])
        if not isinstance(states, list) or len(states) != 1 or states[0] not in local.NEIGHBOR_STATES:
            raise ValueError("invalid neighbor state")
        if "dev" in row:
            _text(row["dev"], policy.limits.input_chars)
    return ()
