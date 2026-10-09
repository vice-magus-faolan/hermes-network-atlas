# SPDX-License-Identifier: GPL-3.0-or-later
"""Strict, immutable profile-local policy. Loading never creates files or grants defaults."""
from __future__ import annotations

from dataclasses import dataclass, fields
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path
import re
from collections.abc import Mapping

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

MAX_CONFIG_BYTES = 65536
MAX_POLICY_ENTRIES = 32
NAME_PATTERN = r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}"
LEGACY_TCP_PORTS = (80, 443)
MAX_TCP_DISCOVERY_PORTS = 4
EXCLUDED_TCP_PORTS = frozenset({4403})


class ConfigError(ValueError):
    """Operator policy is malformed; no plugin surface may become usable."""


@dataclass(frozen=True)
class Limits:
    """Hard V1 ceilings. Policy may only lower them."""

    command_timeout_seconds: int = 15
    host_timeout_seconds: int = 10
    operation_timeout_seconds: int = 120
    concurrent_probes: int = 4
    output_bytes: int = 1048576
    observations: int = 4096
    input_chars: int = 4096
    result_count: int = 100
    page_offset: int = 10000
    busy_timeout_ms: int = 5000


@dataclass(frozen=True)
class Network:
    """One named canonical scope; IPv6 is passive-only."""

    name: str
    cidr: str
    passive: bool
    ping: bool
    icmp_echo: bool = False
    tcp_ports: tuple[int, ...] = LEGACY_TCP_PORTS


@dataclass(frozen=True)
class SSHHost:
    """A profile-local authorization, never an atlas-derived capability."""

    name: str
    alias: str
    inspect: bool


@dataclass(frozen=True)
class Policy:
    """Validated policy snapshot with profile-local config/exports and optional shared data."""

    home: Path
    database: Path
    networks: tuple[Network, ...]
    ssh_enabled: bool
    ssh_hosts: tuple[SSHHost, ...]
    limits: Limits
    stale_after_days: int
    include_addresses: bool
    include_interfaces: bool

    @property
    def authorized_aliases(self) -> tuple[str, ...]:
        """Return only aliases currently permitted for Atlas inspection."""
        return tuple(host.alias for host in self.ssh_hosts if self.ssh_enabled and host.inspect)

    @property
    def exports(self) -> Path:
        """Exports remain profile-local even when the database is explicitly shared."""
        return self.home / "network-atlas" / "exports"


def _object(value: object, allowed: set[str], label: str) -> Mapping:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be an object")
    if any(not isinstance(key, str) or key not in allowed for key in value):
        raise ConfigError(f"unknown key in {label}")
    return value


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise ConfigError(f"{label} must be boolean")
    return value


def _integer(value: object, ceiling: int, label: str) -> int:
    if type(value) is not int or not 1 <= value <= ceiling:
        raise ConfigError(f"{label} must be an integer in 1..{ceiling}")
    return value


def _name(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(NAME_PATTERN, value) is None:
        raise ConfigError("invalid policy name or SSH alias")
    return value


def _entries(value: object, label: str) -> Mapping:
    if not isinstance(value, dict) or len(value) > MAX_POLICY_ENTRIES:
        raise ConfigError(f"{label} must be an object with at most {MAX_POLICY_ENTRIES} entries")
    for key in value:
        _name(key)
    return value


def _scope(cidr: object) -> IPv4Network | IPv6Network:
    """Canonical bounded scope shared by all configured discovery methods."""
    if not isinstance(cidr, str) or len(cidr) > 64:
        raise ConfigError("network requires a canonical CIDR")
    try:
        network = ip_network(cidr, strict=True)
    except ValueError as exc:
        raise ConfigError("invalid CIDR") from exc
    if str(network) != cidr:
        raise ConfigError("CIDR must be canonical")
    if network.version == 4 and network.num_addresses > 256:
        raise ConfigError("V1 IPv4 scope exceeds 256 addresses")
    return network


def _tcp_ports(value: object) -> tuple[int, ...]:
    if type(value) is not list or len(value) > MAX_TCP_DISCOVERY_PORTS:
        raise ConfigError("tcp_ports must be a list with at most four ports")
    ports = tuple(_integer(port, 65535, "tcp port") for port in value)
    if len(set(ports)) != len(ports) or EXCLUDED_TCP_PORTS.intersection(ports):
        raise ConfigError("duplicate or excluded TCP discovery port")
    return tuple(sorted(ports))


def _network(name: str, raw: object) -> Network:
    data = _object(raw, {"cidr", "discovery"}, "network")
    network = _scope(data.get("cidr"))
    modes = _object(data.get("discovery", {}), {"passive", "ping", "icmp_echo", "tcp_ports"}, "network.discovery")
    passive = _bool(modes.get("passive", False), "passive")
    ping = _bool(modes.get("ping", False), "ping")
    icmp_echo = _bool(modes.get("icmp_echo", False), "icmp_echo")
    ports = _tcp_ports(modes.get("tcp_ports", list(LEGACY_TCP_PORTS)))
    if network.version == 6 and ping:
        raise ConfigError("V1 active discovery is IPv4 only")
    if icmp_echo and not ping:
        raise ConfigError("icmp_echo requires ping authorization")
    if ping and not (icmp_echo or ports):
        raise ConfigError("active discovery requires at least one method")
    return Network(name, str(network), passive, ping, icmp_echo, ports)


def validate_network(network: Network) -> None:
    """Revalidate native snapshots before invocation, not just YAML at startup."""
    if type(network.tcp_ports) is not tuple or len(network.tcp_ports) > MAX_TCP_DISCOVERY_PORTS:
        raise ConfigError("invalid immutable TCP discovery ports")
    _network(_name(network.name), {"cidr": network.cidr, "discovery": {
        "passive": network.passive, "ping": network.ping, "icmp_echo": network.icmp_echo,
        "tcp_ports": list(network.tcp_ports)}})


def _ssh(raw: object) -> tuple[bool, tuple[SSHHost, ...]]:
    data = _object(raw, {"enabled", "hosts"}, "ssh")
    enabled = _bool(data.get("enabled", False), "ssh.enabled")
    hosts = []
    for name, item in _entries(data.get("hosts", {}), "ssh.hosts").items():
        host = _object(item, {"alias", "inspect"}, "ssh.host")
        hosts.append(SSHHost(name, _name(host.get("alias")), _bool(host.get("inspect", False), "inspect")))
    if len({host.alias for host in hosts}) != len(hosts):
        raise ConfigError("duplicate SSH alias anchors")
    return enabled, tuple(sorted(hosts, key=lambda host: host.name))


def validate_policy(raw: object, home: Path) -> Policy:
    """Validate a complete operator policy; unknown keys and coercion fail closed."""
    data = _object(raw, {"version", "networks", "ssh", "limits", "retention", "render", "store"}, "policy")
    if type(data.get("version", 1)) is not int or data.get("version", 1) != 1:
        raise ConfigError("unsupported configuration version")
    networks = tuple(_network(name, item) for name, item in sorted(
        _entries(data.get("networks", {}), "networks").items()))
    ssh_enabled, ssh_hosts = _ssh(data.get("ssh", {}))
    ceilings = Limits()
    limit_data = _object(data.get("limits", {}), {field.name for field in fields(Limits)}, "limits")
    limits = Limits(**{key: _integer(value, getattr(ceilings, key), key) for key, value in limit_data.items()})
    retention = _object(data.get("retention", {}), {"stale_after_days"}, "retention")
    stale_days = _integer(retention.get("stale_after_days", 14), 3650, "stale_after_days")
    render = _object(data.get("render", {}), {"include_addresses", "include_interfaces"}, "render")
    store = _object(data.get("store", {}), {"shared_sqlite_path"}, "store")
    home = home.resolve()
    database = home / "network-atlas" / "atlas.sqlite3"
    if "shared_sqlite_path" in store:
        path = store["shared_sqlite_path"]
        if not isinstance(path, str) or not 1 <= len(path) <= 4096 or any(ord(c) < 32 for c in path):
            raise ConfigError("invalid shared SQLite path")
        if not Path(path).is_absolute() or Path(path).suffix != ".sqlite3":
            raise ConfigError("shared SQLite path must be absolute and end in .sqlite3")
        database = Path(path).resolve()
    return Policy(home, database, networks, ssh_enabled, ssh_hosts, limits, stale_days,
                  _bool(render.get("include_addresses", True), "include_addresses"),
                  _bool(render.get("include_interfaces", False), "include_interfaces"))


def load_policy(home: Path) -> Policy:
    """Read only this profile's policy, bounded to 64 KiB; absent file means no permissions."""
    path = home / "network-atlas" / "config.yaml"
    try:
        with path.open("rb") as handle:
            content = handle.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError:
        return validate_policy({}, home)
    if len(content) > MAX_CONFIG_BYTES:
        raise ConfigError("configuration exceeds 64 KiB")
    try:
        parser = YAML(typ="safe", pure=True)
        parser.version = (1, 2)
        raw = parser.load(content)
    except (YAMLError, UnicodeError, RecursionError) as exc:
        raise ConfigError("invalid policy YAML") from exc
    return validate_policy(raw, home)
