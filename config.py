# SPDX-License-Identifier: GPL-3.0-or-later
"""Atlas domain validation over native Hermes settings and profile storage."""
from __future__ import annotations

from dataclasses import dataclass, fields
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path
import re
from collections.abc import Mapping
from typing import Protocol

from .errors import RequestError

MAX_CONFIG_BYTES = 65536
MAX_POLICY_ENTRIES = 32
NAME_PATTERN = r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}"
LEGACY_TCP_PORTS = (80, 443)
MAX_TCP_DISCOVERY_PORTS = 4
MAX_TCP_ENDPOINT_PORTS = 32
EXCLUDED_TCP_PORTS = frozenset({4403})
MAX_UDP_ENDPOINT_PORTS = 32
EXCLUDED_UDP_PORTS = frozenset({7, 19, 4403})
LAN_SCOPES = tuple(IPv4Network(cidr) for cidr in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"))


class ConfigError(RequestError):
    """Returned Atlas settings are malformed; refuse the requested action."""

    def __init__(self, diagnostic: str):
        super().__init__("policy: " + diagnostic)


class ActiveScopeError(ConfigError):
    """Current named scope lacks its explicit non-LAN collection grant."""

    def __init__(self, network_name: str):
        super().__init__(
            f"networks.{network_name}.allow_public: active collection outside RFC1918/private or "
            "IPv4 link-local scopes requires explicit true for this network; "
            "check its cidr before opting in (IPv6 remains passive-only)")


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
    endpoint_ports: tuple[int, ...] = ()
    allow_public: bool = False
    endpoint_udp_ports: tuple[int, ...] = ()

    @property
    def endpoint_methods(self) -> tuple[tuple[str, int], ...]:
        """One protocol-sensitive selection for admission, scheduling and recovery."""
        return tuple(('tcp', port) for port in self.endpoint_ports) + tuple(
            ('udp', port) for port in self.endpoint_udp_ports)


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


def _name(value: object, label: str = "policy name") -> str:
    if not isinstance(value, str) or re.fullmatch(NAME_PATTERN, value) is None:
        raise ConfigError(
            f"{label}: use 1..64 letters, digits, underscores or hyphens, starting with a letter or digit")
    return value


def _entries(value: object, label: str) -> Mapping:
    if not isinstance(value, dict) or len(value) > MAX_POLICY_ENTRIES:
        raise ConfigError(f"{label} must be an object with at most {MAX_POLICY_ENTRIES} entries")
    for key in value:
        _name(key, label + ".name")
    return value


def _scope(cidr: object) -> IPv4Network | IPv6Network:
    """Canonical bounded scope shared by all configured discovery methods."""
    if not isinstance(cidr, str) or len(cidr) > 64:
        raise ConfigError("network.cidr: canonical CIDR text required")
    try:
        network = ip_network(cidr, strict=True)
    except ValueError as exc:
        raise ConfigError("network.cidr: use a canonical IP network with no host bits") from exc
    if str(network) != cidr:
        raise ConfigError("network.cidr: use canonical CIDR notation")
    if network.version == 4 and network.num_addresses > 256:
        raise ConfigError("network.cidr: IPv4 scope must contain at most 256 addresses")
    return network


def _tcp_ports(value: object, label: str = "network.discovery.tcp_ports", *,
               ceiling: int = MAX_TCP_DISCOVERY_PORTS) -> tuple[int, ...]:
    if type(value) is not list or len(value) > ceiling:
        raise ConfigError(f"{label}: list of at most {ceiling} ports required")
    ports = tuple(_integer(port, 65535, label) for port in value)
    if len(set(ports)) != len(ports) or EXCLUDED_TCP_PORTS.intersection(ports):
        raise ConfigError(f"{label}: ports must be distinct and must not include excluded port 4403")
    return tuple(sorted(ports))


def _endpoint_settings(raw: object) -> tuple[tuple[int, ...], tuple[int, ...]]:
    endpoints = _object(raw, {"enabled", "tcp_ports", "udp_ports"}, "network.endpoints")
    enabled = _bool(endpoints.get("enabled", False), "endpoints.enabled")
    tcp = _tcp_ports(endpoints.get("tcp_ports", []), "network.endpoints.tcp_ports", ceiling=MAX_TCP_ENDPOINT_PORTS)

    udp = endpoints.get("udp_ports", [])
    label = "network.endpoints.udp_ports"
    if type(udp) is not list or len(udp) > MAX_UDP_ENDPOINT_PORTS:
        raise ConfigError(f"{label}: list of at most 32 ports required")
    udp = tuple(_integer(port, 65535, label) for port in udp)
    if len(set(udp)) != len(udp) or EXCLUDED_UDP_PORTS.intersection(udp):
        raise ConfigError(f"{label}: ports must be distinct and must not include excluded ports 7, 19, 4403")
    if enabled and not (tcp or udp):
        raise ConfigError("network.endpoints: enabled requires nonempty tcp_ports or udp_ports")
    return (tcp, tuple(sorted(udp))) if enabled else ((), ())


def _network(name: str, raw: object) -> Network:
    data = _object(raw, {"cidr", "discovery", "endpoints", "allow_public"}, "network")
    network = _scope(data.get("cidr"))
    allow_public = _bool(data.get("allow_public", False), f"networks.{name}.allow_public")
    modes = _object(data.get("discovery", {}), {"passive", "ping", "icmp_echo", "tcp_ports"}, "network.discovery")
    passive = _bool(modes.get("passive", False), "network.discovery.passive")
    ping = _bool(modes.get("ping", False), "network.discovery.ping")
    icmp_echo = _bool(modes.get("icmp_echo", False), "network.discovery.icmp_echo")
    ports = _tcp_ports(modes.get("tcp_ports", list(LEGACY_TCP_PORTS)))
    if network.version == 6 and ping:
        raise ConfigError("network.discovery.ping: active discovery requires an IPv4 cidr")
    if icmp_echo and not ping:
        raise ConfigError("network.discovery.icmp_echo: requires ping authorization")
    if ping and not (icmp_echo or ports):
        raise ConfigError("network.discovery.ping: requires icmp_echo or nonempty tcp_ports")
    endpoint_ports, udp_ports = _endpoint_settings(data.get("endpoints", {}))
    if (endpoint_ports or udp_ports) and network.version != 4:
        raise ConfigError("network.endpoints: checks require an IPv4 cidr")
    return Network(name, str(network), passive, ping, icmp_echo, ports, endpoint_ports, allow_public, udp_ports)


def active_scope_allowed(network: Network) -> bool:
    """RFC1918/link-local only by default, not ipaddress's broader is_private.

    Apply only to current active authority, never to parsing passive policy or
    reading historical evidence. Public opt-in cannot enable IPv6 transport.
    """
    scope = ip_network(network.cidr)
    return isinstance(scope, IPv4Network) and (network.allow_public or any(
        scope.subnet_of(lan) for lan in LAN_SCOPES))


def validate_network(network: Network, *, active: bool = False) -> None:
    """Revalidate native snapshots before invocation, not just YAML at startup."""
    if type(network.tcp_ports) is not tuple or len(network.tcp_ports) > MAX_TCP_DISCOVERY_PORTS:
        raise ConfigError("invalid immutable TCP discovery ports")
    if type(network.endpoint_ports) is not tuple or type(network.endpoint_udp_ports) is not tuple:
        raise ConfigError("invalid immutable endpoint ports")
    _network(_name(network.name), {"cidr": network.cidr, "allow_public": network.allow_public,
        "endpoints": {"enabled": bool(network.endpoint_methods), "tcp_ports": list(network.endpoint_ports),
                      "udp_ports": list(network.endpoint_udp_ports)},
        "discovery": {
        "passive": network.passive, "ping": network.ping, "icmp_echo": network.icmp_echo,
        "tcp_ports": list(network.tcp_ports)}})
    if active and not active_scope_allowed(network):
        raise ActiveScopeError(network.name)


def _ssh(raw: object) -> tuple[bool, tuple[SSHHost, ...]]:
    data = _object(raw, {"enabled", "hosts"}, "ssh")
    enabled = _bool(data.get("enabled", False), "ssh.enabled")
    hosts = []
    for name, item in _entries(data.get("hosts", {}), "ssh.hosts").items():
        host = _object(item, {"alias", "inspect"}, "ssh.host")
        hosts.append(SSHHost(name, _name(host.get("alias"), "ssh.host.alias"),
                             _bool(host.get("inspect", False), "ssh.host.inspect")))
    if len({host.alias for host in hosts}) != len(hosts):
        raise ConfigError("ssh.host.alias: aliases must be distinct across ssh.hosts")
    return enabled, tuple(sorted(hosts, key=lambda host: host.name))


def validate_policy(raw: object, home: Path, *, data_dir: Path | None = None) -> Policy:
    """Validate policy with independent profile identity and managed storage location."""
    data = _object(raw, {"version", "networks", "ssh", "limits", "retention", "render", "store"}, "policy")
    if type(data.get("version", 1)) is not int or data.get("version", 1) != 1:
        raise ConfigError("unsupported configuration version")
    networks = tuple(_network(name, item) for name, item in sorted(
        _entries(data.get("networks", {}), "networks").items()))
    ssh_enabled, ssh_hosts = _ssh(data.get("ssh", {}))
    ceilings = Limits()
    limit_data = _object(data.get("limits", {}), {field.name for field in fields(Limits)}, "limits")
    limits = Limits(**{key: _integer(value, getattr(ceilings, key), "limits." + key)
                       for key, value in limit_data.items()})
    retention = _object(data.get("retention", {}), {"stale_after_days"}, "retention")
    stale_days = _integer(retention.get("stale_after_days", 14), 3650, "stale_after_days")
    render = _object(data.get("render", {}), {"include_addresses", "include_interfaces"}, "render")
    store = _object(data.get("store", {}), {"shared_sqlite_path"}, "store")
    home = home.resolve()
    database = (home / "plugin-data" / "network-atlas" if data_dir is None else data_dir) / "atlas.sqlite3"
    if "shared_sqlite_path" in store:
        path = store["shared_sqlite_path"]
        if not isinstance(path, str) or not 1 <= len(path) <= 4096 or any(ord(c) < 32 for c in path):
            raise ConfigError(
                "store.shared_sqlite_path: nonempty bounded path text without control characters required")
        if not Path(path).is_absolute() or Path(path).suffix != ".sqlite3":
            raise ConfigError("store.shared_sqlite_path: path must be absolute and end in .sqlite3")
        database = Path(path).resolve()
    return Policy(home, database, networks, ssh_enabled, ssh_hosts, limits, stale_days,
                  _bool(render.get("include_addresses", True), "include_addresses"),
                  _bool(render.get("include_interfaces", False), "include_interfaces"))


class Settings(Protocol):
    """The supported plugin-relative settings boundary supplied by Hermes."""

    def get_config(self, key: str, default: object = None) -> object: ...


def load_policy(ctx: Settings) -> Policy:
    """Resolve native settings and current profile storage for this invocation.

    Hermes owns config caching, fallback and managed-worker snapshots. Its public
    storage helper creates the directory, not an Atlas database or collection.
    Profile identity follows the native home resolver, never the storage target:
    plugin-data or its Atlas subdirectory may be symlinked to another disk.
    """
    from hermes_constants import get_hermes_home
    from plugins.plugin_storage import plugin_data_dir

    raw = ctx.get_config("policy", {})
    data = plugin_data_dir("network-atlas").resolve()
    policy = validate_policy(raw, get_hermes_home(), data_dir=data)
    legacy = policy.home / "network-atlas" / "atlas.sqlite3"
    if not (legacy.exists() or legacy.is_symlink()):
        return policy
    if isinstance(raw, dict) and "shared_sqlite_path" in raw.get("store", {}):
        from .conversion import read_legacy

        # Conversion retains legacy files. Block guessed recovery destinations,
        # not a deliberate distinct new store or its intentional empty reset.
        # Resolve full file identities, including managed file symlinks, without
        # importing legacy grants into runtime policy.
        if not policy.database.is_file() and (
                policy.database == (data / "atlas.sqlite3").resolve() or
                policy.database == validate_policy(
                    read_legacy(policy.home), policy.home, data_dir=data).database.resolve()):
            raise ConfigError(
                "legacy store present but selected store is absent or not a regular file; stop writers. "
                "Do not create an empty replacement. Establish first migration versus converted-profile "
                "recovery in docs/operator-guide.md#recover-the-selected-binding; preserve originals and backups. "
                "Only after independently confirming first migration and that the guessed selected file remains "
                "absent, preserve native config and clear the policy with the replacing native config CLI as in "
                "docs/operator-guide.md#clear-an-absent-guessed-binding-before-first-migration, "
                "then explicitly accept conversion. Never clear a binding to existing data")
        return policy
    destination = ("managed destination exists but does not prove conversion or the intended inventory. "
                   if policy.database.is_file() else
                   "managed destination is absent; this can mean first migration or deleted converted data. ")
    raise ConfigError(
        "legacy store present without a native store binding; stop writers. " + destination +
        "Only an independently confirmed first migration should follow "
        "docs/operator-guide.md#convert-legacy-policy-and-storage. For an already-converted profile, "
        "use binding-only recovery only after verifying the actual retained store and expected history in "
        "docs/operator-guide.md#recover-the-selected-binding. If history is uncertain or data is missing, "
        "stop and inspect private records/backups; do not select an empty replacement. "
        "Conversion may restore revoked collection grants")
