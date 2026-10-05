# SPDX-License-Identifier: GPL-3.0-or-later
"""Staged host-discovery boundary and packet-free Linux echo-datagram diagnosis.

No helper or raw-socket fallback. Opening a socket is not proof of transport,
reachability or authority; future collection must still enforce current policy.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import errno
import math
import socket
import sys
import time

from .config import Network, validate_network


class TransportStaged(ValueError):
    """Selected policy is valid but its transport is not implemented at this stage."""


@dataclass(frozen=True)
class ICMPCapability:
    """Bounded diagnostic only, never a cached permission or reachability grant."""

    state: str
    diagnostic_code: str


def _socket_failure(error: OSError) -> ICMPCapability:
    if error.errno in {errno.EPERM, errno.EACCES}:
        code = "icmp_permission_denied"
    elif error.errno in {errno.EPROTONOSUPPORT, errno.EAFNOSUPPORT, errno.ESOCKTNOSUPPORT, errno.ENOSYS}:
        code = "icmp_protocol_unsupported"
    else:
        code = "icmp_socket_open_failed"
    return ICMPCapability("unavailable", code)


def icmp_capability(network: Network, deadline: float, *, platform: str | None = None,
                    socket_factory: Callable[..., socket.socket] | None = None) -> ICMPCapability:
    """Open/close one echo datagram without bind/connect/send/receive or DNS.

    Disabled, expired and unsupported-platform checks open nothing. A successful
    open is explicitly unverified: runtime sends/routing/replies may still fail.
    The monotonic deadline is shared with collection; no independent retry budget.
    OS failures retain no raw error text. Interruption propagates after owned
    socket cleanup. Dependencies are injectable for packet-free tests only, not
    exposed through any plugin surface. Never executes an external program.
    """
    validate_network(network)
    if not network.ping or not network.icmp_echo:
        return ICMPCapability("disabled", "icmp_disabled")
    if not math.isfinite(deadline):
        raise ValueError("finite shared capability deadline required")
    if time.monotonic() >= deadline:
        return ICMPCapability("not_started", "operation_deadline_exceeded")
    if (sys.platform if platform is None else platform) != "linux":
        return ICMPCapability("unavailable", "icmp_platform_unsupported")
    factory = socket.socket if socket_factory is None else socket_factory
    try:
        with factory(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP):
            pass
    except OSError as error:
        return _socket_failure(error)
    return ICMPCapability("unverified", "icmp_socket_opened_transport_unverified")
