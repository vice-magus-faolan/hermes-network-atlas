# SPDX-License-Identifier: GPL-3.0-or-later
"""Owned nonblocking host-only sockets; no raw sockets, payloads or helper fallback."""
from __future__ import annotations

from dataclasses import dataclass
import errno
from ipaddress import ip_address, ip_network
import math
import selectors
import socket
import struct
import sys
import time

from .config import EXCLUDED_TCP_PORTS, Network, validate_network

Outcome = tuple[str, str, bool]


@dataclass
class Attempt:
    """One socket owned until completion/cancellation; deadline never renews."""
    sock: socket.socket
    address: str
    port: int | None
    deadline: float
    identifier: int = 0
    sequence: int = 1


def checksum(packet: bytes) -> int:
    """Internet checksum, including the odd trailing byte if present."""
    data = packet + b'\0' if len(packet) % 2 else packet
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    total = (total & 65535) + (total >> 16)
    total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def excluded(network: Network, address: str) -> bool:
    """Reject nonnumeric/out-of-scope and special destinations before any socket."""
    scope, target = ip_network(network.cidr), ip_address(address)
    if str(target) != address or target.version != 4 or target not in scope:
        raise ValueError('numeric authorized IPv4 destination required')
    return (target.is_multicast or target.is_unspecified or target.is_loopback
            or target.is_reserved or target == scope.broadcast_address and scope.prefixlen < 31
            or target == scope.network_address and scope.prefixlen < 31)


def _error(error: OSError) -> tuple[str, str, bool]:
    if error.errno in {errno.EPERM, errno.EACCES}:
        return 'unavailable', 'transport_permission_denied', False
    if error.errno in {errno.EPROTONOSUPPORT, errno.EAFNOSUPPORT, errno.ESOCKTNOSUPPORT}:
        return 'unavailable', 'transport_protocol_unsupported', False
    return 'unavailable', 'transport_socket_failed', False


def _tcp_result(code: int) -> tuple[str, str, bool]:
    """Only connect/SO_ERROR results qualify; local socket-setup failures do not."""
    if code == 0:
        return 'success', 'tcp_connected_response', True
    if code == errno.ECONNREFUSED:
        return 'success', 'tcp_refused_response', True
    return _error(OSError(code, ''))


def begin(network: Network, address: str, port: int | None, deadline: float) -> tuple[Attempt | None, Outcome | None]:
    """Start at most one fixed connect/8-byte echo; return owned attempt or outcome.

    Revalidate native inputs, including sensitive exclusions, before opening and
    recheck the shared effective deadline immediately before network effects.
    Linux assigns the echo identifier to the bound datagram socket's local port.
    """
    validate_network(network)
    if not network.ping or excluded(network, address):
        raise ValueError('excluded or unauthorized destination')
    if port is None:
        if not network.icmp_echo:
            raise ValueError('ICMP not authorized')
    elif type(port) is not int or port not in network.tcp_ports or port in EXCLUDED_TCP_PORTS:
        raise ValueError('TCP port not authorized')
    if not math.isfinite(deadline):
        raise ValueError('finite effective deadline required')
    if time.monotonic() >= deadline:
        return None, ('not_started', 'effective_deadline_before_start', False)
    if port is None and sys.platform != 'linux':
        return None, ('unavailable', 'icmp_platform_unsupported', False)
    return _open(address, port, deadline)


def _open(address: str, port: int | None, deadline: float) -> tuple[Attempt | None, Outcome | None]:
    sock = None
    try:
        kind, protocol = (socket.SOCK_STREAM, socket.IPPROTO_TCP) if port is not None else (socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        sock = socket.socket(socket.AF_INET, kind, protocol)
        sock.setblocking(False)
        attempt = Attempt(sock, address, port, deadline)
        result = _initiate(attempt)
        if result is not None:
            sock.close()
            return None, result
        return attempt, None
    except BaseException as error:
        if sock is not None:
            sock.close()
        if isinstance(error, OSError):
            return None, _error(error)
        raise


def _initiate(attempt: Attempt) -> Outcome | None:
    if attempt.port is None:
        attempt.sock.bind(('0.0.0.0', 0))
        attempt.identifier = attempt.sock.getsockname()[1]
    if time.monotonic() >= attempt.deadline:
        return 'not_started', 'effective_deadline_before_start', False
    if attempt.port is not None:
        code = attempt.sock.connect_ex((attempt.address, attempt.port))
        if code == 0:
            return 'success', 'tcp_connected_response', True
        if code not in {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EINTR}:
            return _tcp_result(code)
    else:
        header = struct.pack('!BBHHH', 8, 0, 0, attempt.identifier, attempt.sequence)
        header = struct.pack('!BBHHH', 8, 0, checksum(header), attempt.identifier, attempt.sequence)
        if attempt.sock.sendto(header, (attempt.address, 0)) != 8:
            return 'command_failed', 'icmp_short_send', False
    return None


def ready(attempt: Attempt, remaining_bytes: int) -> tuple[Outcome | None, int]:
    """Validate a bounded matching response; return outcome (or pending), bytes read."""
    try:
        if attempt.port is not None:
            code = attempt.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            return _tcp_result(code), 0
        packet, source = attempt.sock.recvfrom(min(65536, remaining_bytes + 1))
        if len(packet) > remaining_bytes:
            return ('output_limit', 'shared_receive_limit', False), len(packet)
        if _reply(attempt, packet, source):
            return ('success', 'icmp_echo_response', True), len(packet)
        return None, len(packet)
    except BlockingIOError:
        return None, 0
    except OSError as error:
        return _error(error), 0


def _reply(attempt: Attempt, packet: bytes, source: tuple) -> bool:
    if len(packet) != 8 or source[0] != attempt.address or checksum(packet) != 0:
        return False
    kind, code, _, identifier, sequence = struct.unpack('!BBHHH', packet)
    return (kind, code, identifier, sequence) == (0, 0, attempt.identifier, attempt.sequence)


def event_mask(port: int | None) -> int:
    return selectors.EVENT_WRITE if port is not None else selectors.EVENT_READ
