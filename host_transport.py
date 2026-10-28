# SPDX-License-Identifier: GPL-3.0-or-later
"""Owned nonblocking sockets; fixed empty UDP/ICMP header, no arbitrary payloads."""
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

from .config import EXCLUDED_TCP_PORTS, EXCLUDED_UDP_PORTS, Network, validate_network

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
    protocol: str = 'tcp'
    nonempty_reply: bool = False


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
    if code == errno.ETIMEDOUT:
        return 'timeout', 'effective_transport_deadline', False
    if code == errno.EHOSTUNREACH:
        return 'timeout', 'tcp_host_unreachable', False
    return _error(OSError(code, ''))


def begin_endpoint(network: Network, address: str, port: int | None,
                   deadline: float, *, protocol: str = 'tcp') -> tuple[Attempt | None, Outcome | None]:
    """Separate endpoint grant, checked at the actual socket-effect boundary."""
    validate_network(network, active=True)
    forbidden = EXCLUDED_UDP_PORTS if protocol == 'udp' else EXCLUDED_TCP_PORTS
    if (excluded(network, address) or type(port) is not int
            or (protocol, port) not in network.endpoint_methods or port in forbidden):
        raise ValueError('endpoint destination/port not authorized')
    if not math.isfinite(deadline):
        raise ValueError('finite endpoint deadline required')
    if time.monotonic() >= deadline:
        return None, ('not_started', 'effective_deadline_before_start', False)
    return _open_udp(address, port, deadline) if protocol == 'udp' else _open(address, port, deadline)


def _open_udp(address: str, port: int, deadline: float) -> tuple[Attempt | None, Outcome | None]:
    """One empty unicast datagram; local connect/send success is never evidence.

    No SO_REUSEADDR, broadcast, raw ICMP, error queue or application payload.
    Each connected socket owns a fresh ephemeral tuple until its deadline.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setblocking(False)
        if time.monotonic() >= deadline:
            sock.close()
            return None, ('not_started', 'effective_deadline_before_start', False)
        code = sock.connect_ex((address, port))
        if code:
            raise OSError(code, '')
        if time.monotonic() >= deadline:
            sock.close()
            return None, ('not_started', 'effective_deadline_before_start', False)
        if sock.send(b'') != 0:
            raise OSError(errno.EIO, '')
        return Attempt(sock, address, port, deadline, protocol='udp'), None
    except BaseException as error:
        if sock is not None:
            sock.close()
        if isinstance(error, OSError):
            return None, _error(error)
        raise


def expired(attempt: Attempt) -> Outcome:
    """Retain only bounded exact-peer response evidence, never packet contents."""
    code = 'udp_nonempty_reply_inconclusive' if attempt.nonempty_reply else 'effective_transport_deadline'
    return 'timeout', code, False


def _udp_ready(attempt: Attempt, remaining_bytes: int) -> tuple[Outcome | None, int]:
    """Validate the empty-reply method, not a QUIC/application service identity."""
    if time.monotonic() >= attempt.deadline:
        return expired(attempt), 0
    try:
        packet, source = attempt.sock.recvfrom(min(65536, remaining_bytes + 1))
        if len(packet) > remaining_bytes:
            return ('output_limit', 'shared_receive_limit', False), len(packet)
        if time.monotonic() >= attempt.deadline:
            return expired(attempt), len(packet)
        if source == (attempt.address, attempt.port):
            if packet == b'':
                return ('success', 'udp_empty_reply', True), 0
            attempt.nonempty_reply = True
        return None, len(packet)
    except BlockingIOError:
        return None, 0
    except OSError as error:
        if time.monotonic() >= attempt.deadline:
            return expired(attempt), 0
        if error.errno == errno.ECONNREFUSED:
            return ('success', 'udp_kernel_rejected', True), 0
        if error.errno in {errno.EHOSTUNREACH, errno.ENETUNREACH}:
            return ('timeout', 'udp_host_unreachable', False), 0
        outcome, diagnostic, qualified = _error(error)
        return (outcome, 'udp_receive_' + diagnostic, qualified), 0


def begin(network: Network, address: str, port: int | None, deadline: float) -> tuple[Attempt | None, Outcome | None]:
    """Start at most one fixed connect/8-byte echo; return owned attempt or outcome.

    Revalidate native inputs, including sensitive exclusions, before opening and
    recheck the shared effective deadline immediately before network effects.
    Linux assigns the echo identifier to the bound datagram socket's local port.
    """
    validate_network(network, active=True)
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
        kind, protocol = ((socket.SOCK_STREAM, socket.IPPROTO_TCP) if port is not None
                          else (socket.SOCK_DGRAM, socket.IPPROTO_ICMP))
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
    if attempt.protocol == 'udp':
        return _udp_ready(attempt, remaining_bytes)
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


def event_mask(port: int | None, protocol: str = 'tcp') -> int:
    return selectors.EVENT_WRITE if port is not None and protocol == 'tcp' else selectors.EVENT_READ
