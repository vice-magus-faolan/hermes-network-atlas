# SPDX-License-Identifier: GPL-3.0-or-later
"""Non-forwarding echo/TCP fixtures. No real socket or child is ever constructed."""
from __future__ import annotations

from contextlib import ExitStack
import errno
from ipaddress import ip_address
import selectors
import socket
import struct
import time
from types import SimpleNamespace
from unittest.mock import patch


class Clock:
    def __init__(self):
        self.now = time.monotonic()

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        assert seconds >= 0
        self.now += seconds


class SyntheticSockets:
    """Fixed numeric decisions supplied by tests, not a forwarding fallback."""
    def __init__(self, response=None, *, icmp_error=None):
        self.clock = Clock()
        self.response = response or (lambda address, port: 'positive')
        self.icmp_error = icmp_error
        self.sockets = []
        self.calls = []
        self.peak = 0

    def factory(self, family, kind, protocol):
        assert family == socket.AF_INET
        assert (kind, protocol) in {(socket.SOCK_STREAM, socket.IPPROTO_TCP), (socket.SOCK_DGRAM, socket.IPPROTO_ICMP)}
        if protocol == socket.IPPROTO_ICMP and self.icmp_error is not None:
            raise OSError(self.icmp_error, 'synthetic private diagnostic')
        sock = SyntheticSocket(self, protocol)
        self.sockets.append(sock)
        return sock

    def install(self, schedule, transport, capability):
        stack = ExitStack()
        stack.enter_context(patch.object(transport.socket, 'socket', self.factory))
        stack.enter_context(patch.object(schedule.selectors, 'DefaultSelector', lambda: SyntheticSelector(self)))
        for module in (schedule, transport, capability):
            stack.enter_context(patch.object(module, 'time', self.clock))
        return stack


class SyntheticSocket:
    def __init__(self, fixture, protocol):
        self.fixture, self.protocol = fixture, protocol
        self.closed, self.address, self.port = False, None, None
        self.packet = None
        self.state = None
        self.number = 1000 + len(fixture.sockets)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        self.closed = True

    def setblocking(self, value):
        assert value is False

    def bind(self, target):
        assert self.protocol == socket.IPPROTO_ICMP and target == ('0.0.0.0', 0)

    def getsockname(self):
        return ('0.0.0.0', self.number)

    def _start(self, address, port):
        assert str(ip_address(address)) == address
        assert port != 4403
        self.address, self.port = address, port
        self.state = self.fixture.response(address, port)
        self.fixture.calls.append((self.fixture.clock.now, address, port))
        self.fixture.peak = max(self.fixture.peak, sum(s.address is not None and not s.closed for s in self.fixture.sockets))

    def connect_ex(self, target):
        assert self.protocol == socket.IPPROTO_TCP
        self._start(*target)
        return errno.EINPROGRESS

    def getsockopt(self, level, option):
        assert (level, option) == (socket.SOL_SOCKET, socket.SO_ERROR)
        return 0 if self.state == 'positive' else errno.ECONNREFUSED

    def sendto(self, packet, target):
        assert self.protocol == socket.IPPROTO_ICMP and len(packet) == 8 and target[1] == 0
        kind, code, _, identifier, sequence = struct.unpack('!BBHHH', packet)
        assert (kind, code, identifier, sequence) == (8, 0, self.number, 1)
        self.packet = packet
        self._start(target[0], None)
        return 8

    def recvfrom(self, maximum):
        from_checksum = lambda data: (~sum(struct.unpack('!4H', data))) & 65535
        packet = struct.pack('!BBHHH', 0, 0, 0, self.number, 1)
        packet = struct.pack('!BBHHH', 0, 0, from_checksum(packet), self.number, 1)
        if self.state == 'hostile':
            packet = b'hostile' * 100
        return packet[:maximum], (self.address, 0)


class SyntheticSelector:
    def __init__(self, fixture):
        self.fixture, self.registered = fixture, {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.registered.clear()

    def register(self, sock, mask):
        assert mask == (selectors.EVENT_READ if sock.port is None else selectors.EVENT_WRITE)
        self.registered[sock] = mask

    def unregister(self, sock):
        del self.registered[sock]

    def select(self, timeout):
        assert timeout >= 0
        ready = [(SimpleNamespace(fileobj=sock), mask) for sock, mask in self.registered.items()
                 if sock.state != 'filtered']
        self.fixture.clock.sleep(min(timeout, 0.001) if ready else timeout)
        return ready
