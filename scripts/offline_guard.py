# SPDX-License-Identifier: GPL-3.0-or-later
"""Test-only Linux x86_64 inherited socket denial, including native subprocesses."""
from __future__ import annotations

import ctypes
import errno
import platform
import sys


def deny_network() -> None:
    """Fail rather than silently weaken the offline acceptance boundary.

    Canonical tests run in a separate process from online prerequisite setup.
    No inherited sockets are supplied to fixture subprocesses. This is a test
    guard, not a production plugin sandbox or protection from privileged code.
    """
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise RuntimeError("offline acceptance requires Linux x86_64 seccomp")
    class Filter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                    ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]
    # Verify architecture; kill x32/compat syscalls rather than leaving another
    # socket ABI open. fork/exec descendants inherit the non-removable filter.
    rules = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E), (0x06, 0, 0, 0x80000000),
             (0x20, 0, 0, 0), (0x35, 0, 1, 0x40000000), (0x06, 0, 0, 0x80000000)]
    for syscall in (41, 42, 49):
        rules.extend([(0x15, 0, 1, syscall), (0x06, 0, 0, 0x00050000 | errno.EPERM)])
    rules.append((0x06, 0, 0, 0x7FFF0000))
    array = (Filter * len(rules))(*(Filter(*row) for row in rules))
    program = Program(len(rules), array)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        raise OSError(ctypes.get_errno(), "cannot enforce offline seccomp")
    def audit(event: str, args: tuple) -> None:
        if event in {"socket.connect", "socket.getaddrinfo", "socket.bind"}:
            raise RuntimeError("fixture acceptance must remain network-free")
    sys.addaudithook(audit)
