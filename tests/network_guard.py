# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable in-process network tripwire; Docker isolates executable children."""
import sys


def _refuse_network(event: str, args: tuple) -> None:
    if event in {"socket.connect", "socket.getaddrinfo", "socket.bind"}:
        raise RuntimeError("Atlas tests use synthetic transports only")


def deny_network() -> None:
    """Refuse Python connection/DNS/bind attempts, without architecture predicates."""
    sys.addaudithook(_refuse_network)
