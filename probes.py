# SPDX-License-Identifier: GPL-3.0-or-later
"""POSIX owned-child runner with bounded combined output and wall-clock deadlines.

Only trusted collector code constructs argv. This is not a registered command
surface. Each child gets its own process group, null stdin, and no shell. Group
cleanup runs even on successful exit or interruption; no other group is signalled.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import selectors
import signal
import subprocess
import time

from .config import Limits


@dataclass(frozen=True)
class CommandResult:
    """Bounded bytes for immediate parsing; diagnostics never persist raw output."""
    outcome: str
    stdout: bytes = b""
    diagnostic_code: str = "ok"


def _cleanup(child: subprocess.Popen) -> None:
    assert child.stdout is not None and child.stderr is not None
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        child.wait()
        child.stdout.close()
        child.stderr.close()


def _exit_info(child: subprocess.Popen):
    # WNOWAIT reserves the leader PID until group cleanup. Reaping/polling first
    # could let a reused PID refer to an unrelated process group at killpg time.
    return os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)


def _read(child: subprocess.Popen, limits: Limits, deadline: float) -> CommandResult:
    assert child.stdout is not None and child.stderr is not None
    output = bytearray()
    total = 0
    with selectors.DefaultSelector() as selector:
        for stream in (child.stdout, child.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map() or _exit_info(child) is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return CommandResult("timeout", diagnostic_code="deadline_exceeded")
            for key, _ in selector.select(min(remaining, 0.05)):
                data = os.read(key.fd, min(65536, limits.output_bytes - total + 1))
                total += len(data)
                if total > limits.output_bytes:
                    return CommandResult("output_limit", diagnostic_code="combined_output_exceeded")
                if not data:
                    selector.unregister(key.fileobj)
                elif key.fileobj is child.stdout:
                    output.extend(data)
    info = _exit_info(child)
    if info is None or info.si_code != os.CLD_EXITED or info.si_status != 0:
        return CommandResult("command_failed", diagnostic_code="nonzero_exit")
    return CommandResult("success", bytes(output))


def run(argv: tuple[str, ...], limits: Limits, operation_deadline: float, *, host: bool = False) -> CommandResult:
    """Stream combined stdout/stderr; kill and reap the owned child on every exit.

    Per-host invocations are bounded independently of a tool's own timeout flags.
    The collector passes one shared monotonic whole-operation deadline.
    """
    duration = min(limits.command_timeout_seconds, limits.host_timeout_seconds) if host else limits.command_timeout_seconds
    deadline = min(operation_deadline, time.monotonic() + duration)
    if time.monotonic() >= deadline:
        return CommandResult("not_started", diagnostic_code="operation_deadline_exceeded")
    if os.name != "posix" or not hasattr(os, "WNOWAIT"):
        return CommandResult("unavailable", diagnostic_code="posix_runner_required")
    try:
        if time.monotonic() >= deadline:
            return CommandResult("not_started", diagnostic_code="operation_deadline_exceeded")
        child = subprocess.Popen(argv, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True, close_fds=True)
    except FileNotFoundError:
        return CommandResult("unavailable", diagnostic_code="executable_missing")
    except OSError:
        return CommandResult("command_failed", diagnostic_code="spawn_failed")
    try:
        return _read(child, limits, deadline)
    finally:
        _cleanup(child)
