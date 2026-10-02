#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prove socket refusal in Python and an exec child without sending any packet."""
import errno
import os
from pathlib import Path
import socket
import subprocess
import sys

from offline_guard import deny_network


def refused() -> None:
    try:
        channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        assert exc.errno == errno.EPERM, exc
        return
    channel.close()
    raise AssertionError("socket syscall was not denied")


def main() -> int:
    if sys.argv[1:] == ["child"]:
        refused()
        return 0
    deny_network()
    refused()
    child = subprocess.run([sys.executable, str(Path(__file__).resolve()), "child"],
                           env={"PATH": "/usr/bin:/bin", "HOME": os.environ["TMPDIR"]},
                           capture_output=True, text=True, timeout=10)
    assert child.returncode == 0, child.stdout + child.stderr
    print("socket syscall denied in parent and exec child")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
