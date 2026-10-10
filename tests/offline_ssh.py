#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic SSH executable for isolated native tests; never invokes OpenSSH/network."""
from pathlib import Path
import json
import os
import sys

root = Path(os.environ["NETWORK_ATLAS_OFFLINE_FIXTURE_DIR"]).resolve()
scratch = Path(os.environ["TMPDIR"]).resolve()
if not root.is_relative_to(scratch) or not (root / "offline-fixture").is_file():
    raise RuntimeError("synthetic scratch fixture marker required")
args = sys.argv[1:]
assert args[:4] == ["-T", "-n", "-a", "-x"], args
assert args[-2] == "lab-router", args
options = args[4:-2]
assert len(options) % 2 == 0 and options[::2] == ["-o"] * (len(options) // 2), args
expected = {"BatchMode=yes", "StrictHostKeyChecking=yes", "UpdateHostKeys=no", "VerifyHostKeyDNS=no",
            "NoHostAuthenticationForLocalhost=no", "KnownHostsCommand=none",
            "RequestTTY=no", "StdinNull=yes", "PermitLocalCommand=no", "LocalCommand=none",
            "ClearAllForwardings=yes", "ForwardAgent=no", "ForwardX11=no", "ForwardX11Trusted=no",
            "Tunnel=no", "ControlMaster=no", "ControlPath=none", "ControlPersist=no",
            "RemoteCommand=none", "SessionType=default", "ForkAfterAuthentication=no", "AddKeysToAgent=no",
            "ConnectionAttempts=1", "LogLevel=ERROR", "ConnectTimeout=10"}
assert len(options[1::2]) == len(expected) and set(options[1::2]) == expected, args
payloads = {"hostname": "fixture-ssh-host\n", "hostnamectl --static": "fixture-ssh-host\n",
            "cat /etc/os-release": 'PRETTY_NAME="Synthetic Fixture Linux"\nID=fixture\n',
            "ip -j address": json.dumps([{"ifname": "ssh0", "address": "00:11:22:33:44:77", "operstate": "UP",
                                         "addr_info": [{"local": "198.51.100.7", "prefixlen": 24}]}]),
            "ip -j link": json.dumps([{"ifname": "ssh0", "address": "00:11:22:33:44:77", "operstate": "UP"}]),
            "ip -j route": "[]", "ip -j neigh": '[{"dst":"198.51.100.20","lladdr":"00:11:22:33:44:99","state":["STALE"]}]'}
assert args[-1] in payloads, args
outcome = root / "ssh-outcome"
if outcome.is_file():
    # Deliberately synthetic client stderr. A refusal must not persist it.
    os.write(2, b"Synthetic host key refusal; SECRET_FIXTURE_DIAGNOSTIC\n")
    raise SystemExit(255)
sys.stdout.write(payloads[args[-1]])
