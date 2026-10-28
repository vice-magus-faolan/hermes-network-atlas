#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic ip/Nmap/SSH transports; fixed data, exact argv, no real network path."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

MACS = {"lab-a": "00:11:22:33:44:11", "lab-b": "00:11:22:33:44:22", "lab-c": "00:11:22:33:44:33"}


def nmap(args: list[str], stage: str) -> str:
    base = ["-sn", "-n", "-PS80,443", "-v", "--host-timeout", "10s", "--max-parallelism", "4",
            "--max-rate", "32", "-oX", "-"]
    if args[-1] == "192.0.2.2/31":
        assert args[:-1] == base
        return ('<nmaprun><host><status state="down" reason="no-response"/>'
                '<address addr="192.0.2.2" addrtype="ipv4"/></host>'
                '<host><status state="down" reason="no-response"/>'
                '<address addr="192.0.2.3" addrtype="ipv4"/></host>'
                '<runstats><finished exit="success"/><hosts up="0" down="2" total="2"/></runstats></nmaprun>')
    assert args[:-1] == [*base, "--exclude", "192.0.2.0,192.0.2.7"]
    assert args[-1] == "192.0.2.0/29"
    records = {1: MACS["lab-a"], 2: MACS["lab-b"], 3: MACS["lab-c"], 4: None, 5: "00:11:22:33:44:55"}
    if stage == "changed":
        records = {2: "00:11:22:33:44:66", 4: None, 6: MACS["lab-a"]}
    hosts = []
    for number, mac in sorted(records.items()):
        host = f'<host><status state="up"/><address addr="192.0.2.{number}" addrtype="ipv4"/>'
        if mac:
            host += f'<address addr="{mac}" addrtype="mac"/>'
        hosts.append(host + "</host>")
    hosts.extend('<host><status state="down" reason="no-response"/>'
                 f'<address addr="192.0.2.{number}" addrtype="ipv4"/></host>'
                 for number in range(1, 7) if number not in records)
    return ('<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun>' + ''.join(hosts) +
            f'<runstats><finished exit="success"/><hosts up="{len(records)}" down="{6 - len(records)}" '
            'total="6"/></runstats></nmaprun>')


def ssh(args: list[str], stage: str) -> str:
    assert args[:4] == ["-T", "-n", "-a", "-x"]
    alias, command = args[-2:]
    assert alias in MACS
    options = args[4:-2]
    assert options[::2] == ["-o"] * (len(options) // 2)
    expected = {"BatchMode=yes", "StrictHostKeyChecking=yes", "UpdateHostKeys=no", "VerifyHostKeyDNS=no",
                "NoHostAuthenticationForLocalhost=no", "KnownHostsCommand=none",
                "RequestTTY=no", "StdinNull=yes", "PermitLocalCommand=no", "LocalCommand=none",
                "ClearAllForwardings=yes", "ForwardAgent=no", "ForwardX11=no", "ForwardX11Trusted=no",
                "Tunnel=no", "ControlMaster=no", "ControlPath=none", "ControlPersist=no",
                "RemoteCommand=none", "SessionType=default", "ForkAfterAuthentication=no", "AddKeysToAgent=no",
                "ConnectionAttempts=1", "LogLevel=ERROR", "ConnectTimeout=10"}
    assert len(options[1::2]) == len(expected) and set(options[1::2]) == expected
    if stage == "refused":
        os.write(2, b"Synthetic host-key refusal SECRET_FIXTURE_DIAGNOSTIC\n")
        raise SystemExit(255)
    number = {"lab-a": 1, "lab-b": 2, "lab-c": 3}[alias]
    interface = {"ifname": "eth0", "address": MACS[alias], "operstate": "UP",
                 "addr_info": [{"local": f"192.0.2.{number}", "prefixlen": 29}]}
    hostname = "lab-b" if stage == "duplicate" and alias == "lab-c" else alias
    payloads = {"hostname": hostname + "\n", "hostnamectl --static": hostname + "\n",
                "cat /etc/os-release": 'PRETTY_NAME="Fixture Linux $(do-not-execute)"\nID=fixture\n',
                "ip -j address": json.dumps([interface]), "ip -j link": json.dumps([interface]),
                "ip -j route": "[]",
                "ip -j neigh": '[{"dst":"198.51.100.99","lladdr":"00:11:22:33:44:99","state":["STALE"]}]'}
    if stage == "collision":
        interfaces = [interface, {**interface, "ifname": "duplicate0"}]
        payloads["ip -j address"] = payloads["ip -j link"] = json.dumps(interfaces)
    if stage == "uncertainty":
        interfaces = [interface]
        interfaces += [{"ifname": f"veth{n:03}", "address": f"02:00:00:00:00:{n:02x}", "operstate": "UP",
                        "addr_info": [{"local": f"198.18.0.{n + 1}", "prefixlen": 24}]} for n in range(40)]
        interfaces.append({"ifname": "collision0", "address": MACS["lab-b"], "operstate": "UP", "addr_info": []})
        payloads["ip -j address"] = json.dumps(interfaces)
        payloads["ip -j link"] = json.dumps([{key: value for key, value in row.items() if key != "addr_info"}
                                            for row in interfaces])
        payloads["ip -j route"] = json.dumps([
            {"dst": "default", "gateway": "198.51.100.254", "dev": "eth0"},
            {"dst": "203.0.113.0/24", "gateway": "198.51.100.253", "dev": "eth0", "table": 100}])
        payloads["ip -j neigh"] = json.dumps([{"dst": "198.51.100.254", "dev": "eth0",
                                               "lladdr": "00:11:22:33:44:99", "state": ["REACHABLE"]}])
    assert command in payloads
    return payloads[command]


def main() -> int:
    root = Path(os.environ["NETWORK_ATLAS_OFFLINE_FIXTURE_DIR"]).resolve()
    scratch = Path(os.environ["TMPDIR"]).resolve()
    if not root.is_relative_to(scratch) or not (root / "offline-fixture").is_file():
        raise RuntimeError("synthetic scratch fixture required")
    stage = (root / "stage").read_text().strip()
    binary, args = Path(sys.argv[0]).name, sys.argv[1:]
    assert stage in {"baseline", "changed", "refused", "duplicate", "uncertainty", "collision"}
    fd = os.open(root / "calls.jsonl", os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(fd, (json.dumps({"binary": binary, "args": args, "stage": stage}) + "\n").encode())
    finally:
        os.close(fd)
    if binary == "nmap":
        print(nmap(args, stage))
    elif binary == "ssh":
        sys.stdout.write(ssh(args, stage))
    elif binary == "ip":
        assert args in (["-j", "addr"], ["-j", "route"], ["-j", "neigh"])
        print("[]")
    else:
        raise ValueError("unknown synthetic transport")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
