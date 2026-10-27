#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline-only native transport fixture; cannot forward commands to real tools."""
from pathlib import Path
import json
import os
import sys
import time

root = Path(os.environ["NETWORK_ATLAS_OFFLINE_FIXTURE_DIR"]).resolve()
if not (root / "offline-fixture").is_file():
    raise RuntimeError("synthetic scratch fixture marker required")
mode = sys.argv[1:]
if mode == ["-j", "addr"]:
    print(json.dumps([{"ifname": "fixture0", "address": "00:11:22:33:44:55", "operstate": "UP",
                       "addr_info": [{"local": "192.0.2.1", "prefixlen": 24}]}]))
elif mode == ["-j", "route"]:
    print(json.dumps([{"dst": "default", "gateway": "192.0.2.254", "dev": "fixture0"}]))
elif mode == ["-j", "neigh"]:
    print(json.dumps([{"dst": "192.0.2.10", "lladdr": "00:11:22:33:44:66", "state": ["STALE"]}]))
elif mode == ["sleep"]:
    time.sleep(30)
elif mode == ["flood"]:
    while True:
        os.write(2, b"x" * 4096)
elif mode in (["fork"], ["fork_exit"]):
    child = os.fork()
    if child == 0:
        if mode == ["fork_exit"]:
            os.close(1)
            os.close(2)
        time.sleep(30)
        os._exit(0)
    (root / "owned-pids.json").write_text(json.dumps([os.getpid(), child]))
    print(str(os.getpid()) + " " + str(child), flush=True)
    if mode == ["fork"]:
        time.sleep(30)
elif mode == ["echo"]:
    os.write(1, b"safe-output")
    os.write(2, b"warning")
elif mode and mode[0] == "nmap-fixture":
    # Nmap -v emits down-host reasons; without it only the summary survives.
    from ipaddress import ip_network
    from xml.etree import ElementTree

    result = os.environ["NETWORK_ATLAS_OFFLINE_NMAP_RESULT"]
    excluded = set(mode[mode.index("--exclude") + 1].split(",")) if "--exclude" in mode else set()
    targets = [str(ip) for ip in ip_network(mode[-1]) if str(ip) not in excluded]
    if result == "no-targets":
        targets = []  # privileged route lookup can skip targets before discovery
    xml = ElementTree.Element("nmaprun")
    positives = (set(targets) if result == "positive" else
                 {"192.0.2.1", "192.0.2.2"} if result.startswith("mixed") else set())
    for address in targets:
        positive = address in positives
        if positive or "-v" in mode:
            host = ElementTree.SubElement(xml, "host")
            ElementTree.SubElement(host, "status", state="up" if positive else "down",
                                   reason="syn-ack" if positive else
                                   "net-unreach" if result == "no-route" else
                                   "host-unreach" if result.startswith("mixed") and address == "192.0.2.3"
                                   else "no-response")
            ElementTree.SubElement(host, "address", addr=address, addrtype="ipv4")
            if positive:
                mac = ("00:11:22:33:44:66" if result.startswith("mixed") and address == "192.0.2.2"
                       else "00:11:22:33:44:55")
                ElementTree.SubElement(host, "address", addr=mac, addrtype="mac")
    if result == "mixed-duplicate":
        xml.findall("host/address")[0].set("addr", "192.0.2.3")
    elif result == "mixed-out-of-target":
        xml.findall("host/address")[0].set("addr", "198.51.100.1")
    elif result == "mixed-inconsistent":
        xml.findall("host/status")[0].set("state", "down")
    stats = ElementTree.SubElement(xml, "runstats")
    ElementTree.SubElement(stats, "finished", exit="success")
    ElementTree.SubElement(stats, "hosts", up=str(len(positives)),
                           down=str(len(targets) - len(positives)), total=str(len(targets)))
    os.write(1, ElementTree.tostring(xml))
    if result in {"no-route", "no-targets"} or result.startswith("mixed"):
        os.write(2, b"private fixture route diagnostic; never retain raw stderr")
else:
    raise RuntimeError("fixture does not execute unknown commands")
