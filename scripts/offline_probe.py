#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline-only native transport fixture; cannot forward commands to real tools."""
from pathlib import Path
import json
import os
import sys
import time

root = Path(os.environ["NETWORK_ATLAS_OFFLINE_FIXTURE_DIR"]).resolve()
scratch = Path(os.environ["TMPDIR"]).resolve()
if not root.is_relative_to(scratch) or not (root / "offline-fixture").is_file():
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
else:
    raise RuntimeError("fixture does not execute unknown commands")
