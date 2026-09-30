#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fresh-process synthetic persistence check; refuses all non-fixture homes."""
from datetime import datetime, timezone
import importlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from helpers import load_package


def deny_network(event, args):
    # A fresh read process must not rediscover/inspect even through an executable.
    if event in {"socket.connect", "socket.getaddrinfo", "socket.bind", "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
        raise RuntimeError("offline read-only fixture only")


def main():
    home = Path(sys.argv[1]).resolve()
    if not home.is_relative_to(Path(os.environ["TMPDIR"]).resolve()) or not (home / "synthetic-phase1-home").is_file():
        raise RuntimeError("synthetic scratch home required")
    sys.addaudithook(deny_network)
    load_package()
    config = importlib.import_module("atlas_test_plugin.config")
    query = importlib.import_module("atlas_test_plugin.query")
    render = importlib.import_module("atlas_test_plugin.render")
    storage = importlib.import_module("atlas_test_plugin.storage")
    policy = config.load_policy(home)
    now = datetime(2026, 9, 30, 12, tzinfo=timezone.utc)
    with storage.Store(policy) as store:
        count = store.connection.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
    print(json.dumps({"query": query.query(policy, {}, now=now), "map": render.render_map(policy, now=now),
                      "history_count": count}, sort_keys=True))


if __name__ == "__main__":
    main()
