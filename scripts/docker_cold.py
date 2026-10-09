#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Cold read-only native consumer after fresh genuine enable; never admission setup."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys

from acceptance_support import HERMES_COMMIT, contained, fixture_root, git_head, git_tree, validate_receipt
from offline_guard import deny_network

NAMES = {"network_query", "network_update", "network_map", "network_discover", "network_inspect", "network_reconcile"}


def check_selection(root: Path, receipt: dict, source: Path) -> None:
    """A base/interpreter symlink is not a selected UUID member-union generation."""
    from pm.environments import committed_venv, runtime_facts_path, venv_python
    from hermes_cli.config import load_config_readonly
    generation = committed_venv(source)
    if generation is None or contained(root, str(generation)) != Path(receipt["native_generation"]).resolve():
        raise ValueError("cold PM committed generation mismatch")
    if Path(sys.prefix).resolve() != generation.resolve():
        raise ValueError("cold consumer not running selected generation")
    if (Path(sys.executable).resolve() != contained(root, str(venv_python(generation)))
            or str(runtime_facts_path(source)) != receipt["native_facts"]):
        raise ValueError("cold interpreter/native source facts mismatch")
    enabled = load_config_readonly().get("plugins", {}).get("enabled", [])
    if enabled != ["network-atlas"]:
        raise ValueError("cold enabled selection mismatch")
    installed = contained(root, receipt["plugin"])
    if git_head(installed) != receipt["installed_commit"] or git_tree(installed) != receipt["candidate_tree"]:
        raise ValueError("cold installed complete commit/tree mismatch")


def check_registration() -> dict:
    from hermes_cli.plugins import discover_plugins, get_plugin_manager, get_plugin_command_handler
    from tools.registry import registry
    discover_plugins()
    manager = get_plugin_manager()
    plugin = next((item for item in manager.list_plugins() if item["name"] == "network-atlas"), None)
    if plugin is None or not plugin["enabled"] or plugin["error"] or plugin["source"] != "user":
        raise ValueError("cold installed native registration failed")
    definitions = registry.get_definitions(NAMES)
    if {value["function"]["name"] for value in definitions} != NAMES:
        raise ValueError("cold native tool registration incomplete")
    if get_plugin_command_handler("network") is None or "network-atlas" not in manager._cli_commands:
        raise ValueError("cold slash/CLI registration incomplete")
    return {"tools": sorted(NAMES), "slash": "network", "cli": "network-atlas"}


def consume(root: Path, image: str) -> dict:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("immutable Docker image binding required")
    receipt = validate_receipt(root)
    source = contained(root, receipt["source"])
    sys.path.insert(0, str(source))
    check_selection(root, receipt, source)
    database = root / "hermes" / "network-atlas" / "atlas.sqlite3"
    existed = database.exists()
    registration = check_registration()
    if database.exists() != existed:
        raise ValueError("cold registration unexpectedly created an atlas")
    validate_receipt(root)
    return {"cold_native_selection": True, "collected": False, "image": image,
            "candidate_commit": receipt["candidate_commit"], "candidate_tree": receipt["candidate_tree"],
            "native_generation": receipt["native_generation"], "python": receipt["python"], "source": str(source),
            "native_facts": receipt["native_facts"], "installed_tree": receipt["installed_tree"],
            "hermes_commit": HERMES_COMMIT, "registration": registration}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("fixture")
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    deny_network()
    root = fixture_root(args.fixture)
    if os.environ.get("HERMES_HOME") != str(root / "hermes"):
        raise ValueError("cold isolated fixture home required")
    print(json.dumps(consume(root, args.image), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
