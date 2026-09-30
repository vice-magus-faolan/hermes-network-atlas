# SPDX-License-Identifier: GPL-3.0-or-later
"""Native local operator CLI. No source/attestation token can be supplied by the caller."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import ConfigError, load_policy
from .schemas import UPDATE_FIELDS
from .tools import status, update_receipt
from .updates import operator_update


def setup_parser(parser: argparse.ArgumentParser) -> None:
    """Attach bounded validation-only commands to Hermes's supported argparse surface."""
    parser.allow_abbrev = False
    commands = parser.add_subparsers(dest="atlas_action", required=True)
    commands.add_parser("status", allow_abbrev=False)
    update = commands.add_parser("validate-update", allow_abbrev=False,
                                 help="Validate an operator assertion; not applied/persisted until Atlas Core ships")
    update.add_argument("--device-id", required=True)
    update.add_argument("--field", choices=UPDATE_FIELDS, required=True)
    update.add_argument("--value-json", required=True, help="A bounded JSON string, or boolean for retired")


def run_command(args: argparse.Namespace, home: Path) -> int:
    """Emit an operator validation receipt via the trusted local CLI, not an LLM handler."""
    try:
        policy = load_policy(home)
        if args.atlas_action == "status":
            print(status(home))
            return 0
        if args.atlas_action != "validate-update" or len(args.value_json) > policy.limits.input_chars * 6 + 2:
            raise ValueError("invalid command or oversized JSON input")
        params = {"device_id": args.device_id, "field": args.field, "value": json.loads(args.value_json)}
        print(update_receipt(operator_update(params, policy)))
        return 0
    except (OSError, ConfigError, ValueError, RecursionError):
        print(json.dumps({"error": "invalid operator update or local policy", "applied": False}))
        return 2
