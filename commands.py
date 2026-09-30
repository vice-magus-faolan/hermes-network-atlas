# SPDX-License-Identifier: GPL-3.0-or-later
"""Native local operator CLI. No source/attestation token can be supplied by the caller."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3

from .config import ConfigError, Policy, load_policy
from .schemas import UPDATE_FIELDS
from .tools import Handlers, status, update_receipt
from .updates import Update, operator_update
from .core import add_address, add_interface, apply_update, create_device, end_address
from .storage import Store


def setup_parser(parser: argparse.ArgumentParser) -> None:
    """Attach the trusted local operator route; slash/model calls cannot attest origin."""
    parser.allow_abbrev = False
    commands = parser.add_subparsers(dest="atlas_action", required=True)
    commands.add_parser("status", allow_abbrev=False)
    create = commands.add_parser("create", allow_abbrev=False, help="Create a known device (not an observation)")
    create.add_argument("--name", required=True)
    for action in ("update", "validate-update"):
        update = commands.add_parser(action, allow_abbrev=False)
        update.add_argument("--device-id", required=True)
        update.add_argument("--field", choices=UPDATE_FIELDS, required=True)
        update.add_argument("--value-json", required=True, help="Bounded JSON scalar or typed relationship")
    interface = commands.add_parser("interface", allow_abbrev=False)
    interface.add_argument("--device-id", required=True)
    interface.add_argument("--name", required=True)
    interface.add_argument("--mac")
    interface.add_argument("--interface-type", default="unknown")
    address = commands.add_parser("address", allow_abbrev=False)
    address.add_argument("--interface-id", required=True)
    address.add_argument("--address", required=True)
    address.add_argument("--prefix-length", type=int, required=True)
    ended = commands.add_parser("end-address", allow_abbrev=False)
    ended.add_argument("--assignment-id", required=True)
    query = commands.add_parser("query", allow_abbrev=False)
    query.add_argument("--query-json", default="{}")
    map_parser = commands.add_parser("map", allow_abbrev=False)
    map_parser.add_argument("--format", choices=("text", "markdown", "mermaid"), default="text")
    map_parser.add_argument("--export", action="store_true")


def run_command(args: argparse.Namespace, home: Path) -> int:
    """Run a bounded trusted local command, emitting audited persistence receipts."""
    try:
        policy = load_policy(home)
        result = _read_command(args, home, policy)
        if result is None:
            result = _write_command(args, policy)
        print(json.dumps(result, sort_keys=True))
        return 2 if "error" in result else 0
    except (OSError, ConfigError, ValueError, RecursionError, sqlite3.Error):
        print(json.dumps({"error": "invalid operator update or local policy", "applied": False}))
        return 2


def _decode(text: str, policy: Policy) -> object:
    if len(text) > policy.limits.input_chars * 6 + 512:
        raise ValueError("oversized JSON input")
    return json.loads(text)


def _read_command(args: argparse.Namespace, home: Path, policy: Policy) -> dict | None:
    if args.atlas_action == "status":
        return json.loads(status(home))
    if args.atlas_action == "query":
        return json.loads(Handlers(home).query(_decode(args.query_json, policy)))
    if args.atlas_action == "map":
        return json.loads(Handlers(home).map({"format": args.format, "export": args.export}))
    if args.atlas_action == "validate-update":
        update = operator_update({"device_id": args.device_id, "field": args.field,
                                  "value": _decode(args.value_json, policy)}, policy)
        return json.loads(update_receipt(update))
    return None


def _write_command(args: argparse.Namespace, policy: Policy) -> dict:
    # Validate proposals before creating a store; only create may initialize an
    # empty atlas. All other mutations require existing entity references.
    update = None
    if args.atlas_action == "update":
        update = operator_update({"device_id": args.device_id, "field": args.field,
                                  "value": _decode(args.value_json, policy)}, policy)
    if args.atlas_action != "create" and not policy.database.exists():
        raise ValueError("unknown atlas entity")
    with Store(policy, writable=True) as store:
        return _mutate(store, args, update)


def _mutate(store: Store, args: argparse.Namespace, update: Update | None) -> dict:
    if args.atlas_action == "create":
        return create_device(store, args.name)
    if update is not None:
        return apply_update(store, update)
    if args.atlas_action == "interface":
        entity = add_interface(store, args.device_id, args.name, args.mac, interface_type=args.interface_type)
        return {"interface_id": entity, "applied": True, "persisted": True}
    if args.atlas_action == "address":
        entity = add_address(store, args.interface_id, args.address, args.prefix_length)
        return {"assignment_id": entity, "applied": True, "persisted": True}
    if args.atlas_action == "end-address":
        end_address(store, args.assignment_id)
        return {"applied": True, "persisted": True}
    raise ValueError("unknown operator command")
