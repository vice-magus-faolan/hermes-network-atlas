# SPDX-License-Identifier: GPL-3.0-or-later
"""Native local operator CLI. No source/attestation token can be supplied by the caller."""
from __future__ import annotations

import argparse
from collections.abc import Callable
import json
import sqlite3
from typing import TYPE_CHECKING

from .config import Policy
from .errors import RequestError, error_message
from .tools import Handlers, status, update_receipt
from .updates import Update, operator_update
from .core import add_address, add_interface, apply_update, create_device, end_address
from .storage import Store, response_json, upgrade_store

if TYPE_CHECKING:
    from .conversion import WritableSettings


def setup_parser(parser: argparse.ArgumentParser) -> None:
    """Attach the trusted local operator route; slash/model calls cannot attest origin."""
    parser.allow_abbrev = False
    # Semantic values reach the shared validators, whose diagnostics never echo
    # invalid values. Native argparse still owns syntax/unknown-option errors.
    commands = parser.add_subparsers(dest="atlas_action", required=True)
    commands.add_parser("status", allow_abbrev=False)
    conversion = commands.add_parser("convert-legacy", allow_abbrev=False,
                                     help="Explicit one-time conversion; stop all Atlas writers first")
    conversion.add_argument("--writers-stopped", required=True, action="store_true")
    upgrade = commands.add_parser("upgrade-store", allow_abbrev=False,
                                  help="Explicit schema upgrade; back up and stop all Atlas writers first")
    upgrade.add_argument("--writers-stopped", required=True, action="store_true")
    create = commands.add_parser("create", allow_abbrev=False, help="Create a known device (not an observation)")
    create.add_argument("--name", required=True)
    for action in ("update", "validate-update"):
        update = commands.add_parser(action, allow_abbrev=False)
        update.add_argument("--device-id", required=True)
        update.add_argument("--field", required=True, help="Documented operator update field")
        update.add_argument("--value-json", required=True, help="Bounded JSON scalar or typed relationship")
    interface = commands.add_parser("interface", allow_abbrev=False)
    interface.add_argument("--device-id", required=True)
    interface.add_argument("--name", required=True)
    interface.add_argument("--mac")
    interface.add_argument("--interface-type", default="unknown")
    address = commands.add_parser("address", allow_abbrev=False)
    address.add_argument("--interface-id", required=True)
    address.add_argument("--address", required=True)
    address.add_argument("--prefix-length", required=True)
    ended = commands.add_parser("end-address", allow_abbrev=False)
    ended.add_argument("--assignment-id", required=True)
    query = commands.add_parser("query", allow_abbrev=False)
    query.add_argument("--query-json", default="{}")
    map_parser = commands.add_parser("map", allow_abbrev=False)
    map_parser.add_argument("--format", default="text", help="text, markdown or mermaid")
    map_parser.add_argument("--export", action="store_true")
    discover = commands.add_parser("discover", allow_abbrev=False)
    discover.add_argument("--network", required=True)
    discover.add_argument("--mode", required=True, help="passive or ping")
    reconcile_parser = commands.add_parser("reconcile", allow_abbrev=False)
    reconcile_parser.add_argument("--batch-id")
    inspect_parser = commands.add_parser("inspect", allow_abbrev=False)
    inspect_parser.add_argument("--target", required=True)
    endpoints = commands.add_parser("check-endpoints", allow_abbrev=False)
    endpoints.add_argument("network")
    resume = commands.add_parser("resume-endpoints", allow_abbrev=False)
    resume.add_argument("batch_id", help="Resume stored local endpoint evidence; never collects")
    preview = commands.add_parser("preview-endpoints", allow_abbrev=False,
                                  help="Read remaining unattempted work; no collection")
    preview.add_argument("batch_id")
    continuation = commands.add_parser("continue-endpoints", allow_abbrev=False,
                                       help="Explicitly make NEW TCP/UDP checks of remaining unattempted work")
    continuation.add_argument("batch_id")


def run_command(args: argparse.Namespace, policy_loader: Callable[[], Policy], *,
                ctx: WritableSettings | None = None) -> int:
    """Run a bounded trusted local command, emitting audited persistence receipts."""
    try:
        if args.atlas_action == "convert-legacy":
            from .conversion import convert_legacy
            result = convert_legacy(ctx, writers_stopped=args.writers_stopped)
            print(json.dumps(result, sort_keys=True))
            return 0
        policy = policy_loader()
        result = _read_command(args, policy)
        if result is None:
            result = _write_command(args, policy)
        # Native mutations have already checked this exact receipt before commit;
        # read-only and validation results are checked here without side effects.
        print(response_json(result, policy.limits.output_bytes), end="")
        return 2 if "error" in result else 0
    except (OSError, ValueError, RecursionError, sqlite3.Error) as exc:
        print(json.dumps({"error": error_message(exc), "applied": False, "persisted": False}))
        return 2


def _decode(text: str, policy: Policy, field: str) -> object:
    """Decode JSON with the code-owned option name supplied by each CLI route."""
    if len(text) > policy.limits.input_chars * 6 + 512:
        raise RequestError(f"{field}: JSON input exceeds configured size limit")
    try:
        return json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise RequestError(f"{field}: JSON input requires valid bounded JSON") from exc


def _read_command(args: argparse.Namespace, policy: Policy) -> dict | None:
    handlers = Handlers(lambda: policy)
    endpoint_keys = {"resume-endpoints": "batch_id", "preview-endpoints": "preview_batch_id",
                     "continue-endpoints": "continue_batch_id"}
    if args.atlas_action in endpoint_keys or args.atlas_action == "check-endpoints":
        selection = ({"network": args.network} if args.atlas_action == "check-endpoints" else
                     {endpoint_keys[args.atlas_action]: args.batch_id})
        return json.loads(handlers.check_endpoints(selection))
    if args.atlas_action == "inspect":
        return json.loads(handlers.inspect({"target": args.target}))
    if args.atlas_action == "discover":
        return json.loads(handlers.discover({"network": args.network, "mode": args.mode}))
    if args.atlas_action == "reconcile":
        return json.loads(handlers.reconcile({"batch_id": args.batch_id} if args.batch_id else {}))
    if args.atlas_action == "status":
        return json.loads(status(policy))
    if args.atlas_action == "query":
        return json.loads(handlers.query(_decode(args.query_json, policy, "query-json")))
    if args.atlas_action == "map":
        return json.loads(handlers.map({"format": args.format, "export": args.export}))
    if args.atlas_action == "validate-update":
        update = operator_update({"device_id": args.device_id, "field": args.field,
                                  "value": _decode(args.value_json, policy, "value-json")}, policy)
        return json.loads(update_receipt(update))
    return None


def _write_command(args: argparse.Namespace, policy: Policy) -> dict:
    if args.atlas_action == "upgrade-store":
        return upgrade_store(policy, writers_stopped=args.writers_stopped)
    # Validate proposals before creating a store; only create may initialize an
    # empty atlas. All other mutations require existing entity references.
    update = None
    if args.atlas_action == "address":
        if type(args.prefix_length) not in (str, int):
            raise RequestError("prefix_length: integer required")
        try:
            args.prefix_length = int(args.prefix_length)
        except (ValueError, TypeError) as exc:
            raise RequestError("prefix_length: integer required") from exc
    if args.atlas_action == "update":
        update = operator_update({"device_id": args.device_id, "field": args.field,
                                  "value": _decode(args.value_json, policy, "value-json")}, policy)
    if args.atlas_action != "create" and not policy.database.exists():
        raise RequestError("entity reference: select an existing atlas entity before updating")
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
