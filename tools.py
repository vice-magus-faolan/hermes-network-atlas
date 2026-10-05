# SPDX-License-Identifier: GPL-3.0-or-later
"""Native handlers: explicit bounded discovery, stored knowledge and inference writes."""
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import sqlite3

from .config import ConfigError, load_policy
from .updates import Update, inference_update
from .core import apply_update
from .query import query
from .render import export_map, render_map
from .storage import Store, response_json
from .discovery import collect
from .host_discovery import TransportStaged
from .reconcile import reconcile
from .inspection import collect as inspect_host

COMMAND_USAGE = ("status|show <id>|map [text|markdown|mermaid]|discover <network> <passive|ping>|"
                 "inspect <alias-or-id>|reconcile [batch-id]|help")


def update_receipt(update: Update) -> str:
    """Make validation visibly distinct from an applied/audited database update."""
    return json.dumps({"validated": True, "applied": False, "persisted": False,
                       "stage": "validation_only", "update": asdict(update)}, sort_keys=True)


def status(home: Path) -> str:
    """Summarize stored knowledge separately from profile-local authorization."""
    policy = load_policy(home)
    return response_json({**query(policy, {"view": "status"}), "stage": "v1", "persistence_available": True,
                          "collection_available": True, "ssh_transport_available": True,
                          "configured_networks": [network.name for network in policy.networks],
                          "configured_scopes": [asdict(network) for network in policy.networks],
                          "authorized_for_atlas_ssh_inspection": list(policy.authorized_aliases),
                          "operator_update_route": "hermes network-atlas update"},
                         policy.limits.output_bytes)


class Handlers:
    """Capture registration's profile home; revalidate its policy at every invocation."""

    def __init__(self, home: Path):
        self.home = home

    def query(self, params: object, **runtime_context: object) -> str:
        """Read existing state only; runtime kwargs never attest origin or supply policy."""
        del runtime_context
        try:
            policy = load_policy(self.home)
            return status(self.home) if params == {"view": "status"} else response_json(query(policy, params), policy.limits.output_bytes)
        except (OSError, ConfigError, ValueError, sqlite3.Error):
            return json.dumps({"error": "invalid query or local policy", "applied": False})

    def update(self, params: object, **runtime_context: object) -> str:
        """Persist inference only, ignoring origin-like kwargs from runtime dispatch."""
        del runtime_context
        try:
            policy = load_policy(self.home)
            update = inference_update(params, policy)
            if not policy.database.exists():
                raise ValueError("unknown atlas entity")
            with Store(policy, writable=True) as store:
                # apply_update checks this exact serialized receipt before commit.
                return response_json(apply_update(store, update), policy.limits.output_bytes)
        except (OSError, ConfigError, ValueError, sqlite3.Error):
            return json.dumps({"error": "invalid inference proposal or local policy", "applied": False})

    def map(self, params: object, **runtime_context: object) -> str:
        """Render stored topology; output and fixed export paths are code-owned."""
        del runtime_context
        try:
            if not isinstance(params, dict) or not set(params) <= {"format", "export"}:
                raise ValueError("invalid map arguments")
            format_name = params.get("format", "text")
            if not isinstance(format_name, str) or format_name not in {"text", "markdown", "mermaid"}:
                raise ValueError("invalid map format")
            if type(params.get("export", False)) is not bool:
                raise ValueError("invalid export boolean")
            policy = load_policy(self.home)
            outputs = render_map(policy)
            files = [str(policy.exports / name) for name in ("network_map.md", "network_map.mmd")] if params.get("export", False) else []
            result = response_json({"format": format_name, "content": outputs[format_name], "exports": files,
                                    "discovery_performed": False}, policy.limits.output_bytes)
            if params.get("export", False):
                export_map(policy, outputs)
            return result
        except (OSError, ConfigError, ValueError, sqlite3.Error):
            return json.dumps({"error": "invalid map, bound, store, or local policy", "applied": False})

    def discover(self, params: object, **runtime_context: object) -> str:
        """Collect only an explicitly named current-policy network/mode; ignore kwargs."""
        del runtime_context
        try:
            policy = load_policy(self.home)
            return response_json(collect(policy, params), policy.limits.output_bytes)
        except TransportStaged:
            return json.dumps({"error": "selected host discovery transport is staged, not yet functional",
                               "diagnostic_code": "host_discovery_transport_staged", "applied": False, "persisted": False})
        except (OSError, ConfigError, ValueError, sqlite3.Error):
            return json.dumps({"error": "invalid discovery request, bounds, store, or local policy", "applied": False, "persisted": False})

    def reconcile(self, params: object, **runtime_context: object) -> str:
        """Apply stored evidence only; no probe runs on this path."""
        del runtime_context
        try:
            policy = load_policy(self.home)
            return response_json(reconcile(policy, params), policy.limits.output_bytes)
        except (OSError, ConfigError, ValueError, sqlite3.Error):
            return json.dumps({"error": "invalid stored batch, bounds, store, or local policy", "applied": False})

    def inspect(self, params: object, **runtime_context: object) -> str:
        """Fixed probes only; runtime kwargs cannot supply target policy or commands."""
        del runtime_context
        try:
            policy = load_policy(self.home)
            return response_json(inspect_host(policy, params), policy.limits.output_bytes)
        except (OSError, ConfigError, ValueError, sqlite3.Error):
            return json.dumps({"error": "invalid inspection target, bounds, store, or local policy",
                               "applied": False, "persisted": False})

    def command(self, raw_args: str) -> str:
        """Slash origin is not attested by this runtime; refuse all operator writes."""
        if raw_args.strip() == "help":
            return json.dumps({"usage": COMMAND_USAGE, "operator_update_route": "hermes network-atlas update"})
        if raw_args.strip() == "status":
            return self.query({"view": "status"})
        parts = raw_args.split()
        if len(parts) == 2 and parts[0] == "show":
            return self.query({"device_id": parts[1]})
        if parts and parts[0] == "map" and len(parts) <= 2:
            return self.map({"format": parts[1] if len(parts) == 2 else "text"})
        collected = self._collection_command(parts)
        if collected is not None:
            return collected
        error = "slash update origin cannot be attested; use the local operator CLI" if parts and parts[0] == "update" else "invalid network command"
        return json.dumps({"error": error, "usage": COMMAND_USAGE, "applied": False})

    def _collection_command(self, parts: list[str]) -> str | None:
        """Exact slash collection arities route through the same validated handlers."""
        if len(parts) == 2 and parts[0] == "inspect":
            return self.inspect({"target": parts[1]})
        if len(parts) == 3 and parts[0] == "discover":
            return self.discover({"network": parts[1], "mode": parts[2]})
        if parts and parts[0] == "reconcile" and len(parts) <= 2:
            return self.reconcile({"batch_id": parts[1]} if len(parts) == 2 else {})
        return None
