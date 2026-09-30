# SPDX-License-Identifier: GPL-3.0-or-later
"""Native handlers: stored knowledge, inference-only updates, no collection."""
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
from .storage import Store


def update_receipt(update: Update) -> str:
    """Make validation visibly distinct from an applied/audited database update."""
    return json.dumps({"validated": True, "applied": False, "persisted": False,
                       "stage": "validation_only", "update": asdict(update)}, sort_keys=True)


def status(home: Path) -> str:
    """Summarize stored knowledge separately from profile-local authorization."""
    policy = load_policy(home)
    return json.dumps({**query(policy, {"view": "status"}), "stage": "atlas_core", "persistence_available": True,
                       "collection_available": False,
                       "configured_networks": [network.name for network in policy.networks],
                       "authorized_for_atlas_ssh_inspection": list(policy.authorized_aliases),
                       "operator_update_route": "hermes network-atlas update"},
                      sort_keys=True)


class Handlers:
    """Capture registration's profile home; revalidate its policy at every invocation."""

    def __init__(self, home: Path):
        self.home = home

    def query(self, params: object, **runtime_context: object) -> str:
        """Read existing state only; runtime kwargs never attest origin or supply policy."""
        del runtime_context
        try:
            policy = load_policy(self.home)
            result = status(self.home) if params == {"view": "status"} else json.dumps(query(policy, params), sort_keys=True)
            return _bounded(result, policy.limits.output_bytes)
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
                return json.dumps(apply_update(store, update), sort_keys=True)
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
            result = _bounded(json.dumps({"format": format_name, "content": outputs[format_name], "exports": files,
                                          "discovery_performed": False}), policy.limits.output_bytes)
            if params.get("export", False):
                export_map(policy, outputs)
            return result
        except (OSError, ConfigError, ValueError, sqlite3.Error):
            return json.dumps({"error": "invalid map, bound, store, or local policy", "applied": False})

    def command(self, raw_args: str) -> str:
        """Slash origin is not attested by this runtime; refuse all operator writes."""
        if raw_args.strip() == "status":
            return self.query({"view": "status"})
        parts = raw_args.split()
        if len(parts) == 2 and parts[0] == "show":
            return self.query({"device_id": parts[1]})
        if parts and parts[0] == "map" and len(parts) <= 2:
            return self.map({"format": parts[1] if len(parts) == 2 else "text"})
        return json.dumps({"error": "slash update origin cannot be attested; use the local operator CLI",
                           "applied": False})


def _bounded(content: str, maximum: int) -> str:
    if len(content.encode("utf-8")) > maximum:
        raise ValueError("query output exceeds configured byte bound")
    return content
