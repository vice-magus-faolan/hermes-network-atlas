# SPDX-License-Identifier: GPL-3.0-or-later
"""Real scaffold handlers: readiness and proposal validation, with no persistence/collection."""
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path

from .config import ConfigError, load_policy
from .updates import Update, inference_update


def update_receipt(update: Update) -> str:
    """Make validation visibly distinct from an applied/audited database update."""
    return json.dumps({"validated": True, "applied": False, "persisted": False,
                       "stage": "contract_scaffold", "update": asdict(update)}, sort_keys=True)


def status(home: Path) -> str:
    """Report only profile-local policy/readiness; no inventory or reachability claims."""
    policy = load_policy(home)
    return json.dumps({"stage": "contract_scaffold", "persistence_available": False,
                       "collection_available": False,
                       "configured_networks": [network.name for network in policy.networks],
                       "authorized_for_atlas_ssh_inspection": list(policy.authorized_aliases),
                       "last_inspection": None, "operator_update_route": "hermes network-atlas validate-update"},
                      sort_keys=True)


class Handlers:
    """Capture registration's profile home; revalidate its policy at every invocation."""

    def __init__(self, home: Path):
        self.home = home

    def query(self, params: object, **runtime_context: object) -> str:
        """Read readiness only; runtime kwargs never attest origin or supply policy."""
        del runtime_context
        try:
            if not isinstance(params, dict) or params != {"view": "status"}:
                raise ValueError("query requires exactly view=status in this scaffold")
            return status(self.home)
        except (OSError, ConfigError, ValueError):
            return json.dumps({"error": "invalid query or local policy", "applied": False})

    def update(self, params: object, **runtime_context: object) -> str:
        """Validate inference, ignoring any origin-like kwargs from runtime dispatch."""
        del runtime_context
        try:
            return update_receipt(inference_update(params, load_policy(self.home)))
        except (OSError, ConfigError, ValueError):
            return json.dumps({"error": "invalid inference proposal or local policy", "applied": False})

    def command(self, raw_args: str) -> str:
        """Slash origin is not attested by this runtime; refuse all operator writes."""
        if raw_args.strip() == "status":
            return self.query({"view": "status"})
        return json.dumps({"error": "slash update origin cannot be attested; use the local operator CLI",
                           "applied": False})
