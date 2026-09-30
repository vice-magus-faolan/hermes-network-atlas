# SPDX-License-Identifier: GPL-3.0-or-later
"""Supported native Hermes plugin entry point; validate policy before any registration."""
from __future__ import annotations

from functools import partial
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hermes_cli.plugins import PluginContext


def register(ctx: PluginContext) -> None:
    """Fail closed on unsupported Python or malformed policy; never activate live collection."""
    if not (3, 11) <= sys.version_info[:2] < (3, 15):
        raise RuntimeError("Network Atlas supports Python >=3.11,<3.15")
    from hermes_constants import get_hermes_home
    from .commands import run_command, setup_parser
    from .config import load_policy
    from .schemas import QUERY_SCHEMA, UPDATE_SCHEMA
    from .tools import Handlers

    home = get_hermes_home().resolve()
    load_policy(home)
    handlers = Handlers(home)
    ctx.register_tool(name="network_query", toolset="network_atlas", schema=QUERY_SCHEMA,
                      handler=handlers.query)
    ctx.register_tool(name="network_update", toolset="network_atlas", schema=UPDATE_SCHEMA,
                      handler=handlers.update)
    ctx.register_command("network", handlers.command, description="Atlas readiness; operator writes require local CLI",
                         args_hint="status")
    ctx.register_cli_command("network-atlas", "Network Atlas operator validation/readiness",
                             setup_parser, partial(run_command, home=home))
