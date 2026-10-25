# SPDX-License-Identifier: GPL-3.0-or-later
"""Supported native Hermes plugin entry point; registration never collects."""
from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hermes_cli.plugins import PluginContext


def register(ctx: PluginContext) -> None:
    """Register adapters; native Hermes owns runtime and settings lifecycle."""
    from .commands import run_command, setup_parser
    from .config import load_policy
    from .schemas import (
        DISCOVER_SCHEMA, ENDPOINT_SCHEMA, INSPECT_SCHEMA, MAP_SCHEMA, QUERY_SCHEMA, RECONCILE_SCHEMA, UPDATE_SCHEMA)
    from .tools import COMMAND_USAGE, Handlers

    policy_loader = partial(load_policy, ctx)
    handlers = Handlers(policy_loader)
    ctx.register_tool(name="network_query", toolset="network_atlas", schema=QUERY_SCHEMA,
                      handler=handlers.query)
    ctx.register_tool(name="network_update", toolset="network_atlas", schema=UPDATE_SCHEMA,
                      handler=handlers.update)
    ctx.register_tool(name="network_map", toolset="network_atlas", schema=MAP_SCHEMA,
                      handler=handlers.map)
    ctx.register_tool(name="network_discover", toolset="network_atlas", schema=DISCOVER_SCHEMA,
                      handler=handlers.discover)
    ctx.register_tool(name="network_reconcile", toolset="network_atlas", schema=RECONCILE_SCHEMA,
                      handler=handlers.reconcile)
    ctx.register_tool(name="network_inspect", toolset="network_atlas", schema=INSPECT_SCHEMA,
                      handler=handlers.inspect)
    ctx.register_tool(name="network_check_endpoints", toolset="network_atlas", schema=ENDPOINT_SCHEMA,
                      handler=handlers.check_endpoints)
    ctx.register_command("network", handlers.command, description="Stored atlas; operator writes require local CLI",
                         args_hint=COMMAND_USAGE)
    ctx.register_cli_command("network-atlas", "Network Atlas operator updates and stored knowledge",
                             setup_parser, partial(run_command, policy_loader=policy_loader, ctx=ctx))
