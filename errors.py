# SPDX-License-Identifier: GPL-3.0-or-later
"""Authored validation diagnostics; unexpected exceptions are never reflected."""
from __future__ import annotations

import sqlite3


class StoreError(ValueError):
    """Local store layout/schema is unusable; never an invalid caller argument."""


class RequestError(ValueError):
    """A code-authored field/reason, never exception text or a caller's value.

    Only validators may construct this with static text or code-owned field names.
    Library, transport and storage exceptions must not be converted using str(exc).
    """

    def __init__(self, diagnostic: str):
        super().__init__(diagnostic)
        self.diagnostic = diagnostic


def error_message(error: BaseException) -> str:
    """Keep infrastructure/state failures distinct from correctable request errors."""
    if isinstance(error, RequestError):
        return error.diagnostic
    if isinstance(error, (sqlite3.Error, StoreError)):
        return "store: database operation failed; check availability and compatible schema"
    if isinstance(error, OSError):
        return "local I/O: operation failed; check store/export access and available space"
    return "atlas state or bounds: operation failed; check stored evidence and configured limits"
