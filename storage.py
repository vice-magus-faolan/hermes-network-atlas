# SPDX-License-Identifier: GPL-3.0-or-later
"""Small SQLite boundary: explicit transactions, immutable evidence, no collection.

Writable callers are trusted local native code. Model handlers never receive a
connection, path, source, or qualification switch. Read-only opens do not create,
migrate, chmod, or repair the store. Shared files are knowledge, not authority.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import time
from uuid import uuid4
from collections.abc import Iterator

from .config import Policy

SCHEMA_VERSION = 1
IMMUTABLE_TABLES = ("batches", "probes", "observations", "applications", "audit_events", "access_evidence")


def identifier() -> str:
    """Generate an address/name-independent entity or operation ID."""
    return str(uuid4())


def utc_now() -> datetime:
    """Return the real UTC clock; tests inject their own aware clock."""
    return datetime.now(timezone.utc)


def timestamp(value: datetime) -> str:
    """Serialize a timezone-aware time to fixed-width UTC RFC3339."""
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone-aware timestamp required")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    """Accept only the canonical persisted UTC representation."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if timestamp(parsed) != value:
        raise ValueError("noncanonical UTC timestamp")
    return parsed


def encode(value: object) -> str:
    """Canonical JSON without non-finite numbers; never executable text."""
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def response_json(value: object, maximum: int) -> str:
    """Serialize a bounded JSON response, including the CLI's trailing newline.

    Mutation callers must check the exact receipt before committing. Use this
    same serializer at emission so escaping/UTF-8 expansion cannot bypass policy.
    """
    content = json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False) + "\n"
    if len(content.encode("utf-8")) > maximum:
        raise ValueError("response exceeds configured byte bound")
    return content


def private_directory(path: Path) -> None:
    """Create private directories without chmodding an existing shared parent."""
    if path.is_symlink():
        raise ValueError("symlink data directory refused")
    if not path.exists():
        private_directory(path.parent)
        path.mkdir(mode=0o700)
    if not path.is_dir():
        raise ValueError("data directory required")


def _prepare_file(path: Path) -> None:
    private_directory(path.parent)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        if path.is_symlink() or not path.is_file():
            raise ValueError("regular SQLite file required")
        return
    os.close(fd)


def _initialize(connection: sqlite3.Connection) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        _initialize_locked(connection)
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def _initialize_locked(connection: sqlite3.Connection) -> None:
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version == SCHEMA_VERSION:
        return
    if version != 0 or connection.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone():
        raise ValueError("unsupported or unversioned atlas schema; no automatic downgrade")
    schema = Path(__file__).with_name("storage_schema.sql").read_text(encoding="utf-8")
    for statement in schema.split(";"):
        if statement.strip():
            connection.execute(statement)
    for table in IMMUTABLE_TABLES:
        for action in ("UPDATE", "DELETE"):
            connection.execute(f"CREATE TRIGGER immutable_{table}_{action} BEFORE {action} ON {table} "
                               "BEGIN SELECT RAISE(ABORT,'immutable evidence'); END;")


class _DeadlineConnection(sqlite3.Connection):
    """Internal execute-only store boundary with one shared monotonic SQL budget.

    Refresh the busy allowance before each statement, and interrupt long-running
    SQL every 1,000 VM instructions. Rollback is deliberately outside the budget:
    expiration must release locks, not prevent cleanup. No model receives this
    connection; store code uses execute, never raw cursors/executescript.
    """

    def bind(self, deadline: float, busy_timeout_ms: int) -> None:
        self.deadline = deadline
        self.busy_timeout_ms = busy_timeout_ms
        self.check_deadline()
        self.set_progress_handler(self._expired, 1000)

    def _expired(self) -> bool:
        return time.monotonic() >= self.deadline

    def check_deadline(self) -> None:
        if self._expired():
            raise ValueError("operation deadline during persistence")

    def execute(self, sql: str, parameters=(), /) -> sqlite3.Cursor:
        if sql.strip().upper() == "ROLLBACK":
            self.set_progress_handler(None, 0)
            try:
                return super().execute(sql, parameters)
            finally:
                self.set_progress_handler(self._expired, 1000)
        self.check_deadline()
        remaining_ms = max(0, int((self.deadline - time.monotonic()) * 1000))
        allowance = min(self.busy_timeout_ms, remaining_ms)
        super().execute(f"PRAGMA busy_timeout={allowance}")
        return super().execute(sql, parameters)


class Store:
    """Profile-policy-selected store with bounded waits and explicitly owned lifetime."""

    def __init__(self, policy: Policy, *, writable: bool = False, deadline: float | None = None):
        self.policy = policy
        self.writable = writable
        if writable:
            _prepare_file(policy.database)
        uri = policy.database.as_uri() + ("?mode=rw" if writable else "?mode=ro")
        self.connection = sqlite3.connect(uri, uri=True, isolation_level=None,
                                          timeout=policy.limits.busy_timeout_ms / 1000,
                                          factory=_DeadlineConnection if deadline is not None else sqlite3.Connection)
        self.connection.row_factory = sqlite3.Row
        try:
            if isinstance(self.connection, _DeadlineConnection):
                assert deadline is not None
                self.connection.bind(deadline, policy.limits.busy_timeout_ms)
            self.connection.execute("PRAGMA foreign_keys=ON")
            if deadline is None:
                self.connection.execute(f"PRAGMA busy_timeout={policy.limits.busy_timeout_ms}")
            if writable:
                _initialize(self.connection)
                os.chmod(policy.database, 0o600)
                self.connection.execute("PRAGMA journal_mode=WAL")
            elif self.connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                raise ValueError("unsupported atlas schema")
            else:
                self.connection.execute("PRAGMA query_only=ON")
        except BaseException:
            self.connection.close()
            raise

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.connection.close()

    def check_deadline(self) -> None:
        """Check a bound operation between Python phases as well as SQL work."""
        if isinstance(self.connection, _DeadlineConnection):
            self.connection.check_deadline()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Acquire a bounded write lock; rollback every exception, including interrupts."""
        if not self.writable:
            raise ValueError("read-only atlas")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield self.connection
            self.connection.execute("COMMIT")
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    @contextmanager
    def snapshot(self) -> Iterator[sqlite3.Connection]:
        """Use one consistent read snapshot for facts, endpoints, and map output."""
        self.connection.execute("BEGIN")
        try:
            yield self.connection
        finally:
            self.connection.execute("ROLLBACK")

    def require(self, table: str, entity_id: str) -> sqlite3.Row:
        """Validate existing stable references; table names are code-owned."""
        if table not in {"devices", "interfaces", "batches"}:
            raise ValueError("invalid reference kind")
        row = self.connection.execute(f"SELECT * FROM {table} WHERE id=?", (entity_id,)).fetchone()
        if row is None:
            raise ValueError("unknown atlas entity")
        return row

    def audit(self, operation: str, action: str, actor: str, at: str, *,
              entity: str | None = None, details: object = None, batch: str | None = None) -> str:
        """Append one local event inside the caller's transaction."""
        if not self.connection.in_transaction or not self.writable:
            raise ValueError("audit requires an explicit writable transaction")
        event = identifier()
        self.connection.execute("INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?)",
                                (event, operation, batch, at, actor, action, entity, encode(details)))
        return event
