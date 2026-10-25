# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit stopped-writer conversion; never invoked by registration or reads."""
from __future__ import annotations

from dataclasses import replace
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import time
from typing import Protocol

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from .config import ConfigError, MAX_CONFIG_BYTES, Settings, validate_policy
from .storage import Store, private_directory


class WritableSettings(Settings, Protocol):
    """Native atomic single-value writer, used only by explicit conversion."""

    def set_config(self, key: str, value: object) -> None: ...


def read_legacy(home: Path) -> dict:
    """Bounded legacy parser retained solely for explicit one-time conversion."""
    path = home / "network-atlas" / "config.yaml"
    try:
        with path.open("rb") as handle:
            content = handle.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError:
        return {}
    if len(content) > MAX_CONFIG_BYTES:
        raise ConfigError("legacy configuration exceeds 64 KiB")
    try:
        parser = YAML(typ="safe", pure=True)
        parser.version = (1, 2)
        raw = parser.load(content)
    except (YAMLError, UnicodeError, RecursionError) as exc:
        raise ConfigError("invalid legacy policy YAML") from exc
    validate_policy(raw, home)
    return raw


def _fingerprint(connection: sqlite3.Connection, deadline: float) -> bytes:
    """Compare complete schema, rows and schema version without retaining data."""
    connection.set_progress_handler(lambda: time.monotonic() >= deadline, 1000)
    if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
        raise ConfigError("legacy conversion: SQLite integrity check failed")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise ConfigError("legacy conversion: foreign key check failed")
    digest = hashlib.sha256(str(connection.execute("PRAGMA user_version").fetchone()[0]).encode())
    for statement in connection.iterdump():
        if time.monotonic() >= deadline:
            raise ConfigError("legacy conversion: comparison deadline; originals retained")
        digest.update(statement.encode("utf-8"))
        digest.update(b"\n")
    return digest.digest()


def _require_unchanged_source(connection: sqlite3.Connection, version: int) -> None:
    """Detect other-connection commits since this connection's initial sample."""
    if connection.execute("PRAGMA data_version").fetchone()[0] != version:
        raise ConfigError("legacy conversion: source changed; stop writers and preserve both stores")


def _copy_store(source: Path, destination: Path, home: Path) -> bool:
    """WAL-aware backup, no-clobber publication and exact-content cold retry.

    All Atlas writers must remain stopped until settings commit. SQLite backup
    includes committed WAL rows; originals and sidecars are never moved/deleted.
    A completed copy survives a later settings-write failure and is reusable only
    while it still equals the original. Concurrent destination publication fails.
    The final source-change check is not a lock across publication/settings commit.
    """
    policy = replace(validate_policy({}, home), database=source)
    deadline = time.monotonic() + policy.limits.operation_timeout_seconds
    with Store(policy, deadline=deadline) as store:
        # Store uses Row for application callers; dump/integrity checks need tuples.
        store.connection.row_factory = None
        version = store.connection.execute("PRAGMA data_version").fetchone()[0]
        original = _fingerprint(store.connection, deadline)
        if destination.exists():
            with Store(replace(policy, database=destination), deadline=deadline) as existing:
                existing.connection.row_factory = None
                if _fingerprint(existing.connection, deadline) != original:
                    raise ConfigError("legacy conversion: destination conflicts; preserve both stores")
            _require_unchanged_source(store.connection, version)
            return False
        private_directory(destination.parent)
        fd, name = tempfile.mkstemp(prefix=".atlas-convert-", suffix=".sqlite3", dir=destination.parent)
        os.close(fd)
        temporary = Path(name)
        def progress(status, remaining, total):
            if time.monotonic() >= deadline:
                raise ConfigError("legacy conversion: backup deadline; original retained")
        try:
            with closing(sqlite3.connect(temporary)) as output:
                store.connection.backup(output, pages=256, progress=progress)
                output.execute("PRAGMA journal_mode=DELETE")
                if _fingerprint(output, deadline) != original:
                    raise ConfigError("legacy conversion: backup differs; original retained")
            with temporary.open("rb") as handle:
                os.fsync(handle.fileno())
            _require_unchanged_source(store.connection, version)
            os.link(temporary, destination)
            directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
    return True


def convert_legacy(ctx: WritableSettings | None, *, writers_stopped: bool) -> dict:
    """Convert policy and default store explicitly, preserving sharing and history.

    No multi-file transaction is claimed. Publish the complete DB before the one
    native settings write. On interruption, keep originals and cold-retry with all
    writers stopped; never overwrite/merge a divergent destination or settings.
    """
    from hermes_constants import get_hermes_home
    from plugins.plugin_storage import plugin_data_dir

    if not writers_stopped or ctx is None:
        raise ConfigError("legacy conversion requires stopped writers and native settings context")
    data = plugin_data_dir("network-atlas").resolve()
    home = get_hermes_home().resolve()
    raw = read_legacy(home)
    policy = validate_policy(raw, home, data_dir=data)
    legacy = home / "network-atlas" / "atlas.sqlite3"
    if not (home / "network-atlas" / "config.yaml").exists() and not legacy.exists():
        raise ConfigError("legacy conversion: no legacy policy or store found")
    shared = "shared_sqlite_path" in raw.get("store", {})
    converted = raw if shared else {**raw, "store": {"shared_sqlite_path": str(policy.database)}}
    current = ctx.get_config("policy", None)
    if current not in (None, {}, converted):
        raise ConfigError("legacy conversion: native policy conflicts; preserve both configurations")
    copied = False
    if not shared and legacy.exists():
        copied = _copy_store(legacy, policy.database, home)
    ctx.set_config("policy", converted)
    if ctx.get_config("policy", None) != converted:
        raise ConfigError("legacy conversion: native settings readback failed; originals retained")
    return {"converted": True, "copied": copied, "shared_store_retained": shared,
            "originals_retained": True, "collection_performed": False}
