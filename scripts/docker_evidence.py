# SPDX-License-Identifier: GPL-3.0-or-later
"""Write-side evidence bounds, including atomic replacement and SQLite backup.

These are cooperative application limits, not a quota on an untrusted host bind.
Never use this module with live databases or credentials as evidence.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tarfile
import time

TOTAL = 32 * 1024 ** 2
PER_FILE = 8 * 1024 ** 2
COUNT = 64
PENDING = ".atlas-pending"


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def flat_name(name: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", name):
        raise ValueError("bounded flat evidence filename required")


def regular_read(path: Path, maximum: int) -> bytes:
    """Nofollow fd identity/size checks before reading or allocating a payload."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("evidence member/per-file bound exceeded")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            payload = stream.read(info.st_size + 1)
        after = os.fstat(fd)
        before_identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if len(payload) != info.st_size or after_identity != before_identity:
            raise ValueError("evidence member changed during read")
        return payload
    finally:
        os.close(fd)


class BoundedDirectory:
    """Flat owned evidence with per-file/count/aggregate and transient write limits."""
    def __init__(self, root: Path, *, total: int = TOTAL, per_file: int = PER_FILE, count: int = COUNT):
        if root.is_symlink() or not root.is_dir():
            raise ValueError("existing nonsymlink evidence directory required")
        self.root, self.total, self.per_file, self.count = root, total, per_file, count

    def members(self) -> list[tuple[Path, int]]:
        result = []
        for path in self.root.iterdir():
            flat_name(path.name)
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > self.per_file:
                raise ValueError("unexpected export member or per-file bound")
            result.append((path, info.st_size))
            if len(result) > self.count:
                raise ValueError("evidence member count exceeded")
        if sum(size for _path, size in result) > self.total:
            raise ValueError("aggregate evidence bound exceeded")
        return result

    def reserve(self, name: str, size: int) -> Path:
        flat_name(name)
        if type(size) is not int or not 0 <= size <= self.per_file:
            raise ValueError("evidence per-file write bound exceeded")
        members = self.members()
        path = self.root / name
        # Atomic replacement temporarily retains the old bytes AND the new bytes.
        if sum(value for _path, value in members) + size > self.total:
            raise ValueError("aggregate/transient evidence write bound exceeded")
        if len(members) + 1 > self.count:
            raise ValueError("evidence count including pending replacement exceeded before write")
        if (self.root / PENDING).exists():
            raise ValueError("pending export residue, not a retry opportunity")
        return path

    def write(self, name: str, payload: bytes) -> None:
        path = self.reserve(name, len(payload))
        pending = self.root / PENDING
        try:
            with pending.open("xb") as stream:
                os.chmod(pending, 0o600)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(pending, path)
        finally:
            pending.unlink(missing_ok=True)

    def json(self, name: str, value: object) -> None:
        self.write(name, json_bytes(value))

    def copy(self, source: Path, name: str) -> None:
        size = source.lstat().st_size
        self.reserve(name, size)
        self.write(name, regular_read(source, self.per_file))

    def sqlite_backup(self, source: Path, name: str) -> None:
        """Reserve the full per-file ceiling before SQLite writes; consistent snapshot."""
        if source.is_symlink() or not source.is_file():
            raise ValueError("synthetic regular SQLite source required")
        path = self.reserve(name, self.per_file)
        pending = self.root / PENDING
        try:
            with sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=1) as db:
                page_size = db.execute("PRAGMA page_size").fetchone()[0]
                pages = db.execute("PRAGMA page_count").fetchone()[0]
                if pages * page_size > self.per_file:
                    raise ValueError("SQLite backup exceeds reserved bytes")
                backup_database(db, pending, page_size, self.per_file)
            if pending.stat().st_size > self.per_file:
                raise ValueError("SQLite backup exceeded reserved ceiling")
            os.replace(pending, path)
        finally:
            pending.unlink(missing_ok=True)


def backup_database(source: sqlite3.Connection, pending: Path, page_size: int, ceiling: int) -> None:
    """One page per step; abort on growth before the reserved ceiling can be crossed."""
    fd = os.open(pending, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    deadline = time.monotonic() + 10
    def progress(_status: int, _remaining: int, total: int) -> None:
        if time.monotonic() >= deadline:
            raise TimeoutError("SQLite evidence snapshot deadline")
        if total * page_size > ceiling:
            raise ValueError("SQLite source grew beyond evidence reservation")
    with sqlite3.connect(pending, timeout=1) as target:
        target.execute("PRAGMA journal_mode=OFF")
        source.backup(target, pages=1, progress=progress, sleep=0)


def archive_directory(root: Path, *, limit: int = TOTAL) -> bytes:
    """Account tar header/block padding BEFORE allocation; reject all links/dirs."""
    members = BoundedDirectory(root).members()
    padded = 1024 + sum(512 + ((size + 511) // 512) * 512 for _path, size in members)
    padded = ((padded + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
    if not members or padded > limit:
        raise ValueError("missing/oversized evidence archive including padding")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as bundle:
        for path, size in sorted(members):
            payload = regular_read(path, PER_FILE)
            if len(payload) != size:
                raise ValueError("export changed before archive")
            member = tarfile.TarInfo(path.name)
            member.size = size
            bundle.addfile(member, io.BytesIO(payload))
    return buffer.getvalue()


def inventory_hashes(root: Path) -> dict[str, str]:
    return {path.name: hashlib.sha256(regular_read(path, PER_FILE)).hexdigest()
            for path, _size in BoundedDirectory(root).members()}
