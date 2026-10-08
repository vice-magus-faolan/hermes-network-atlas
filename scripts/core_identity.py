# SPDX-License-Identifier: GPL-3.0-or-later
"""Complete pinned public-source identity, independent of imported Hermes code.

Runtime/VCS caches retain the existing two exclusions only. Every other regular
file and symlink, including source/tests/docs and executable semantics, counts.
Diagnostics contain hashes/paths, never source bytes or native state.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

CORE_SOURCE_DIGEST = '880bc1836050b055ecd47f08bcc3f25fc1392f824a170f93d07e2ae7e8705b96'
CORE_TREE = '008b644d38770b7de0835592ddaf19a708e2fa82'
MANIFEST_BYTES = 4 * 1024 ** 2
MEMBER_COUNT = 100000
SOURCE_BYTES = 256 * 1024 ** 2
DIFFERENCES = 64


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def manifest_digest(manifest: dict) -> str:
    payload = canonical(manifest)
    if len(payload) > MANIFEST_BYTES:
        raise ValueError('complete core manifest byte bound')
    return hashlib.sha256(payload).hexdigest()


def file_identity(path: Path, info: os.stat_result) -> list:
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    after = path.lstat()
    if (info.st_ino, info.st_size, info.st_mtime_ns, info.st_mode) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode):
        raise ValueError('core member changed during authentication')
    return ['file', bool(info.st_mode & 0o111), digest]


def source_manifest(source: Path) -> dict:
    """Hash all leaves without following directory symlinks; bound traversal/bytes."""
    if source.is_symlink() or not source.is_dir():
        raise ValueError('literal complete core directory required')
    manifest = {}
    total = count = 0
    encoded = 2
    for path in source.rglob('*'):
        relative = path.relative_to(source)
        if any(part in {'.git', '__pycache__'} for part in relative.parts):
            continue
        count += 1
        if count > MEMBER_COUNT or len(relative.as_posix().encode()) > 4096:
            raise ValueError('complete core member/path bound')
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            manifest[relative.as_posix()] = ['symlink', os.readlink(path)]
        elif stat.S_ISREG(info.st_mode):
            total += info.st_size
            if total > SOURCE_BYTES:
                raise ValueError('complete core source byte bound')
            manifest[relative.as_posix()] = file_identity(path, info)
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError('unexpected complete core member type')
        if relative.as_posix() in manifest:
            encoded += len(canonical({relative.as_posix(): manifest[relative.as_posix()]})) - 1
            if encoded > MANIFEST_BYTES:
                raise ValueError('complete core manifest byte bound')
    manifest_digest(manifest)
    return manifest


def identity_report(actual: dict, expected: dict, phase: str) -> dict:
    """Bound differing paths, but retain the honest total and both complete digests."""
    paths = sorted(name for name in set(actual) | set(expected) if actual.get(name) != expected.get(name))
    return {'phase': phase, 'expected_digest': manifest_digest(expected), 'actual_digest': manifest_digest(actual),
            'expected_members': len(expected), 'actual_members': len(actual), 'difference_count': len(paths),
            'differences': [{'path': name, 'expected': expected.get(name), 'actual': actual.get(name)} for name in paths[:DIFFERENCES]],
            'omitted_differences': max(0, len(paths) - DIFFERENCES), 'native_acceptance': False}


def require_identity(manifest: dict, *, expected_digest: str = CORE_SOURCE_DIGEST) -> None:
    if manifest_digest(manifest) != expected_digest:
        raise ValueError('pinned complete Hermes source identity mismatch')
