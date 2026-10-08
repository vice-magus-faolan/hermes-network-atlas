# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact controller-created read-only snapshot trust, never ambient Git authority.

The controller writes the commit/tree record only after public reconstruction.
The container bind is immutable; this is not a sandbox against same-UID host code.
Only /candidate gets a process-local exception. Owned native copies need none.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from docker_evidence import regular_read

CANDIDATE = Path('/candidate')
RECORD = 'atlas-snapshot.json'
CONFIG = b'[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n'
LIMIT = 256 * 1024 ** 2


def snapshot_record(root: Path) -> dict[str, str]:
    """Reject alternate roots, symlinked Git storage and malformed authority."""
    if root != CANDIDATE or not root.is_absolute() or root.resolve(strict=True) != root:
        raise ValueError('only literal fixed candidate snapshot may receive Git trust')
    if root.is_symlink() or (root / '.git').is_symlink() or not (root / '.git').is_dir():
        raise ValueError('ordinary nonsymlink snapshot Git directory required')
    if regular_read(root / '.git' / 'config', 1024) != CONFIG:
        raise ValueError('controller-only inert snapshot Git config required')
    record = json.loads(regular_read(root / '.git' / RECORD, 1024))
    if not isinstance(record, dict) or set(record) != {'commit', 'tree'}:
        raise ValueError('exact controller snapshot commit/tree record required')
    if not all(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{40}', value) for value in record.values()):
        raise ValueError('exact lowercase snapshot identities required')
    return record


def git_settings(root: Path) -> dict[str, str]:
    """Reset ambient trust before adding ONE literal repository, never a parent."""
    return {'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': '/dev/null', 'GIT_CONFIG_GLOBAL': '/dev/null',
            'GIT_CONFIG_COUNT': '2', 'GIT_CONFIG_KEY_0': 'safe.directory', 'GIT_CONFIG_VALUE_0': str(root),
            'GIT_CONFIG_KEY_1': 'core.hooksPath', 'GIT_CONFIG_VALUE_1': '/dev/null',
            'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0'}


def git_environment(root: Path) -> dict[str, str]:
    snapshot_record(root)
    return dict(git_settings(root), PATH='/usr/bin:/bin', HOME='/nonexistent', LC_ALL='C')


def git_output(root: Path, *args: str) -> bytes:
    # Existing bounded owned-child reader, including deadlines and primary exits.
    from docker_acceptance import command
    return command(['git', '-C', str(root), *args], env=git_environment(root), timeout=30, limit=4 * 1024 ** 2)


def git_identity(root: Path, field: str) -> str:
    expected = snapshot_record(root)[field]
    expression = 'HEAD' if field == 'commit' else 'HEAD^{tree}'
    actual = git_output(root, 'rev-parse', expression).decode().strip()
    if actual != expected:
        raise ValueError('controller snapshot ' + field + ' drift')
    return actual


def validate_git_storage(root: Path) -> None:
    """Bound traversal and reject links even inside the reconstructed .git."""
    count = total = 0
    for path in (root / '.git').rglob('*'):
        info = path.lstat()
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError('snapshot Git storage link/special file refused')
        count += 1
        total += info.st_size
        if count > 100000 or total > LIMIT:
            raise ValueError('snapshot Git storage bound')
    if (root / '.git' / 'objects' / 'info' / 'alternates').exists():
        raise ValueError('snapshot external object storage refused')


def verify_blob(root: Path, row: bytes) -> int:
    metadata, name = row.split(b'\t', 1)
    mode, kind, expected = metadata.split(b' ')
    relative = Path(os.fsdecode(name))
    if relative.is_absolute() or '..' in relative.parts or relative.parts[0] == '.git' or kind != b'blob':
        raise ValueError('snapshot tree path/type refused')
    path = root / relative
    if path.resolve(strict=True) != path or mode not in (b'100644', b'100755'):
        raise ValueError('snapshot tree symlink/special mode refused')
    payload = regular_read(path, LIMIT)
    executable = bool(path.stat().st_mode & 0o111)
    actual = hashlib.sha1(b'blob ' + str(len(payload)).encode() + b'\0' + payload).hexdigest()
    if actual != expected.decode() or executable != (mode == b'100755'):
        raise ValueError('snapshot committed blob/mode drift')
    return len(payload)


def validate_snapshot(root: Path) -> dict[str, str]:
    """Verify exact objects AND actual complete bytes, not only index timestamps."""
    record = snapshot_record(root)
    validate_git_storage(root)
    if git_identity(root, 'commit') != record['commit'] or git_identity(root, 'tree') != record['tree']:
        raise ValueError('snapshot identity drift')
    if git_output(root, 'rev-parse', '--show-toplevel').decode().strip() != str(root):
        raise ValueError('snapshot Git root escape')
    rows = git_output(root, 'ls-tree', '-rz', '--full-tree', 'HEAD').split(b'\0')
    verify_tree(root, rows)
    if git_output(root, 'status', '--porcelain=v1', '--untracked-files=all'):
        raise ValueError('snapshot dirty/untracked drift')
    return record


def verify_tree(root: Path, rows: list[bytes]) -> None:
    if len(rows) > 100001:
        raise ValueError('snapshot complete tree count bound')
    total = 0
    for row in rows:
        if row:
            total += verify_blob(root, row)
            if total > LIMIT:
                raise ValueError('snapshot complete tree byte bound')
