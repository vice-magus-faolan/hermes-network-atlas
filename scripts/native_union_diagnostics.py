# SPDX-License-Identifier: GPL-3.0-or-later
"""Read bounded public source/cache evidence; never resolve, install or select.

Opaque uv metadata is evidence, not decoded proof of freshness/authentication.
Callers supply only disposable public producer/consumer roots, never live homes.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import tomllib

from docker_evidence import regular_read

REPORT_LIMIT = 8 * 1024
ENTRY_LIMIT = 100000
CACHE_BYTES = 2 * 1024 ** 3
METADATA_LIMIT = 128 * 1024
DETAIL_LIMIT = 8


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_identity(path: Path, limit: int) -> dict:
    data = regular_read(path, limit)
    return {'bytes': len(data), 'sha256': digest(data)}


def source_snapshot(source: Path) -> dict:
    """Actual literal settings/lock inputs, not a fabricated generated recipe."""
    project = regular_read(source / 'pyproject.toml', METADATA_LIMIT)
    lock = regular_read(source / 'uv.lock', 8 * 1024 ** 2)
    document = tomllib.loads(project.decode('utf-8-sig'))
    resolved = tomllib.loads(lock.decode('utf-8-sig'))
    options = resolved.get('options', {})
    lock_quarantines = options.get('exclude-newer-package', {})
    uv = document.get('tool', {}).get('uv', {})
    quarantines = uv.get('exclude-newer-package', {})
    extras = document.get('project', {}).get('optional-dependencies', {}).get('kittentts', [])
    return {'path': str(source), 'pyproject': {'bytes': len(project), 'sha256': digest(project)},
            'lock': {'bytes': len(lock), 'sha256': digest(lock)},
            'settings': {'exclude-newer': uv.get('exclude-newer'),
                         'exclude-newer-package-count': len(quarantines),
                         'exclude-newer-package-sha256': digest(json.dumps(quarantines, sort_keys=True).encode())},
            'lock_options': {'exclude-newer': options.get('exclude-newer'),
                             'exclude-newer-span': options.get('exclude-newer-span'),
                             'exclude-newer-package-count': len(lock_quarantines),
                             'exclude-newer-package-sha256': digest(json.dumps(lock_quarantines, sort_keys=True).encode())},
            'kittentts_requirements': extras,
            'kittentts_lock': [{'name': row['name'], 'version': row.get('version'), 'source': row.get('source')}
                              for row in resolved.get('package', []) if row.get('name') == 'kittentts']}


def cache_entry(path: Path, root: Path) -> dict:
    relative = path.relative_to(root).as_posix()
    if len(relative.encode()) > 512:
        raise ValueError('cache path bound')
    info = path.lstat()
    row = {'path': relative, 'bytes': info.st_size, 'mtime_ns': info.st_mtime_ns,
           'mode': stat.S_IMODE(info.st_mode)}
    if stat.S_ISLNK(info.st_mode):
        row.update(type='symlink', target=os.readlink(path))
    elif stat.S_ISREG(info.st_mode):
        row['type'] = 'file'
    elif stat.S_ISDIR(info.st_mode):
        row['type'] = 'directory'
    else:
        raise ValueError('cache special type refused')
    return row


def detail(path: Path, row: dict, remaining: int) -> int:
    """Hash only relevant small actual files, retain a bounded opaque prefix."""
    if row['type'] != 'file' or row['bytes'] > METADATA_LIMIT:
        return remaining
    data = regular_read(path, METADATA_LIMIT)
    row['sha256'] = digest(data)
    prefix = data[:min(512, remaining)]
    row.update(prefix_base64=base64.b64encode(prefix).decode(), prefix_bytes=len(prefix),
               metadata_complete=len(prefix) == len(data))
    return remaining - len(prefix)


def cache_snapshot(root: Path) -> dict:
    """Summarize every cache entry without following uv's archive symlinks."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError('actual nonsymlink cache required')
    deadline = time.monotonic() + 10
    ledger = hashlib.sha256()
    buckets, relevant = {}, []
    count = size = matching = 0
    remaining = 1024
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(dirs + files):
            path = Path(directory) / name
            row = cache_entry(path, root)
            count += 1
            size += row['bytes'] if row['type'] == 'file' else 0
            if count > ENTRY_LIMIT or size > CACHE_BYTES or time.monotonic() > deadline:
                raise ValueError('cache count/byte/deadline bound')
            ledger.update(json.dumps(row, sort_keys=True).encode() + b'\n')
            bucket = row['path'].split('/')[0]
            buckets[bucket] = buckets.get(bucket, 0) + 1
            if len(buckets) > 64:
                raise ValueError('cache bucket count bound')
            if 'kittentts' in row['path'].lower() and row['type'] != 'directory':
                matching += 1
                if len(relevant) < DETAIL_LIMIT:
                    remaining = detail(path, row, remaining)
                    relevant.append(row)
    flags = os.statvfs(root).f_flag
    return {'path': str(root), 'entries': count, 'file_bytes': size, 'buckets': buckets,
            'identity_sha256': ledger.hexdigest(), 'statvfs_flags': flags,
            'kittentts_matching_entries': matching, 'kittentts': relevant,
            'kittentts_omitted_entries': matching - len(relevant),
            'metadata_interpretation': 'opaque bytes; cache freshness/key sufficiency UNKNOWN'}


def snapshot(source: Path, cache: Path, *, member: Path | None = None,
             workspace: Path | None = None) -> dict:
    report = {'native_acceptance': False, 'diagnostics_only': True, 'exact_cache_deficiency': 'UNKNOWN',
              'source': source_snapshot(source), 'cache': cache_snapshot(cache)}
    if member is not None:
        report['member_path'] = str(member)
        report['member'] = {name: file_identity(member / name, METADATA_LIMIT)
                            for name in ('plugin.yaml', 'plugin.yml', 'pyproject.toml')
                            if (member / name).exists()}
    if workspace is not None:
        report['actual_selected_workspace'] = source_snapshot(workspace)
    return report


def emit(report: dict, writer) -> None:
    """One encoded cap shared by producer stdout and consumer file evidence."""
    payload = json.dumps(report, sort_keys=True)
    if len(payload.encode()) + 1 > REPORT_LIMIT:
        raise ValueError('union diagnostic report bound')
    writer(report)


def retain_producer(seed: Path, phase: str, report: dict) -> None:
    """Incremental private fixed-phase file, independently exported on failure."""
    if phase not in {'before-warm', 'after-warm', 'after-warm-failure'}:
        raise ValueError('fixed producer phase required')
    path = seed / 'union-diagnostics.json'
    previous = json.loads(regular_read(path, 32 * 1024)) if path.exists() else {}
    if phase in previous or len(previous) >= 2:
        raise ValueError('producer phase repeated/count bound')
    previous[phase] = report
    payload = json.dumps(previous, sort_keys=True).encode()
    if len(payload) > 32 * 1024:
        raise ValueError('producer diagnostic aggregate bound')
    pending = seed / 'union-diagnostics.pending'
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
        pending.replace(path)
    finally:
        pending.unlink(missing_ok=True)
