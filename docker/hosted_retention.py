# SPDX-License-Identifier: GPL-3.0-or-later
"""Pack only the owned reconstructed core; account all retained bytes honestly.

No uv/cache edits, history fetching, object deletion or widened retention limits.
Git's literal shallow boundary preserves the originally absent parent history.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from acquisition_support import audited_run, bounded_run
from core_identity import source_manifest, require_identity, manifest_digest
from docker_evidence import regular_read
from hosted_contract import container_setup_guard

BYTE_LIMIT = 1024 ** 3
FILE_LIMIT = 100000
REPORT_LIMIT = 32 * 1024
OBJECT_LIMIT = 40000


def owned_layout(core: Path, seed: Path) -> None:
    """Refuse local/ambient repositories before any compaction or report effects."""
    container_setup_guard()
    if core != Path('/opt/seed/hermes-source') or seed != Path('/opt/seed'):
        raise ValueError('literal owned producer retention layout required')
    for path in (Path('/opt'), seed, core):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('owned nonsymlink producer retention directory required')


def retain(seed: Path, report: dict) -> None:
    """Incremental bounded private proof, independent of success-only inventory."""
    payload = json.dumps(report, sort_keys=True).encode()
    if len(payload) > REPORT_LIMIT:
        raise ValueError('retained inventory report bound')
    pending = seed / 'retained-inventory.pending'
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
        pending.replace(seed / 'retained-inventory.json')
    finally:
        pending.unlink(missing_ok=True)


def component(root: Path, path: Path) -> str:
    relative = path.relative_to(root).parts
    return 'hermes-source/.git' if relative[:2] == ('hermes-source', '.git') else relative[0]


def measure(root: Path, row: dict) -> None:
    """Complete stat-only accounting or explicit bounded prefix; never skip sources.

    Match the inherited regular non-symlink file semantics, including hardlink
    path bytes. Bound visited entries, component names and wall time separately.
    """
    row.update(files=0, bytes=0, entries=0, complete=False, components={})
    if root.is_symlink() or not root.is_dir():
        raise ValueError('nonsymlink retained root required')
    deadline = time.monotonic() + 10
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            info = path.lstat()
            row['entries'] += 1
            if row['entries'] > 100000 or time.monotonic() >= deadline:
                raise ValueError('retention accounting entry/read deadline bound')
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                raise ValueError('retention special file refused')
            if stat.S_ISREG(info.st_mode):
                account_file(row, component(root, path), info.st_size)
    row['complete'] = True


def walk_error(error: OSError) -> None:
    """A skipped unreadable directory is not complete retention accounting."""
    raise error


def account_file(row: dict, name: str, size: int) -> None:
    if name not in row['components'] and len(row['components']) >= 32:
        raise ValueError('retention component count bound')
    bucket = row['components'].setdefault(name, {'files': 0, 'bytes': 0})
    for value in (row, bucket):
        value['files'] += 1
        value['bytes'] += size


def git_layout(core: Path, commit: str) -> None:
    """Only an unmodified fresh reconstructed object store, never alternates/cache."""
    if any(key.startswith('GIT_') for key in os.environ):
        raise ValueError('ambient Git state refused before retention effects')
    git = core / '.git'
    if git.is_symlink() or not git.is_dir():
        raise ValueError('owned reconstructed Git directory required')
    for relative in ('objects/info/alternates', 'info/grafts', 'refs/replace'):
        path = git / relative
        if path.exists() or path.is_symlink():
            raise ValueError('alternate/replacement Git object authority refused')
    if regular_read(git / 'shallow', 128) != (commit + '\n').encode():
        raise ValueError('literal reconstructed shallow boundary required')
    for count, path in enumerate(git.rglob('*')):
        if count >= 100000 or path.is_symlink():
            raise ValueError('Git directory member/symlink bound')
    if list((git / 'objects/pack').iterdir()):
        raise ValueError('fresh loose reconstructed Git objects required')


def object_rows(output: str) -> dict:
    rows = {}
    for line in output.splitlines():
        match = re.fullmatch(r'([0-9a-f]{40}) (blob|tree|commit|tag) (0|[1-9][0-9]*)', line)
        if match is None or match[1] in rows or len(rows) >= OBJECT_LIMIT:
            raise ValueError('bounded unique actual Git object rows required')
        rows[match[1]] = (match[2], int(match[3]))
    if not rows:
        raise ValueError('actual Git objects absent')
    payload = json.dumps(rows, sort_keys=True).encode()
    return {'count': len(rows), 'sha256': hashlib.sha256(payload).hexdigest()}


def runner(core: Path):
    """Keep inherited child audit/reaping plus a shared 120-second pack deadline."""
    deadline = time.monotonic() + 120
    next_sample = 0.0
    def poll():
        nonlocal next_sample
        if time.monotonic() >= deadline:
            raise TimeoutError('core retention aggregate deadline')
        if time.monotonic() >= next_sample:
            row = {}
            measure(core / '.git', row)
            if row['bytes'] > 2 * 1024 ** 3:
                raise ValueError('core retention transient object byte bound')
            next_sample = time.monotonic() + 1
    def run(argv, cwd, **kwargs):
        poll()
        kwargs.update(timeout=min(60, max(0, deadline - time.monotonic())), limit=4 * 1024 ** 2, poll=poll)
        result = bounded_run(argv, cwd, **kwargs)
        poll()
        return result
    return lambda argv: audited_run(argv, core, runner=run)


def pack_objects(core: Path, commit: str, tree: str, report: dict) -> None:
    """Never repack-delete/prune history: only prune loose duplicates after proof.

    Full fsck checks actual object content hashes before and after packing.
    Batch-all-objects covers reachable AND unreachable objects; those not packed
    by refs remain loose. No expiry, gc, -d, shallow rewrite or parent synthesis.
    """
    run = runner(core)
    run(['git', 'fsck', '--full', '--no-reflogs', '--no-dangling'])
    if run(['git', 'rev-parse', 'HEAD', 'HEAD^{tree}']).splitlines() != [commit, tree]:
        raise ValueError('literal reconstructed commit/tree differs')
    argv = ['git', 'cat-file', '--batch-all-objects', '--batch-check=%(objectname) %(objecttype) %(objectsize)']
    report['objects_before'] = object_rows(run(argv))
    run(['git', '-c', 'pack.threads=1', '-c', 'pack.windowMemory=16m', 'repack', '-a', '-n', '--no-write-bitmap-index'])
    indices = sorted((core / '.git/objects/pack').glob('*.idx'))
    if len(indices) != 1 or indices[0].is_symlink():
        raise ValueError('one genuine reconstructed pack index required')
    run(['git', 'verify-pack', str(indices[0])])
    run(['git', 'fsck', '--full', '--no-reflogs', '--no-dangling'])
    run(['git', 'prune-packed'])  # ONLY duplicate loose objects already in verified pack
    report['objects_after'] = object_rows(run(argv))
    if report['objects_after'] != report['objects_before']:
        raise ValueError('complete actual Git object set/content differs after packing')
    if regular_read(core / '.git/shallow', 128) != (commit + '\n').encode():
        raise ValueError('original missing-history boundary changed')
    if run(['git', 'status', '--porcelain=v1', '--untracked-files=all']):
        raise ValueError('source/index drift after packing')


def compact_core(core: Path, seed: Path, commit: str, tree: str) -> dict:
    owned_layout(core, seed)
    if not re.fullmatch(r'[0-9a-f]{40}', commit) or not re.fullmatch(r'[0-9a-f]{40}', tree):
        raise ValueError('literal Git identity required')
    git_layout(core, commit)
    before_source = source_manifest(core)
    require_identity(before_source)
    report = {'stage': 'started', 'commit': commit, 'tree': tree, 'before': {}, 'after': {},
              'source_digest': manifest_digest(before_source)}
    original = None
    try:
        measure(core / '.git', report['before'])
        retain(seed, {'stage': 'compacting', 'compaction': report, 'native_acceptance': False})
        pack_objects(core, commit, tree, report)
        after_source = source_manifest(core)
        require_identity(after_source)
        if after_source != before_source:
            raise ValueError('complete source bytes/modes/symlinks differ after packing')
        measure(core / '.git', report['after'])
        report['stage'] = 'complete'
        return report
    except BaseException as exc:
        original = exc
        report.update(stage='failed', error=type(exc).__name__, message=str(exc)[:512])
        raise
    finally:
        try:
            retain(seed, {'stage': 'compacted' if original is None else 'failed', 'compaction': report, 'native_acceptance': False})
        except BaseException as exc:
            if original is None:
                raise
            original.add_note(f'retention diagnostic failed: {type(exc).__name__}')


def retained_inventory(seed: Path, verifier: Path, compaction: dict) -> dict:
    owned_layout(seed / 'hermes-source', seed)
    if verifier != Path('/opt/verifier') and seed == Path('/opt/seed'):
        raise ValueError('fixed verifier retention root required')
    report = {'stage': 'measuring', 'compaction': compaction, 'native_acceptance': False,
              'limits': {'bytes': BYTE_LIMIT, 'files': FILE_LIMIT}, 'seed': {}, 'verifier': {}, 'violations': []}
    original = None
    try:
        for name, root in (('seed', seed), ('verifier', verifier)):
            measure(root, report[name])
            for field, limit in (('bytes', BYTE_LIMIT), ('files', FILE_LIMIT)):
                if report[name][field] > limit:
                    report['violations'].append(name + ':' + field)
        retain(seed, report)  # exact complete component totals survive guard refusal
        if report['violations']:
            raise ValueError('public retained inventory bound')
        report['stage'] = 'complete'
        require_complete(report)
        return report
    except BaseException as exc:
        original = exc
        report.update(stage='failed', error=type(exc).__name__, message=str(exc)[:512])
        raise
    finally:
        try:
            retain(seed, report)
        except BaseException as exc:
            if original is None:
                raise
            original.add_note(f'retention diagnostic failed: {type(exc).__name__}')


def require_complete(report: dict) -> None:
    """Success provenance is mandatory; component accounting is not native proof."""
    if not isinstance(report, dict) or report.get('stage') != 'complete' or report.get('violations') != []:
        raise ValueError('complete retained inventory proof required')
    if report.get('limits') != {'bytes': BYTE_LIMIT, 'files': FILE_LIMIT}:
        raise ValueError('unchanged retained inventory limits required')
    compact = report.get('compaction')
    if not isinstance(compact, dict) or compact.get('stage') != 'complete' or not compact.get('objects_before') or compact.get('objects_before') != compact.get('objects_after'):
        raise ValueError('complete object-preserving compaction proof required')
    require_compaction(compact)
    for name in ('seed', 'verifier'):
        require_accounting(report.get(name))


def require_compaction(row: dict) -> None:
    for name in ('commit', 'tree'):
        if not isinstance(row.get(name), str) or not re.fullmatch(r'[0-9a-f]{40}', row[name]):
            raise ValueError('literal compaction commit/tree proof required')
    if not isinstance(row.get('source_digest'), str) or not re.fullmatch(r'[0-9a-f]{64}', row['source_digest']):
        raise ValueError('complete source digest proof required')
    objects = row['objects_before']
    if not isinstance(objects, dict) or type(objects.get('count')) is not int or not 1 <= objects['count'] <= OBJECT_LIMIT:
        raise ValueError('actual bounded object count required')
    if not isinstance(objects.get('sha256'), str) or not re.fullmatch(r'[0-9a-f]{64}', objects['sha256']):
        raise ValueError('complete actual object digest required')
    for name in ('before', 'after'):
        require_accounting(row.get(name))


def require_accounting(row: object) -> None:
    if not isinstance(row, dict) or row.get('complete') is not True:
        raise ValueError('complete actual component accounting required')
    require_totals(row)
    components = row.get('components')
    if not isinstance(components, dict) or len(components) > 32:
        raise ValueError('bounded actual components required')
    for item in components.values():
        if not isinstance(item, dict):
            raise ValueError('actual component totals required')
        require_totals(item)
    if sum(item['files'] for item in components.values()) != row['files'] or sum(item['bytes'] for item in components.values()) != row['bytes']:
        raise ValueError('component totals differ from complete retained totals')


def require_totals(row: dict) -> None:
    if type(row.get('files')) is not int or type(row.get('bytes')) is not int:
        raise ValueError('actual retained totals required')
    if not 0 <= row['files'] <= FILE_LIMIT or not 0 <= row['bytes'] <= BYTE_LIMIT:
        raise ValueError('public retained inventory bound')
