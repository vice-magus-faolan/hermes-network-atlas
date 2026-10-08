# SPDX-License-Identifier: GPL-3.0-or-later
"""Versioned Git-only CORE at rest; complete bounded materialization before native code.

The format changes physical retention, never source scope, objects, pins or PM.
Git archive is a binary source artifact, not a command log. No failed/partial
representation or consumer is reused, and no legacy format is silently promoted.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import selectors
import shutil
import signal
import stat
import subprocess
import tarfile
import time

from acceptance_support import HERMES_COMMIT
from core_identity import (CORE_TREE, CORE_SOURCE_DIGEST, SOURCE_BYTES, MEMBER_COUNT,
                           MANIFEST_BYTES, canonical, source_manifest, require_identity)
from docker_evidence import regular_read
from docker_snapshot import CONFIG

FORMAT = 'atlas-core-git-only-v1'
STORE = 'core-git'
RECORD = 'core-representation.json'
WORK_LIMIT = 2 * 1024 ** 3
REPORT_LIMIT = 32 * 1024


def environment() -> dict[str, str]:
    """No inherited Git authority, hooks, global attributes, helpers or network."""
    return {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LC_ALL': 'C',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': '/dev/null',
            'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_ATTR_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0',
            'GIT_OPTIONAL_LOCKS': '0'}


def paths(root: Path, *, owner: bool = False) -> dict:
    """Authenticate every metadata file, with no linked/alternate object storage."""
    if root.resolve(strict=True) != root or not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError('literal nonsymlink CORE Git root required')
    result = {}
    total = count = 0
    deadline = time.monotonic() + 10
    for path in root.rglob('*'):
        count += 1
        if count > MEMBER_COUNT or time.monotonic() >= deadline:
            raise ValueError('CORE Git metadata entry/deadline bound')
        info = path.lstat()
        if owner and info.st_uid != os.getuid():
            raise ValueError('owned CORE Git metadata required')
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('CORE Git linked/special metadata refused')
        total += info.st_size
        if total > SOURCE_BYTES:
            raise ValueError('CORE Git metadata byte bound')
        name = path.relative_to(root).as_posix()
        result[name] = [info.st_size, hashlib.sha256(regular_read(path, SOURCE_BYTES)).hexdigest()]
    return {'files': count, 'bytes': total, 'sha256': hashlib.sha256(canonical(result)).hexdigest()}


def storage(root: Path, *, owner: bool = False) -> dict:
    """Only reconstructed local config/shallow state; refuse extra authority."""
    result = paths(root, owner=owner)
    if regular_read(root / 'config', 1024) != CONFIG:
        raise ValueError('inert reconstructed CORE Git config required')
    if regular_read(root / 'shallow', 128) != (HERMES_COMMIT + '\n').encode():
        raise ValueError('original CORE shallow boundary required')
    for name in ('objects/info/alternates', 'objects/info/http-alternates', 'info/grafts',
                 'info/attributes', 'refs/replace', 'commondir', 'gitdir'):
        if (root / name).exists():
            raise ValueError('CORE alternate/attribute/replacement authority refused')
    if any(not path.name.endswith('.sample') for path in (root / 'hooks').iterdir()):
        raise ValueError('active CORE hooks refused')
    return result


def command(core: Path, args: list[str], deadline: float) -> str:
    from acquisition_support import audited_run, bounded_run
    def run(argv, cwd, **kwargs):
        if time.monotonic() >= deadline:
            raise TimeoutError('CORE representation command deadline')
        kwargs.update(env=environment(), timeout=min(60, deadline - time.monotonic()))
        return bounded_run(argv, cwd, **kwargs)
    return audited_run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.attributesFile=/dev/null', *args], core, runner=run)


def objects(core: Path, expected: dict, deadline: float) -> dict:
    """Actual fsck/content and ALL objects, including unreachable original objects."""
    from hosted_retention import object_rows
    command(core, ['fsck', '--full', '--no-reflogs', '--no-dangling'], deadline)
    if command(core, ['rev-parse', 'HEAD', 'HEAD^{tree}'], deadline).splitlines() != [HERMES_COMMIT, CORE_TREE]:
        raise ValueError('literal CORE representation commit/tree mismatch')
    actual = object_rows(command(core, ['cat-file', '--batch-all-objects', '--batch-check=%(objectname) %(objecttype) %(objectsize)'], deadline))
    if actual != expected:
        raise ValueError('complete CORE object identity mismatch')
    return actual


def require_record(row: dict) -> None:
    keys = {'format', 'commit', 'tree', 'source_digest', 'source_members', 'expanded_bytes',
            'objects', 'git_metadata', 'native_acceptance'}
    if not isinstance(row, dict) or set(row) != keys:
        raise ValueError('exact versioned CORE representation required')
    literals = {'format': FORMAT, 'commit': HERMES_COMMIT, 'tree': CORE_TREE,
                'source_digest': CORE_SOURCE_DIGEST, 'native_acceptance': False}
    if any(row.get(key) != value for key, value in literals.items()) or row['native_acceptance'] is not False:
        raise ValueError('old/mixed CORE representation refused')
    for key, limit in (('source_members', MEMBER_COUNT), ('expanded_bytes', SOURCE_BYTES)):
        if type(row[key]) is not int or not 0 < row[key] <= limit:
            raise ValueError('bounded complete expanded CORE totals required')
    require_ledger(row['objects'], {'count', 'sha256'}, 'count', 40000)
    require_ledger(row['git_metadata'], {'files', 'bytes', 'sha256'}, 'files', MEMBER_COUNT)
    if type(row['git_metadata']['bytes']) is not int or not 0 < row['git_metadata']['bytes'] <= SOURCE_BYTES:
        raise ValueError('bounded actual CORE metadata bytes required')


def require_ledger(row: dict, keys: set, count: str, limit: int) -> None:
    import re
    if not isinstance(row, dict) or set(row) != keys or type(row[count]) is not int or not 0 < row[count] <= limit:
        raise ValueError('complete bounded CORE ledger required')
    if not isinstance(row['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', row['sha256']):
        raise ValueError('actual CORE ledger digest required')


def producer_layout(core: Path, seed: Path) -> None:
    from hosted_contract import container_setup_guard
    container_setup_guard()
    if seed != Path('/opt/seed') or core != seed / 'hermes-source':
        raise ValueError('literal owned CORE producer layout required')
    for path in (Path('/opt'), seed, core, core / '.git'):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('owned nonsymlink CORE retirement root required')


def publish(core: Path, seed: Path, compaction: dict) -> dict:
    """Move ALL authenticated Git state; retire only this bootstrap's duplicate root.

    Publication has no fallback and no destructive repair of an existing store.
    On failure the bootstrap is failed; moved data remains in its private rootfs.
    """
    producer_layout(core, seed)
    destination = seed / STORE
    if destination.exists() or destination.is_symlink() or (seed / RECORD).exists():
        raise ValueError('fresh exclusive CORE representation required')
    report = {'format': FORMAT, 'stage': 'started', 'native_acceptance': False}
    original = None
    try:
        row = publish_checked(core, seed, compaction, report)
        report.update(stage='complete', representation=row)
        return row
    except BaseException as exc:
        original = exc
        report.update(stage='failed', error=type(exc).__name__, message=str(exc)[:512])
        raise
    finally:
        try:
            producer_diagnostic(seed, report)
        except BaseException as exc:
            if original is None:
                raise
            original.add_note('CORE producer diagnostic failed: ' + type(exc).__name__)


def producer_diagnostic(seed: Path, report: dict) -> None:
    payload = canonical(report)
    if len(payload) > REPORT_LIMIT:
        raise ValueError('CORE representation diagnostic bound')
    pending = seed / 'core-representation-diagnostic.pending'
    with pending.open('xb') as stream:
        stream.write(payload)
    pending.replace(seed / 'core-representation-diagnostic.json')


def publish_checked(core: Path, seed: Path, compaction: dict, report: dict) -> dict:
    from hosted_retention import measure
    destination = seed / STORE
    manifest = source_manifest(core)
    require_identity(manifest)
    if compaction.get('source_digest') != CORE_SOURCE_DIGEST or compaction.get('stage') != 'complete':
        raise ValueError('complete source-preserving compaction required')
    git_metadata = storage(core / '.git', owner=True)
    actual = objects(core, compaction['objects_after'], time.monotonic() + 120)
    report.update(stage='authenticated', objects=actual, git_metadata=git_metadata,
                  source_digest=CORE_SOURCE_DIGEST, source_members=len(manifest))
    producer_diagnostic(seed, report)
    expanded = {}
    measure(core, expanded)
    row = {'format': FORMAT, 'commit': HERMES_COMMIT, 'tree': CORE_TREE,
           'source_digest': CORE_SOURCE_DIGEST, 'source_members': len(manifest),
           'expanded_bytes': expanded['bytes'] - git_metadata['bytes'],
           'objects': actual, 'git_metadata': git_metadata, 'native_acceptance': False}
    require_record(row)
    destination.mkdir(mode=0o700)
    (core / '.git').rename(destination / '.git')
    if storage(destination / '.git', owner=True) != git_metadata:
        raise ValueError('moved complete CORE metadata differs')
    report['stage'] = 'moved'
    producer_diagnostic(seed, report)
    # Recheck complete bytes and ownership at the actual retirement boundary.
    producer_retirement(core, seed, manifest)
    shutil.rmtree(core)
    with (seed / RECORD).open('xb') as stream:
        stream.write(canonical(row))
    return row


def producer_retirement(core: Path, seed: Path, expected: dict) -> None:
    from hosted_contract import container_setup_guard
    container_setup_guard()
    if core != Path('/opt/seed/hermes-source') or seed != Path('/opt/seed'):
        raise ValueError('fixed duplicate CORE retirement required')
    for path in (seed, core):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('owned duplicate CORE retirement required')
    if (core / '.git').exists() or source_manifest(core) != expected:
        raise ValueError('duplicate CORE changed before retirement')


def seed_record(seed: Path) -> tuple[dict, dict]:
    if (seed / 'hermes-source').exists() or (seed / 'hermes-source').is_symlink():
        raise ValueError('mixed/legacy expanded CORE representation refused')
    row = json.loads(regular_read(seed / RECORD, REPORT_LIMIT))
    require_record(row)
    expected = json.loads(regular_read(seed / 'core-source-manifest.json', MANIFEST_BYTES))
    require_identity(expected)
    if len(expected) != row['source_members'] or storage(seed / STORE / '.git') != row['git_metadata']:
        raise ValueError('retained CORE representation metadata drift')
    if set(path.name for path in (seed / STORE).iterdir()) != {'.git'}:
        raise ValueError('unexpected retained CORE store members')
    return row, expected


def producer_store(seed: Path) -> None:
    from hosted_contract import container_setup_guard
    container_setup_guard()
    if seed != Path('/opt/seed'):
        raise ValueError('fixed owned representation accounting root required')
    for path in (seed, seed / STORE):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('owned representation accounting directory required')
    seed_record(seed)


def seal_inventory(seed: Path, verifier: Path, inventory: dict, compaction: dict, representation: dict) -> None:
    """Converge measured whole-root totals including BOTH final JSON files.

    Never treat a planned reserve as actual capacity. Before each write, include
    temporary overwrite bytes under the unchanged 1GiB/file limits. A finite
    failure refuses image publication rather than emitting a guessed fixed point.
    """
    from hosted_retention import retained_inventory, measure
    for _attempt in range(8):
        proof = retained_inventory(seed, verifier, compaction, representation)
        inventory.update(core_representation=representation, retained_inventory=proof,
                         seed_usage={key: proof['seed'][key] for key in ('files', 'bytes')},
                         verifier_usage={key: proof['verifier'][key] for key in ('files', 'bytes')})
        payload = canonical(inventory)
        if len(payload) > 512 * 1024:
            raise ValueError('public inventory export bound')
        write_inventory(seed, payload)
        actual = {}
        measure(seed, actual)
        if actual == proof['seed']:
            validate_inventory(inventory)
            return
    raise ValueError('actual self-inclusive CORE inventory did not converge')


def write_inventory(seed: Path, payload: bytes) -> None:
    from hosted_retention import measure, BYTE_LIMIT, FILE_LIMIT
    actual = {}
    measure(seed, actual)
    if actual['bytes'] + len(payload) > BYTE_LIMIT or actual['files'] + 1 > FILE_LIMIT:
        raise ValueError('actual transient inventory byte/file bound')
    pending = seed / 'inventory.pending'
    with pending.open('xb') as stream:
        stream.write(payload)
    pending.replace(seed / 'inventory.json')


def validate_inventory(inventory: dict) -> None:
    """Independent controller schema/identity/arithmetic; no flag-only success."""
    from hosted_retention import require_complete
    row = inventory.get('core_representation')
    require_record(row)
    proof = inventory.get('retained_inventory')
    require_complete(proof)
    if proof.get('core_representation') != row or proof['compaction']['objects_after'] != row['objects']:
        raise ValueError('CORE inventory representation/object proof mismatch')
    compact = proof['compaction']
    if (compact['commit'], compact['tree'], compact['source_digest']) != (HERMES_COMMIT, CORE_TREE, CORE_SOURCE_DIGEST):
        raise ValueError('CORE inventory pinned compaction mismatch')
    for key, name in (('seed_usage', 'seed'), ('verifier_usage', 'verifier')):
        if inventory.get(key) != {field: proof[name][field] for field in ('files', 'bytes')}:
            raise ValueError('actual inventory totals differ from complete physical proof')


def authenticate_inventory(seed: Path, verifier: Path) -> dict:
    from hosted_retention import measure
    inventory = json.loads(regular_read(seed / 'inventory.json', 512 * 1024))
    validate_inventory(inventory)
    row, _manifest = seed_record(seed)
    if row != inventory['core_representation']:
        raise ValueError('actual retained representation differs from inventory')
    for name, root in (('seed', seed), ('verifier', verifier)):
        actual = {}
        measure(root, actual)
        if actual != inventory['retained_inventory'][name]:
            raise ValueError('actual whole-root retained accounting drift')
    return inventory


def require_materialization(row: dict, inventory: dict, manifest: dict) -> None:
    """Controller validates actual restored source/objects against pinned base."""
    validate_inventory(inventory)
    base = inventory['core_representation']
    expected = {'format': FORMAT, 'stage': 'complete', 'native_acceptance': False,
                'source_digest': CORE_SOURCE_DIGEST, 'source_members': base['source_members'],
                'commit': HERMES_COMMIT, 'tree': CORE_TREE, 'objects': base['objects'],
                'git_metadata': base['git_metadata'], 'expanded_bytes': base['expanded_bytes']}
    if not isinstance(row, dict) or any(row.get(key) != value for key, value in expected.items()):
        raise ValueError('complete actual CORE materialization proof required')
    require_identity(manifest)
    if len(manifest) != base['source_members']:
        raise ValueError('complete restored CORE member count differs')
    for key, ceiling in (('archive_bytes', SOURCE_BYTES), ('peak_work_bytes', WORK_LIMIT)):
        if type(row.get(key)) is not int or not 0 < row[key] <= ceiling:
            raise ValueError('actual bounded CORE materialization accounting required')


def peak(work: Path, report: dict) -> None:
    """Whole consumer root plus actual tmpfs use; no hidden spool/partial exclusion."""
    from hosted_retention import measure
    if time.monotonic() < report.get('_next_sample', 0):
        return
    report['_next_sample'] = time.monotonic() + 1
    row = {}
    measure(work, row)
    fs = os.statvfs(work)
    allocated = (fs.f_blocks - fs.f_bfree) * fs.f_frsize
    report['peak_work_bytes'] = max(report.get('peak_work_bytes', 0), row['bytes'])
    report['peak_filesystem_used_bytes'] = max(report.get('peak_filesystem_used_bytes', 0), allocated)
    if row['bytes'] > WORK_LIMIT or row['entries'] > MEMBER_COUNT:
        raise ValueError('unchanged consumer work peak bound')


def archive(core: Path, spool: Path, deadline: float, report: dict, work: Path) -> None:
    """Stream binary Git tar under 256MiB/60s; independent 4MiB textual stderr."""
    from acquisition_support import COMMAND_LOG
    argv = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.attributesFile=/dev/null',
            'archive', '--format=tar', HERMES_COMMIT]
    COMMAND_LOG.begin(argv)
    audit: dict = {'public_command': argv}
    original = None
    try:
        stream_archive(argv, core, spool, min(deadline, time.monotonic() + 60), audit, report, work)
        audit['state'] = 'complete'
    except BaseException as exc:
        original = exc
        audit.update(state='failed', error=type(exc).__name__)
        raise
    finally:
        try:
            COMMAND_LOG.emit(audit)
        except BaseException as exc:
            if original is None:
                raise
            original.add_note('CORE archive audit failed: ' + type(exc).__name__)


def stream_archive(argv: list[str], core: Path, spool: Path, deadline: float,
                   audit: dict, report: dict, work: Path) -> None:
    child = subprocess.Popen(argv, cwd=core, env=environment(), stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    selector = selectors.DefaultSelector()
    output = bytearray()
    digest = hashlib.sha256()
    size = 0
    try:
        if child.stdout is None or child.stderr is None:
            raise RuntimeError('CORE archive output pipes absent')
        selector.register(child.stdout, selectors.EVENT_READ, 'source')
        selector.register(child.stderr, selectors.EVENT_READ, 'log')
        with spool.open('xb') as target:
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise TimeoutError('CORE binary archive deadline')
                for key, _ in selector.select(0.1):
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                    elif key.data == 'source':
                        size += len(block)
                        if size > SOURCE_BYTES:
                            raise ValueError('CORE binary archive byte bound')
                        target.write(block)
                        digest.update(block)
                    else:
                        output.extend(block)
                        if len(output) > 4 * 1024 ** 2:
                            raise ValueError('CORE archive textual output bound')
                peak(work, report)
        if child.wait(timeout=max(0.001, deadline - time.monotonic())):
            raise RuntimeError('CORE archive command failed; see bounded audit')
    finally:
        from acquisition_support import finish_command
        selector.close()
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        for stream in (child.stdout, child.stderr):
            if stream is not None:
                stream.close()
        # Reuse bounded log formatting without ever encoding the binary source.
        finish_command(child, selector, output, audit)
        audit.update(source_bytes=size, source_sha256=digest.hexdigest())
        report.update(archive_bytes=size, archive_sha256=digest.hexdigest())


def safe_member(member: tarfile.TarInfo, destination: Path) -> Path:
    name = PurePosixPath(member.name)
    if name.is_absolute() or '..' in name.parts or '.git' in name.parts or len(member.name.encode()) > 4096:
        raise ValueError('CORE archive member path refused')
    target = destination.joinpath(*name.parts)
    if target.parent.resolve() != target.parent:
        raise ValueError('CORE archive linked ancestor refused')
    if not (member.isfile() or member.isdir() or member.issym()):
        raise ValueError('CORE archive hardlink/special type refused')
    if member.issym():
        link = PurePosixPath(member.linkname)
        if link.is_absolute() or '..' in link.parts:
            raise ValueError('CORE archive link escape refused')
    return target


def extract(spool: Path, core: Path, deadline: float, report: dict, work: Path) -> None:
    names = set()
    total = 0
    with tarfile.open(spool, mode='r|') as bundle:
        for member in bundle:
            if time.monotonic() >= deadline:
                raise TimeoutError('CORE materialization deadline')
            target = safe_member(member, core)
            if member.name in names or len(names) >= MEMBER_COUNT:
                raise ValueError('CORE archive duplicate/member bound')
            names.add(member.name)
            total += member.size
            if total > SOURCE_BYTES or member.size < 0:
                raise ValueError('CORE archive expansion bound')
            extract_member(bundle, member, target, deadline)
            peak(work, report)
    report.update(expanded_bytes=total, archive_members=len(names))


def extract_member(bundle: tarfile.TarFile, member: tarfile.TarInfo, target: Path, deadline: float) -> None:
    if member.isdir():
        target.mkdir(mode=0o755, exist_ok=True)
    elif member.issym():
        target.symlink_to(member.linkname)
    else:
        stream = bundle.extractfile(member)
        if stream is None:
            raise ValueError('CORE archive regular stream absent')
        with stream, target.open('xb') as output:
            copy_source(stream, output, member.size, deadline)
        target.chmod(0o755 if member.mode & 0o111 else 0o644)


def copy_source(stream, output, remaining: int, deadline: float) -> None:
    while remaining:
        if time.monotonic() >= deadline:
            raise TimeoutError('CORE source write deadline')
        block = stream.read(min(65536, remaining))
        if not block:
            raise ValueError('truncated CORE source member')
        output.write(block)
        remaining -= len(block)


def restore(seed: Path, core: Path, work: Path, emit) -> dict:
    """No import of native code until exact full source/objects and peaks pass."""
    row, expected = seed_record(seed)
    report = {'format': FORMAT, 'stage': 'started', 'native_acceptance': False}
    emit(report)
    core.mkdir(mode=0o700)  # exclusive ownership is the cleanup authority
    spool = core / '.atlas-core-source.tar'
    deadline = time.monotonic() + 120
    original = None
    try:
        shutil.copytree(seed / STORE / '.git', core / '.git')
        if storage(core / '.git', owner=True) != row['git_metadata']:
            raise ValueError('copied complete CORE metadata differs')
        report['objects'] = objects(core, row['objects'], deadline)
        peak(work, report)
        archive(core, spool, deadline, report, work)
        extract(spool, core, deadline, report, work)
        # Owned metadata/spool/source only grow until this boundary. Force an
        # actual whole-root measurement while BOTH full spool and source exist,
        # even when a tiny reconstruction finishes between periodic samples.
        report.pop('_next_sample', None)
        peak(work, report)
        spool.unlink()
        actual = source_manifest(core)
        require_identity(actual)
        if actual != expected or report['expanded_bytes'] != row['expanded_bytes']:
            raise ValueError('restored full CORE source/accounting differs')
        if storage(core / '.git') != row['git_metadata']:
            raise ValueError('CORE metadata changed during materialization')
        if time.monotonic() >= deadline:
            raise TimeoutError('complete CORE materialization aggregate deadline')
        report.pop('_next_sample', None)
        peak(work, report)
        report.update(stage='complete', source_digest=CORE_SOURCE_DIGEST, source_members=len(actual),
                      commit=HERMES_COMMIT, tree=CORE_TREE, git_metadata=row['git_metadata'])
        return report
    except BaseException as exc:
        original = exc
        report.update(stage='failed', error=type(exc).__name__, message=str(exc)[:512])
        raise
    finally:
        finalize(core, spool, report, original, emit)


def finalize(core: Path, spool: Path, report: dict, original: BaseException | None, emit) -> None:
    try:
        report.pop('_next_sample', None)
        spool.unlink(missing_ok=True)
        if original is not None:
            if not stat.S_ISDIR(core.lstat().st_mode) or core.lstat().st_uid != os.getuid():
                raise ValueError('refuse unowned partial CORE cleanup')
            shutil.rmtree(core)
            report['partial_removed'] = not core.exists()
        emit(report)
    except BaseException as exc:
        if original is None:
            raise
        original.add_note('CORE materialization cleanup/export failed: ' + type(exc).__name__)
