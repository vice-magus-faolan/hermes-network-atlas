#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Hosted fixed-tool execution evidence, not native admission.

Read only the authenticated PM lock and fixture tool facts. Never call PM's
installed_package: its selection path can heal executable bits. No acquisition,
chmod, alternate executable, shell, installer or permission fallback exists here.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys

from docker_evidence import BoundedDirectory, json_bytes, regular_read

FIXTURE = Path('/work/fixture')
EXPORT = Path('/export')
REPORT_LIMIT = 128 * 1024
FILE_LIMIT = 128 * 1024 ** 2
MOUNT_LIMIT = 256 * 1024


def error_record(exc: BaseException) -> dict:
    return {'error': type(exc).__name__, 'errno': getattr(exc, 'errno', None)}


def path_record(path: Path) -> dict:
    """Metadata only; never read target content through an unvalidated link."""
    row: dict[str, object] = {'path': str(path)}
    try:
        info = path.lstat()
        row.update(mode=oct(stat.S_IMODE(info.st_mode)), type=stat.S_IFMT(info.st_mode),
                   uid=info.st_uid, gid=info.st_gid, size=info.st_size,
                   device=info.st_dev, inode=info.st_ino)
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            if len(target) > 4096:
                raise ValueError('symlink text bound')
            row['symlink'] = target
    except (OSError, ValueError) as exc:
        row.update(error_record(exc))
    return row


def ancestors(path: Path) -> list[dict]:
    if not path.is_absolute() or len(path.parts) > 32 or len(str(path)) > 4096:
        raise ValueError('absolute bounded diagnostic path required')
    return [path_record(item) for item in [*reversed(path.parents), path]]


def mount_rows(payload: bytes) -> list[dict]:
    """Project kernel mountinfo without host sources, roots or unrelated mounts."""
    if len(payload) > MOUNT_LIMIT:
        raise ValueError('mountinfo byte bound')
    lines = payload.decode('utf-8', errors='strict').splitlines()
    if len(lines) > 4096:
        raise ValueError('mountinfo row bound')
    rows = []
    for line in lines:
        before, after = line.split(' - ', 1)
        left, right = before.split(), after.split()
        if len(left) < 6 or len(right) < 3:
            raise ValueError('malformed mountinfo')
        point = left[4]
        for escaped, value in ((r'\040', ' '), (r'\011', '\t'), (r'\012', '\n'), (r'\134', '\\')):
            point = point.replace(escaped, value)
        rows.append({'mountpoint': point, 'options': left[5].split(','), 'filesystem': right[0]})
    return rows


def filesystem_record(path: Path, rows: list[dict]) -> dict:
    matches = [row for row in rows if path.is_relative_to(Path(row['mountpoint']))]
    row = {'path': str(path), 'mount': max(matches, key=lambda item: len(item['mountpoint'])) if matches else None}
    try:
        flags = os.statvfs(path).f_flag
        row.update(statvfs_flags=flags, readonly=bool(flags & os.ST_RDONLY),
                   nosuid=bool(flags & os.ST_NOSUID), noexec=bool(flags & os.ST_NOEXEC))
    except OSError as exc:
        row.update(error_record(exc))
    return row


def selection(source: Path, tools: Path, name: str) -> tuple[Path, dict]:
    """Use actual native pin/facts/binary definitions, without PM's healing path."""
    from pm.environments import store_root
    from pm.lock import Facts, Lockfile
    from pm.registry import get_package
    from pm.store import Store
    if name not in ('uv', 'python') or store_root(source) != tools or tools.resolve(strict=True) != tools:
        raise ValueError('fixed contained native store required')
    # Bound parser inputs before native reads; complete source authentication
    # precedes these imports in main. No full facts/env dump is exported.
    regular_read(source / 'pm/lock.json', 512 * 1024)
    regular_read(tools / 'facts.json', 512 * 1024)
    lock, facts = Lockfile(source / 'pm/lock.json'), Facts(tools / 'facts.json', strict=True)
    fact = facts.get(name)
    version = lock.version(name)
    if not isinstance(version, str):
        raise ValueError('native public version pin absent')
    pins = [item['sha256'] for item in lock.artifacts(name, 'linux-x64')]
    package = get_package(name)
    expected_entry = package.store_entry(version, 'linux-x64')
    if not isinstance(fact, dict) or fact.get('entry') != expected_entry:
        raise ValueError('native selected entry differs from current pin')
    if not pins or not facts.installed(name, version, tools, ('linux-x64', tuple(pins))):
        raise ValueError('native selected version/target/artifact mismatch')
    binary = package.binary(Store(tools).entry(expected_entry), 'linux-x64')
    if binary is None or not binary.is_relative_to(tools):
        raise ValueError('native binary path escapes store')
    return binary, {'version': version, 'target': 'linux-x64', 'entry': expected_entry, 'archive_sha256': pins}


def executable_record(binary: Path, tools: Path) -> tuple[Path, dict]:
    row = {'requested_path': str(binary), 'ancestors': ancestors(binary)}
    resolved = binary.resolve(strict=True)
    row['resolved_path'] = str(resolved)
    if not resolved.is_relative_to(tools) or resolved == tools:
        raise ValueError('native binary symlink escapes store')
    row['resolved_ancestors'] = ancestors(resolved)
    # Nofollow and stable fd checks; no FIFO/device/unbounded content reads.
    row.update(binary_identity(resolved))
    if not row['elf']:
        raise ValueError('native Linux tool must be a regular ELF executable')
    return resolved, row


def binary_identity(path: Path) -> dict:
    """Stream bounded actual bytes; inspect ELF loader without executing it."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= FILE_LIMIT:
            raise ValueError('native binary type/size bound')
        digest, size = hashlib.sha256(), 0
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            while block := stream.read(1024 * 1024):
                size += len(block)
                if size > FILE_LIMIT:
                    raise ValueError('native binary grew past bound')
                digest.update(block)
        after = os.fstat(fd)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if size != before.st_size or identity(before) != identity(after):
            raise ValueError('native binary changed during hash')
        header = os.pread(fd, 64, 0)
        row = {'sha256': digest.hexdigest(), 'bytes': size, 'elf': header[:4] == b'\x7fELF'}
        row['loader'] = elf_loader(fd, header, size)
        return row
    finally:
        os.close(fd)


def elf_loader(fd: int, header: bytes, size: int) -> dict | None:
    """Bounded Linux-x64 ELF64 PT_INTERP metadata, no loader content reads."""
    if len(header) != 64 or header[:6] != b'\x7fELF\x02\x01':
        return None
    offset = struct.unpack_from('<Q', header, 32)[0]
    width, count = struct.unpack_from('<HH', header, 54)
    if width != 56 or count > 128 or offset + width * count > size:
        raise ValueError('ELF program header bound')
    for index in range(count):
        entry = os.pread(fd, width, offset + index * width)
        kind, _flags, position, _virtual, _physical, length = struct.unpack_from('<IIQQQQ', entry)
        if kind == 3:
            return loader_record(fd, position, length, size)
    return None


def loader_record(fd: int, position: int, length: int, size: int) -> dict:
    if not 1 < length <= 4096 or position + length > size:
        raise ValueError('ELF interpreter bound')
    data = os.pread(fd, length, position)
    if not data.endswith(b'\0') or b'\0' in data[:-1]:
        raise ValueError('ELF interpreter encoding')
    path = Path(data[:-1].decode('utf-8', errors='strict'))
    if not path.is_absolute() or not (path.is_relative_to('/lib') or path.is_relative_to('/lib64')) or '..' in path.parts:
        raise ValueError('fixed system loader metadata scope')
    return {'path': str(path), 'ancestors': ancestors(path)}


def version_probe(binary: Path, env: dict) -> dict:
    """Exactly one fixed --version attempt; same owned-child bound/reaping as CI."""
    from docker_acceptance import command
    argv = [str(binary), '--version']
    row: dict[str, object] = {'argv': argv, 'output_complete': True}
    output = b''
    try:
        output = command(argv, timeout=5, limit=64 * 1024, env=env)
        row['exit_code'] = 0
    except subprocess.CalledProcessError as exc:
        output = exc.output
        row['exit_code'] = exc.returncode
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        row.update(error_record(exc))
        row['output_complete'] = False
    row.update(output_captured_bytes=len(output), output_sha256=hashlib.sha256(output).hexdigest(),
               output_head=output[:2048].decode(errors='replace'), output_tail=output[-2048:].decode(errors='replace'))
    return row


def persist(report: dict, export: Path) -> None:
    payload = json_bytes(report)
    if len(payload) > REPORT_LIMIT:
        raise ValueError('tool diagnostic report bound')
    BoundedDirectory(export).write('tool-execution.json', payload)


def require_filesystem(row: dict, point: str, *, readonly: bool, noexec: bool, tmpfs: bool = False) -> None:
    """Kernel observations must agree with statvfs, not intended HostConfig."""
    mount = row.get('mount', {})
    options = set(mount.get('options', []))
    flags = row.get('statvfs_flags')
    if type(flags) is not int or 'error' in row:
        raise ValueError('effective filesystem evidence absent: ' + point)
    expected = {'readonly': readonly, 'noexec': noexec}
    actual = {'readonly': bool(flags & os.ST_RDONLY), 'noexec': bool(flags & os.ST_NOEXEC)}
    if actual != expected or any(row.get(key) is not value for key, value in expected.items()):
        raise ValueError('effective filesystem flags drift: ' + point)
    if ('ro' in options) != readonly or ('rw' in options) == readonly or ('noexec' in options) != noexec:
        raise ValueError('effective mountinfo flags drift: ' + point)
    if mount.get('mountpoint') != point:
        raise ValueError('effective mountpoint drift: ' + point)
    if tmpfs:
        require_tmpfs(row, point)


def require_tmpfs(row: dict, point: str) -> None:
    mount, flags = row['mount'], row['statvfs_flags']
    if (mount.get('filesystem') != 'tmpfs' or not {'nosuid', 'nodev'} <= set(mount['options'])
            or not flags & os.ST_NOSUID or not flags & os.ST_NODEV or row.get('nosuid') is not True):
        raise ValueError('effective private tmpfs protection drift: ' + point)


def require_tool(row: dict, name: str) -> None:
    """A contained current native tool must actually answer its fixed version probe."""
    requested, resolved = row.get('requested_path', ''), row.get('resolved_path', '')
    for path in (requested, resolved):
        if not path.startswith('/work/fixture/tools/') or '..' in Path(path).parts:
            raise ValueError('effective tool containment drift: ' + name)
    if 'error' in row or row.get('target') != 'linux-x64' or row.get('elf') is not True:
        raise ValueError('effective native tool evidence absent: ' + name)
    filesystem = row.get('filesystem', {})
    if filesystem.get('path') != resolved:
        raise ValueError('effective tool filesystem path drift: ' + name)
    require_filesystem(filesystem, '/work', readonly=False, noexec=False, tmpfs=True)
    require_version(row, name)


def require_version(row: dict, name: str) -> None:
    result = row.get('probe', {})
    requested = row['requested_path']
    if result.get('argv') != [requested, '--version'] or result.get('exit_code') != 0 or 'error' in result:
        raise ValueError('effective native version probe failed: ' + name)
    if result.get('output_complete') is not True or not 0 < result.get('output_captured_bytes', 0) <= 64 * 1024:
        raise ValueError('effective native version output absent: ' + name)
    version = row.get('version', '')
    prefix = 'uv ' + version if name == 'uv' else 'Python ' + version.split('+', 1)[0]
    text = result.get('output_head', '')
    if not version or not text.startswith(prefix) or not text[len(prefix):len(prefix) + 1].isspace():
        raise ValueError('effective native version identity drift: ' + name)


def require_execution(report: dict) -> None:
    """Reject incomplete kernel/probe proof before enable/canonical acceptance.

    This checks observations collected in this process after authenticated native
    selection, not a caller-provided receipt or proof of native installation.
    """
    if any(report.get(key) != 1000 for key in ('uid', 'euid', 'gid', 'egid')):
        raise ValueError('effective execution UID/GID drift')
    filesystems = report.get('filesystems', [])
    rows = {row.get('path'): row for row in filesystems}
    if set(rows) != {'/', '/work', '/tmp', '/opt', '/candidate'} or len(rows) != len(filesystems):
        raise ValueError('effective filesystem evidence incomplete')
    for point in ('/', '/candidate'):
        require_filesystem(rows[point], point, readonly=True, noexec=False)
    # /opt must be on the already checked read-only root, not an execution fallback.
    require_filesystem(rows['/opt'], '/', readonly=True, noexec=False)
    require_filesystem(rows['/work'], '/work', readonly=False, noexec=False, tmpfs=True)
    require_filesystem(rows['/tmp'], '/tmp', readonly=False, noexec=True, tmpfs=True)
    tools = report.get('tools', {})
    if set(tools) != {'uv', 'python'}:
        raise ValueError('effective native tool evidence incomplete')
    for name, row in tools.items():
        require_tool(row, name)


def check_execution(report: dict, export: Path) -> None:
    """Persist the failed predicate too; installer failure still takes precedence."""
    try:
        require_execution(report)
    except ValueError as exc:
        report['execution_contract'] = {'verified': False, 'error': str(exc)}
        try:
            persist(report, export)
        except Exception as secondary:
            exc.add_note('execution contract export failed: ' + type(secondary).__name__)
        raise
    report['execution_contract'] = {'verified': True, 'native_acceptance': False}
    persist(report, export)


def collect(source: Path, tools: Path, env: dict, export: Path) -> dict:
    """Incremental actual metadata before probes; probe denial never becomes success."""
    groups = os.getgroups()
    if len(groups) > 32:
        raise ValueError('diagnostic group bound')
    report = {'native_acceptance': False, 'permission_repair': False, 'tools': {},
              'uid': os.getuid(), 'euid': os.geteuid(), 'gid': os.getgid(), 'egid': os.getegid(), 'groups': groups}
    persist(report, export)
    with Path('/proc/self/mountinfo').open('rb') as stream:
        payload = stream.read(MOUNT_LIMIT + 1)
    rows = mount_rows(payload)
    report['filesystems'] = [filesystem_record(Path(path), rows) for path in ('/', '/work', '/tmp', '/opt', '/candidate')]
    persist(report, export)
    for name in ('uv', 'python'):
        row = report['tools'][name] = {}
        try:
            binary, pin = selection(source, tools, name)
            row.update(pin, requested_path=str(binary), ancestors=ancestors(binary))
            resolved, metadata = executable_record(binary, tools)
            row.update(metadata, filesystem=filesystem_record(resolved, rows))
            persist(report, export)  # actual path/hash/kernel evidence BEFORE exec
            row['probe'] = version_probe(binary, env)
        except (OSError, ValueError) as exc:
            row.update(error_record(exc))
        persist(report, export)
    return report


def main() -> int:
    if sys.argv[1:] or os.getuid() != 1000 or os.getgid() != 1000:
        raise ValueError('fixed hosted diagnostic invocation/UID required')
    source, tools = FIXTURE / 'hermes-source', FIXTURE / 'tools'
    if FIXTURE.resolve(strict=True) != FIXTURE or os.environ.get('HERMES_RUNTIME_DIR') != str(tools):
        raise ValueError('fixed fixture/runtime required')
    from acceptance_support import ROOT, git_head
    from caution_confirmation import verify_core
    from hosted_contract import require_hosted
    require_hosted(os.environ, workspace=ROOT, commit=git_head())
    verify_core(source)  # complete authenticated core before any native import
    sys.path.insert(0, str(source))
    report = collect(source, tools, dict(os.environ), EXPORT)
    check_execution(report, EXPORT)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
