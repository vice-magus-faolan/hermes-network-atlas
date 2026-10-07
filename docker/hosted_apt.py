# SPDX-License-Identifier: GPL-3.0-or-later
"""Genuine hosted APT proof, captured before normal slim-image cache cleanup.

Only the guarded public bootstrap calls this module. APT authenticates the
snapshot and archives; no-download install consumes the hash-checked cache.
Unchanged installed packages belong to the digest-pinned base, not invented
archive receipts. Resource polling is cooperative, not a filesystem quota.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat
import time

from acquisition_support import bounded_run
from hosted_contract import container_setup_guard

ROOTS = ('git', 'openssh-client', 'ca-certificates')
QUERY = ['dpkg-query', '-W', '-f=${Package}\t${Architecture}\t${Version}\t${Status}\n']
MAX_FILES = 256
MAX_BYTES = 256 * 1024 ** 2


def file_records(directory: Path, *, archives: bool) -> dict:
    """Stream actual regular bytes; exclude locks/partial directories, not errors."""
    result = {}
    total = 0
    for path in sorted(directory.iterdir()):
        if path.name in {'lock', 'partial', 'auxfiles'}:
            continue
        if archives and path.suffix != '.deb':
            raise ValueError('unexpected APT archive member')
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode):
            raise ValueError('nonregular APT proof member')
        size = path.stat().st_size
        total += size
        if size <= 0 or total > MAX_BYTES or len(result) >= MAX_FILES:
            raise ValueError('APT proof size/count bound')
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(65536), b''):
                digest.update(block)
        result[path.name] = {'sha256': digest.hexdigest(), 'bytes': size}
    return result


def cache_bounds(directory: Path) -> None:
    """Poll normal download/cache/partial usage while the owned APT child runs."""
    total = count = 0
    for path in directory.rglob('*'):
        if path.is_symlink():
            raise ValueError('APT cache symlink refused')
        if path.is_file():
            count += 1
            try:
                total += path.stat().st_size
            except FileNotFoundError:
                # Normal post-invoke hooks can remove a file between enumeration
                # and stat. This monitor is not the mandatory stable proof pass.
                continue
        if count > MAX_FILES or total > MAX_BYTES:
            raise ValueError('APT acquisition size/count bound')


def installed_packages(text: str) -> dict:
    """Accept only bounded, unique, fully configured dpkg package identities."""
    result = {}
    for line in text.splitlines():
        fields = line.split('\t')
        if len(fields) != 4:
            raise ValueError('malformed dpkg installed identity')
        name, arch, version, status = fields
        if status != 'install ok installed':
            # Removed/config-files packages cannot prove installed base state.
            continue
        validate_identity(name, arch, version)
        key = name + ':' + arch
        if key in result or len(result) >= 512:
            raise ValueError('duplicate/overbound dpkg identity')
        result[key] = version
    if not result:
        raise ValueError('empty installed base proof')
    return result


def validate_identity(name: str, arch: str, version: str) -> None:
    if (not re.fullmatch(r'[a-z0-9][a-z0-9+.-]{0,127}', name)
            or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,31}', arch)
            or not re.fullmatch(r'[A-Za-z0-9.+:~\-]{1,128}', version)):
        raise ValueError('malformed Debian package identity')


class AptProof:
    """Incremental diagnostics independent of success-only setup inventory."""
    def __init__(self, seed: Path, cwd: Path, cache: Path):
        self.seed, self.cwd, self.cache = seed, cwd, cache
        self.record = {'schema': 1, 'success': False, 'native_acceptance': False,
                       'commands': [], 'index_count': None, 'archive_count': None}
        self.lists: Path | None = None

    def save(self) -> None:
        payload = json.dumps(self.record, sort_keys=True, indent=2).encode()
        if len(payload) > 512 * 1024:
            raise ValueError('APT diagnostic export bound')
        temporary = self.seed / 'apt-diagnostics.pending'
        temporary.write_bytes(payload)
        temporary.replace(self.seed / 'apt-diagnostics.json')

    def command(self, stage: str, argv: list[str]) -> str:
        if len(self.record['commands']) >= MAX_FILES:
            raise ValueError('APT command count bound')
        row = {'stage': stage, 'argv': argv, 'state': 'started', 'exit_code': None}
        self.record['stage'] = stage
        self.record['commands'].append(row)
        self.save()
        start = time.monotonic()
        original = None
        try:
            output = bounded_run(argv, self.cwd, timeout=900, limit=128 * 1024,
                                 audit=row, poll=self.check_resources)
            row['state'] = 'completed'
            return output
        except BaseException as exc:
            original = exc
            row.update(state='failed', error=f'{type(exc).__name__}: {str(exc)[:4096]}')
            raise
        finally:
            row['elapsed_seconds'] = time.monotonic() - start
            self.flush(original)

    def check_resources(self) -> None:
        cache_bounds(self.cache)
        if self.lists is not None:
            cache_bounds(self.lists)

    def flush(self, original: BaseException | None) -> None:
        try:
            self.save()
        except BaseException as exc:
            if original is None:
                raise
            original.add_note(f'APT diagnostic save failed: {type(exc).__name__}')

    def collect(self, stage: str, directory: Path, *, archives: bool) -> dict:
        self.record['stage'] = stage
        self.save()
        rows = file_records(directory, archives=archives)
        kind = 'archive' if archives else 'index'
        self.record[kind + '_count'] = len(rows)
        self.record[kind + 's'] = rows
        self.save()
        return rows


def archive_identities(proof: AptProof, archives: dict) -> dict:
    result = {}
    for filename, row in archives.items():
        text = proof.command('archive-identity', ['dpkg-deb', '-f', str(proof.cache / filename),
                                                'Package', 'Architecture', 'Version'])
        # dpkg-deb prints named fields when multiple fields are requested.
        fields = dict(line.split(': ', 1) for line in text.splitlines())
        if set(fields) != {'Package', 'Architecture', 'Version'}:
            raise ValueError('malformed archive control proof')
        name, arch, version = fields['Package'], fields['Architecture'], fields['Version']
        validate_identity(name, arch, version)
        key = name + ':' + arch
        if key in result:
            raise ValueError('duplicate archive package identity')
        row.update(package=name, architecture=arch, version=version)
        result[key] = version
    return result


def bind_installed(before: dict, after: dict, acquired: dict) -> dict:
    """Every changed package must match an acquired archive; others match the base."""
    if not before.keys() <= after.keys():
        raise ValueError('unexpected base package removal')
    if any(after.get(key) != version for key, version in acquired.items()):
        raise ValueError('installed version differs from acquired archive')
    unchanged = {}
    for key, version in after.items():
        if key in acquired:
            continue
        if before.get(key) != version:
            raise ValueError('installed package absent from archive/base proof')
        unchanged[key] = version
    if not all(any(key.startswith(name + ':') for key in after) for name in ROOTS):
        raise ValueError('required package not installed')
    return unchanged


def provision(snapshot: str, seed: Path, cwd: Path, *, apt_root=Path('/etc/apt'),
              lists=Path('/var/lib/apt/lists'), cache=Path('/var/cache/apt/archives')) -> dict:
    container_setup_guard()  # Direct import callers have no local provisioning bypass.
    if snapshot != '20260919T000000Z':
        raise ValueError('exact Debian snapshot input required')
    proof = AptProof(seed, cwd, cache)
    try:
        return provision_steps(snapshot, apt_root, lists, proof)
    except BaseException as exc:
        proof.record['error'] = f'{type(exc).__name__}: {str(exc)[:4096]}'
        try:
            proof.save()
        except BaseException as secondary:
            exc.add_note(f'APT diagnostics failed: {type(secondary).__name__}')
        raise


def provision_steps(snapshot: str, apt_root: Path, lists: Path, proof: AptProof) -> dict:
    proof.lists = lists
    proof.record['snapshot'] = snapshot
    proof.command('config-before', ['apt-config', 'dump'])
    proof.record['hooks'] = hook_readback(apt_root / 'apt.conf.d')
    proof.save()
    source = apt_root / 'sources.list.d/debian.sources'
    source.write_text('Types: deb\nURIs: https://snapshot.debian.org/archive/debian/' + snapshot +
                      '/\nSuites: bookworm\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n')
    options = ['apt-get', '-o', 'APT::Sandbox::User=root', '-o', 'Acquire::Retries=0',
               '-o', 'Acquire::AllowInsecureRepositories=false', '-o', 'APT::Get::AllowUnauthenticated=false',
               '-o', 'Dir::Etc::sourcelist=' + str(source), '-o', 'Dir::Etc::sourceparts=-']
    before = installed_packages(proof.command('installed-before', QUERY))
    proof.record['installed_before'] = before
    proof.command('update', options + ['-o', 'APT::Update::Error-Mode=any', 'update'])
    indexes = proof.collect('index-proof', lists, archives=False)
    if not any(name.endswith('_InRelease') for name in indexes) or not any('_Packages' in name for name in indexes):
        raise ValueError('actual signed index/package-list proof absent')
    if file_records(proof.cache, archives=True):
        raise ValueError('preexisting archive cache cannot prove this acquisition')
    install = ['install', '-y', '--no-install-recommends', *ROOTS]
    proof.command('download', options + ['--download-only', *install])
    archives = proof.collect('archive-proof', proof.cache, archives=True)
    if not archives:
        raise ValueError('actual authenticated archive proof absent; no new archives acquired')
    acquired = archive_identities(proof, archives)
    proof.save()
    if file_records(proof.cache, archives=True) != {name: {key: row[key] for key in ('sha256', 'bytes')} for name, row in archives.items()}:
        raise ValueError('archive cache changed before install')
    proof.command('install', options + ['--no-download', *install])
    # Normal DPkg post-invoke cache cleanup is permitted: archive proof is already
    # retained. Index drift, unlike cache removal, invalidates the selection.
    if file_records(lists, archives=False) != indexes:
        raise ValueError('signed indexes changed during install')
    after = installed_packages(proof.command('installed-after', QUERY))
    proof.record['unchanged_base_packages'] = bind_installed(before, after, acquired)
    proof.record['installed'] = after
    proof.record['success'] = True
    proof.record['stage'] = 'complete'
    proof.save()
    return proof.record


def hook_readback(directory: Path) -> dict:
    """Read actual pinned-rootfs hook bytes, without disabling or editing them."""
    rows = {}
    total = 0
    for path in sorted(directory.iterdir()):
        if path.is_symlink() or not path.is_file():
            raise ValueError('nonregular APT config readback')
        total += path.stat().st_size
        if len(rows) >= 64 or total > 32768:
            raise ValueError('APT config readback bound')
        rows[path.name] = path.read_text()
    return rows
