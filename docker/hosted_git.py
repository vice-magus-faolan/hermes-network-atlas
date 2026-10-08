# SPDX-License-Identifier: GPL-3.0-or-later
"""Prepare only the evidenced immutable Git source, never consumer selections.

Online union locking may use GitHub static metadata without materializing a Git
commit usable offline. A no-deps install into an owned disposable target forces
source preparation; an independent empty-target offline replay must then pass.
Only uv writes its cache. PEP 610 and real Git objects are read back, not invented.
"""
from __future__ import annotations

from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import time
import tomllib

from acquisition_support import audited_run, bounded_run
from docker_evidence import regular_read
from hosted_contract import container_setup_guard

URL = 'https://github.com/NousResearch/misaki.git'
COMMIT = 'f03fd2be7346952a83d3d4845c217fc7667f322d'
REQUIREMENT = 'misaki @ git+' + URL + '@' + COMMIT
DECLARATION = ('misaki[en] @ git+' + URL + '@' + COMMIT +
               " ; (platform_machine != 'ARM64' or sys_platform != 'win32') and "
               "(platform_machine != 'x86_64' or sys_platform != 'darwin')")
REPORT_LIMIT = 32 * 1024
TARGET_BYTES = 64 * 1024 ** 2
TARGET_ENTRIES = 4096
CACHE_BYTES = 2 * 1024 ** 3
CACHE_ENTRIES = 100000
DEADLINE = 240


def source_contract(core: Path) -> dict:
    """Bind preparation to the unchanged literal core declaration and lock."""
    project = regular_read(core / 'pyproject.toml', 128 * 1024)
    lock = regular_read(core / 'uv.lock', 8 * 1024 ** 2)
    document = tomllib.loads(project.decode('utf-8-sig'))
    rows = tomllib.loads(lock.decode('utf-8-sig')).get('package', [])
    requirements = document['project']['optional-dependencies']['kittentts']
    matches = [row for row in rows if row.get('name') == 'misaki']
    expected = {'git': URL + '?rev=' + COMMIT + '#' + COMMIT}
    if requirements.count(DECLARATION) != 1 or len(matches) != 1 or matches[0].get('source') != expected or matches[0].get('version') != '0.9.4':
        raise ValueError('literal immutable Misaki declaration/lock required')
    return {'requirement': REQUIREMENT, 'declaration': DECLARATION,
            'core_project_sha256': hashlib.sha256(project).hexdigest(),
            'core_lock_sha256': hashlib.sha256(lock).hexdigest(), 'version': matches[0]['version']}


def usage(root: Path, *, entries: int, byte_limit: int) -> dict:
    """Bound a cooperative read interval, without following cache archive links."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError('nonsymlink preparation/cache root required')
    count = size = 0
    deadline = time.monotonic() + 10
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            info = (Path(directory) / name).lstat()
            count += 1
            size += info.st_size if stat.S_ISREG(info.st_mode) else 0
            if count > entries or size > byte_limit or time.monotonic() > deadline:
                raise ValueError('Git preparation entry/byte/read deadline bound')
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                raise ValueError('Git preparation special type refused')
    return {'entries': count, 'file_bytes': size}


def installed_identity(target: Path, expected_version: str) -> dict:
    """Read the sole installed distribution and genuine uv-authored PEP 610."""
    measured = usage(target, entries=TARGET_ENTRIES, byte_limit=TARGET_BYTES)
    distributions = sorted(target.glob('*.dist-info'))
    if len(distributions) != 1 or distributions[0].is_symlink():
        raise ValueError('only the narrow prepared Misaki distribution is permitted')
    metadata = regular_read(distributions[0] / 'METADATA', 128 * 1024)
    parsed = BytesParser().parsebytes(metadata)
    if parsed.get_all('Name') != ['misaki'] or parsed.get_all('Version') != [expected_version]:
        raise ValueError('prepared distribution name/version differs from core lock')
    origin = regular_read(distributions[0] / 'direct_url.json', 8192)
    record = json.loads(origin)
    expected = {'url': URL, 'vcs_info': {'vcs': 'git', 'commit_id': COMMIT, 'requested_revision': COMMIT}}
    if record != expected:
        raise ValueError('actual prepared Git URL/commit/revision mismatch')
    return dict(measured, version=expected_version, direct_url=record,
                metadata_sha256=hashlib.sha256(metadata).hexdigest(),
                direct_url_sha256=hashlib.sha256(origin).hexdigest())


def install_argv(uv: Path, python: Path, cache: Path, target: Path, *, offline: bool) -> list[str]:
    """Pinned supported uv CLI: no extras, deps, system install or alternate URL."""
    argv = [str(uv), 'pip', 'install', '--no-config', '--no-deps', '--no-python-downloads',
            '--python', str(python), '--cache-dir', str(cache), '--target', str(target),
            '--link-mode', 'copy', REQUIREMENT]
    return [*argv, '--offline'] if offline else argv


def retain(seed: Path, report: dict) -> None:
    """Incremental small failure-stage provenance; never a native acceptance receipt."""
    payload = json.dumps(report, sort_keys=True).encode()
    if len(payload) > REPORT_LIMIT:
        raise ValueError('Git preparation report bound')
    pending = seed / 'git-preparation.pending'
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
        pending.replace(seed / 'git-preparation.json')
    finally:
        pending.unlink(missing_ok=True)


def runner_for(cache: Path, temporary: Path, deadline: float, environment: dict):
    """Existing owned-child audit/reaping, shared deadline and polled resource caps."""
    next_sample = 0.0
    def poll():
        nonlocal next_sample
        now = time.monotonic()
        if now >= deadline:
            raise TimeoutError('Git preparation aggregate deadline')
        if now >= next_sample:
            usage(cache, entries=CACHE_ENTRIES, byte_limit=CACHE_BYTES)
            usage(temporary, entries=TARGET_ENTRIES * 2, byte_limit=TARGET_BYTES * 2)
            next_sample = time.monotonic() + 1
    def runner(argv, cwd, **kwargs):
        poll()
        kwargs.update(timeout=min(120, max(0, deadline - time.monotonic())),
                      limit=1024 ** 2, poll=poll, env=environment)
        result = bounded_run(argv, cwd, **kwargs)
        poll()
        return result
    return runner


def git_identity(cache: Path, run) -> dict:
    """Read immutable commit objects through Git, never decode/edit opaque uv keys."""
    databases = cache / 'git-v0/db'
    if databases.is_symlink() or not databases.is_dir():
        raise ValueError('actual uv Git database absent')
    repositories = sorted(databases.iterdir())
    if not 1 <= len(repositories) <= 8:
        raise ValueError('bounded actual Git database count required')
    for repository in repositories:
        objects = repository / '.git'
        if repository.is_symlink() or not repository.is_dir() or objects.is_symlink() or not objects.is_dir():
            raise ValueError('nonsymlink Git database required')
        try:
            commit = run(['git', '--no-replace-objects', '--git-dir', str(objects), 'cat-file', 'commit', COMMIT])
        except RuntimeError:
            continue  # Other real union repositories need not contain this commit.
        data = commit.encode()
        identity = hashlib.sha1(b'commit ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        tree = re.match(r'tree ([0-9a-f]{40})\n', commit)
        if identity != COMMIT or tree is None:
            raise ValueError('actual immutable Git commit object mismatch')
        return {'database': repository.relative_to(cache).as_posix(), 'commit': identity,
                'tree': tree.group(1), 'commit_bytes': len(data), 'commit_sha256': hashlib.sha256(data).hexdigest()}
    raise ValueError('required immutable Git commit absent from actual uv databases')


def dispose(temporary: Path, seed: Path) -> None:
    """Only the exclusively created fixed preparation directory is cleanup-owned."""
    if temporary != seed / 'git-preparation' or temporary.is_symlink() or not temporary.is_dir():
        raise ValueError('owned Git preparation cleanup identity drift')
    shutil.rmtree(temporary)
    if temporary.exists():
        raise ValueError('Git preparation cleanup residue')


def prepare(core: Path, seed: Path) -> dict:
    """Hosted-only narrow acquisition + fresh-target offline replay, then disposal."""
    container_setup_guard()  # Before PM import, filesystem or acquisition effects.
    contract = source_contract(core)
    from pm._uv import _toolchain
    from pm.environment import _base_environment
    tools = _toolchain(realize=False)
    if tools is None or any(not path.resolve().is_relative_to(seed / 'tools') for path in tools):
        raise ValueError('existing pinned contained PM toolchain required')
    uv, python = tools
    cache = seed / 'hermes/cache/uv'
    cache.mkdir(parents=True, exist_ok=True)
    temporary = seed / 'git-preparation'
    temporary.mkdir(mode=0o700)  # Exclusive, no replacement/reuse/cleanup on refusal.
    report = {'schema': 1, 'native_acceptance': False, 'contract': contract, 'stage': 'started',
              'offline_union_proven': False, 'cleanup_verified': False, 'commands': []}
    original = None
    try:
        retain(seed, report)
        report['cache_before'] = usage(cache, entries=CACHE_ENTRIES, byte_limit=CACHE_BYTES)
        runner = runner_for(cache, temporary, time.monotonic() + DEADLINE, _base_environment())
        def run(argv):
            return audited_run(argv, temporary, runner=runner)
        for phase in ('online', 'offline'):
            target = temporary / phase
            target.mkdir(mode=0o700)
            argv = install_argv(uv, python, cache, target, offline=phase == 'offline')
            report.update(stage=phase + '-install')
            report['commands'].append(argv)
            retain(seed, report)
            run(argv)
            report[phase] = installed_identity(target, contract['version'])
            retain(seed, report)
        report['git'] = git_identity(cache, run)
        if report['online']['metadata_sha256'] != report['offline']['metadata_sha256']:
            raise ValueError('independent offline preparation metadata differs')
        report['cache_after'] = usage(cache, entries=CACHE_ENTRIES, byte_limit=CACHE_BYTES)
        report.update(stage='complete', narrow_offline_replay=True)
    except BaseException as exc:
        original = exc
        report.update(error=type(exc).__name__, message=str(exc)[:512])
        raise
    finally:
        finish(temporary, seed, report, original)
    return report


def finish(temporary: Path, seed: Path, report: dict, original: BaseException | None) -> None:
    """Cleanup/export failures remain secondary to the actual preparation failure."""
    errors = []
    try:
        dispose(temporary, seed)
        report['cleanup_verified'] = True
    except BaseException as exc:
        report['cleanup_error'] = type(exc).__name__
        errors.append(exc)
    try:
        retain(seed, report)
    except BaseException as exc:
        errors.append(exc)
    if errors:
        if original is None:
            raise errors[0]
        for exc in errors:
            original.add_note('Git preparation cleanup/export failed: ' + type(exc).__name__)


def require_complete(report: dict) -> None:
    """Fail closed on missing success provenance; flags alone are not evidence."""
    expected = {'schema': 1, 'stage': 'complete', 'narrow_offline_replay': True,
                'cleanup_verified': True, 'native_acceptance': False, 'offline_union_proven': False}
    if any(type(report.get(key)) is not type(value) or report[key] != value for key, value in expected.items()):
        raise ValueError('complete disposed offline Git preparation required')
    contract = report.get('contract', {})
    if contract.get('requirement') != REQUIREMENT or contract.get('declaration') != DECLARATION or contract.get('version') != '0.9.4':
        raise ValueError('complete exact Git source contract required')
    require_hashes(contract, ('core_project_sha256', 'core_lock_sha256'))
    git = report.get('git', {})
    if git.get('commit') != COMMIT or not re.fullmatch('[0-9a-f]{40}', git.get('tree', '')):
        raise ValueError('complete immutable Git object provenance required')
    require_hashes(git, ('commit_sha256',))
    require_installed_proof(report)
    require_commands(report)
    for name in ('cache_before', 'cache_after'):
        require_measurement(report.get(name, {}), CACHE_ENTRIES, CACHE_BYTES)


def require_hashes(row: dict, names: tuple[str, ...]) -> None:
    for name in names:
        if not isinstance(row.get(name), str) or not re.fullmatch('[0-9a-f]{64}', row[name]):
            raise ValueError('complete Git preparation hash provenance required')


def require_installed_proof(report: dict) -> None:
    expected_origin = {'url': URL, 'vcs_info': {'vcs': 'git', 'commit_id': COMMIT, 'requested_revision': COMMIT}}
    for phase in ('online', 'offline'):
        row = report.get(phase, {})
        if row.get('direct_url') != expected_origin or row.get('version') != '0.9.4':
            raise ValueError('complete independent prepared origin/version required')
        require_hashes(row, ('metadata_sha256', 'direct_url_sha256'))
        require_measurement(row, TARGET_ENTRIES, TARGET_BYTES)
    if report['online']['metadata_sha256'] != report['offline']['metadata_sha256']:
        raise ValueError('independent offline preparation metadata differs')


def require_measurement(row: dict, entries: int, byte_limit: int) -> None:
    for name, maximum in (('entries', entries), ('file_bytes', byte_limit)):
        if type(row.get(name)) is not int or not 0 <= row[name] <= maximum:
            raise ValueError('complete bounded Git preparation measurements required')


def require_commands(report: dict) -> None:
    commands = report.get('commands')
    if not isinstance(commands, list) or len(commands) != 2:
        raise ValueError('two genuine Git preparation commands required')
    for phase, argv in zip(('online', 'offline'), commands):
        if not isinstance(argv, list) or len(argv) < 15 or not all(isinstance(item, str) for item in argv):
            raise ValueError('bounded narrow Git preparation command required')
        uv, python = Path(argv[0]), Path(argv[7])
        if not all(path.is_absolute() and '..' not in path.parts and path.is_relative_to('/opt/seed/tools')
                   for path in (uv, python)):
            raise ValueError('contained pinned preparation tools required')
        expected = install_argv(uv, python, Path('/opt/seed/hermes/cache/uv'),
                                Path('/opt/seed/git-preparation') / phase, offline=phase == 'offline')
        if argv != expected:
            raise ValueError('exact no-deps independent offline preparation argv required')
