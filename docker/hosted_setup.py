#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Hosted PUBLIC prerequisite phase only; never import/execute candidate tests.

Apt verifies Debian signatures/index hashes. Pip resolves binary-only verifier
inputs from public PyPI, then exact report/index hashes authenticate bounded
wheel acquisition before native PM's offline verifier build. Native PM verifies
its pinned tools and resolves the real dependency-member union. The base keeps
only public core/tools/cache/verifier and compact provenance, never selections.
"""
from __future__ import annotations
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import time
import urllib.request
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from hosted_contract import container_setup_guard
from acquisition_support import bounded_run, finite_download, reconstruct_public_core
from base_setup import readable_seed, inventory
from hosted_apt import provision

PUBLIC = Path('/opt/inputs')
SEED = Path('/opt/seed')
CORE = SEED / 'hermes-source'
HERMES = 'f42f579cf8bac4918ac9599bece71618afadd846'
TREE = '008b644d38770b7de0835592ddaf19a708e2fa82'


COMMAND_LOG_LIMIT = 1024 ** 2
COMMAND_COUNT_LIMIT = 32
TERMINAL_ROW_LIMIT = 256 * 1024
COMMAND_ARGV_LIMIT = 8192


class CommandLog:
    """Reserve encoded terminal evidence before spawning; bound cumulative rows.

    A 32 KiB head/tail can expand sixfold in JSON (invalid UTF-8, controls,
    non-ASCII). Reserve 256 KiB, including bounded argv/metadata, for each
    terminal row. The 1 MiB process-local aggregate leaves traceback/headroom
    under the unchanged 4 MiB bootstrap exporter, without silently dropping rows.
    Nested wrapper output is captured by its parent's bounded command audit.
    """
    def __init__(self):
        self.bytes = 0
        self.commands = 0

    def begin(self, argv: list[str]) -> None:
        if not argv or len(argv) > 64 or any(not isinstance(item, str) for item in argv):
            raise ValueError('bounded public command argv required')
        row = {'public_command': argv, 'state': 'started'}
        size = len(json.dumps(row, sort_keys=True).encode()) + 1
        if size > COMMAND_ARGV_LIMIT:
            raise ValueError('public command argv diagnostic bound exceeded')
        if self.commands >= COMMAND_COUNT_LIMIT or self.bytes + size + TERMINAL_ROW_LIMIT > COMMAND_LOG_LIMIT:
            raise ValueError('public command diagnostic budget exhausted')
        self.commands += 1
        self.emit(row, limit=COMMAND_ARGV_LIMIT)

    def emit(self, row: dict, *, limit: int = TERMINAL_ROW_LIMIT) -> None:
        payload = json.dumps(row, sort_keys=True)
        size = len(payload.encode()) + 1
        if size > limit or self.bytes + size > COMMAND_LOG_LIMIT:
            raise ValueError('public command diagnostic row bound exceeded')
        # Consume before printing: a failed stream write cannot renew the budget.
        self.bytes += size
        print(payload, flush=True)


COMMAND_LOG = CommandLog()


def run(argv: list[str]) -> str:
    """Retain actual bounded phase/exit/output evidence in bootstrap.log."""
    COMMAND_LOG.begin(argv)
    audit: dict[str, object] = {'public_command': argv}
    started = time.monotonic()
    original = None
    try:
        output = bounded_run(argv, CORE, timeout=900, audit=audit)
        audit['state'] = 'complete'
        return output
    except BaseException as exc:
        original = exc
        audit.update(state='failed', error=type(exc).__name__)
        raise
    finally:
        audit['elapsed_seconds'] = time.monotonic() - started
        try:
            COMMAND_LOG.emit(audit)
        except BaseException as diagnostic_error:
            if original is None:
                raise
            original.add_note(f'command diagnostic failed: {type(diagnostic_error).__name__}')


def public_json(url: str) -> dict:
    value = urlsplit(url)
    if value.scheme != 'https' or value.hostname != 'pypi.org' or value.query or value.fragment:
        raise ValueError('public PyPI metadata required')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=30) as response:
        if response.geturl() != url:
            raise ValueError('metadata redirect refused')
        data = response.read(2 * 1024 ** 2 + 1)
    if len(data) > 2 * 1024 ** 2:
        raise ValueError('metadata bound')
    return json.loads(data)


def wheel_record(row: dict, metadata: dict) -> dict:
    info = row['download_info']
    matches = [item for item in metadata['urls'] if item['url'] == info['url']]
    if len(matches) != 1:
        raise ValueError('resolved artifact absent from public index')
    item = matches[0]
    if item['packagetype'] != 'bdist_wheel' or item['yanked'] or item['digests']['sha256'] != info['archive_info']['hashes']['sha256']:
        raise ValueError('public binary artifact hash/type differs from resolver')
    return {'url': item['url'], 'filename': item['filename'], 'compressed_bytes': item['size'],
            'sha256': item['digests']['sha256'], 'name': row['metadata']['name'], 'version': row['metadata']['version']}


def verifier(inputs: dict) -> list[dict]:
    downloads = SEED / 'wheelhouse'
    downloads.mkdir()
    # Resolver only: no installation/source builds before verifying artifacts.
    report = SEED / 'verifier-resolution.json'
    run([sys.executable, '-m', 'pip', 'install', '--dry-run', '--ignore-installed', '--only-binary=:all:',
         '--index-url', 'https://pypi.org/simple', '--disable-pip-version-check', '--retries', '0',
         '--timeout', '30', '--report', str(report), *inputs['verifier_requirements']])
    rows = json.loads(report.read_text())['install']
    if not 1 <= len(rows) <= 64:
        raise ValueError('verifier closure count bound')
    records = []
    total = 0
    for row in rows:
        name, version = row['metadata']['name'], row['metadata']['version']
        import re
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', name) or not re.fullmatch(r'[A-Za-z0-9_.+-]+', version):
            raise ValueError('literal public package identity required')
        metadata = public_json(f'https://pypi.org/pypi/{name}/{version}/json')
        record = wheel_record(row, metadata)
        total += record['compressed_bytes']
        if total > 128 * 1024 ** 2:
            raise ValueError('verifier artifact aggregate bound')
        finite_download(record, downloads, deadline=time.monotonic() + 120)
        records.append(record)
    run([sys.executable, '-m', 'pm.build_env', '--out', '/opt/verifier', '--wheelhouse', str(downloads),
         '--offline', *[part for requirement in inputs['verifier_requirements'] for part in ('--requirement', requirement)]])
    shutil.rmtree(downloads)
    return records


def apt(inputs: dict) -> dict:
    container_setup_guard()  # No direct-call/local bypass of the provisioning contract.
    snapshot = inputs['debian_snapshot']
    if snapshot != '20260919T000000Z':
        raise ValueError('exact Debian snapshot input required')
    return provision(snapshot, SEED, CORE)


def warm() -> None:
    container_setup_guard()  # BEFORE PM import, in the actual dispatcher too.
    sys.path.insert(0, str(CORE))
    import pm
    from pm.plugin_inputs import Members
    pm.sync_venv(explicit=True, plugins=Members([SEED / 'dependency-input']), project_root=CORE)
    from pm.environments import runtime_facts_path, selected_venv
    facts = json.loads(runtime_facts_path(CORE).read_text())
    lock = Path(facts['packages']['venv']['resolved_lock'])
    if not lock.resolve().is_relative_to(SEED):
        raise ValueError('real union lock escapes public setup state')
    shutil.copyfile(lock, SEED / 'resolved-union.lock')
    executable = selected_venv(CORE) / 'bin/python'
    packages = run([str(executable), str(PUBLIC / 'hosted_setup.py'), 'inventory'])
    (SEED / 'union-packages.json').write_text(packages)


def tool_artifacts(lock: dict) -> list[dict]:
    """Read actual native fetch-cache bytes BEFORE PM publication releases them."""
    result = []
    for name in ('python', 'uv'):
        item = lock['packages'][name]['artifacts']['linux-x64']
        archive = SEED / 'tools' / ('fetch-' + item['sha256']) / Path(urlsplit(item['url']).path).name
        if not 0 < archive.stat().st_size <= 128 * 1024 ** 2:
            raise ValueError('native tool archive byte bound')
        with archive.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != item['sha256']:
            raise ValueError('actual native tool archive differs from source lock')
        result.append({'name': name, 'url': item['url'], 'sha256': actual, 'bytes': archive.stat().st_size})
    return result


def fetch_tools() -> None:
    """Use pinned native acquisition, then retain hashes before genuine install."""
    container_setup_guard()
    sys.path.insert(0, str(CORE))
    from pm.store import Store
    lock = json.loads((CORE / 'pm/lock.json').read_text())
    artifacts = [lock['packages'][name]['artifacts']['linux-x64'] for name in ('python', 'uv')]
    deadline = time.monotonic() + 900
    def progress(done, total, _ranges):
        if done > 256 * 1024 ** 2 or total > 256 * 1024 ** 2 or time.monotonic() >= deadline:
            raise ValueError('native tool acquisition resource/deadline bound')
    store = Store(SEED / 'tools')
    with store.install_lock(), store.scratch() as scratch:
        store.fetch_many(artifacts, scratch, progress=progress)
        records = tool_artifacts(lock)
    (SEED / 'tool-archives.json').write_text(json.dumps(records, sort_keys=True))


def main() -> int:
    setup_status = container_setup_guard()  # Before filesystem, package, source, tool or PM setup.
    if sys.version_info[:3] != (3, 14, 7) or SEED.exists():
        raise ValueError('fresh pinned public setup required')
    inputs = json.loads((PUBLIC / 'dependencies.json').read_text())
    if inputs['hermes_commit'] != HERMES or inputs['python'] != '3.14.7':
        raise ValueError('public source/runtime input mismatch')
    CORE.mkdir(parents=True)
    apt_record = apt(inputs)
    with tarfile.open(PUBLIC / 'hermes.tar') as bundle:
        bundle.extractall(CORE, filter='data')
    reconstruct_public_core(CORE, PUBLIC / 'hermes.commit', HERMES, TREE)
    home = SEED / 'hermes'
    home.mkdir()
    (home / 'config.yaml').write_text('{"plugins":{"enabled":[],"disabled":[]}}')
    os.environ.update(HOME=str(SEED / 'user'), HERMES_HOME=str(home), TMPDIR=str(SEED),
                      HERMES_RUNTIME_DIR=str(SEED / 'tools'), UV_PYTHON_DOWNLOADS='never',
                      HERMES_MANAGED='false', HERMES_ENABLE_PROJECT_PLUGINS='0')
    # Native PM deletes fetch-<hash> entries on successful publication. Capture
    # their genuine bytes first; never infer an archive from installed facts.
    run([sys.executable, str(PUBLIC / 'hosted_setup.py'), 'fetch-tools'])
    # Named install already stops before venv sync. --tools-only forbids names
    # and selects a broader default closure (including optional browser tools).
    run([sys.executable, '-m', 'pm.cli', 'install', 'python', 'uv'])
    wheels = verifier(inputs)
    member = SEED / 'dependency-input'
    member.mkdir()
    (member / 'plugin.yaml').write_text(json.dumps({'name': 'dependency-input', 'version': '1.0.0',
                                                 'python_dependencies': inputs['plugin_python_dependencies']}))
    run(['/opt/verifier/bin/python', str(PUBLIC / 'hosted_setup.py'), 'warm'])
    lock = json.loads((CORE / 'pm/lock.json').read_text())
    if lock['packages']['uv']['version'] != inputs['uv']:
        raise ValueError('literal native uv version mismatch')
    record = {'inputs': inputs, 'bootstrap_process': setup_status, 'apt': apt_record, 'verifier_artifacts': wheels,
              'native_pm_lock_sha256': hashlib.sha256((CORE / 'pm/lock.json').read_bytes()).hexdigest(),
              'resolved_union_sha256': hashlib.sha256((SEED / 'resolved-union.lock').read_bytes()).hexdigest(),
              'union_packages': json.loads((SEED / 'union-packages.json').read_text()),
              'tools': {name: lock['packages'][name] for name in ('python', 'uv')},
              'actual_tool_artifacts': json.loads((SEED / 'tool-archives.json').read_text()),
              'source_archive_sha256': hashlib.sha256((PUBLIC / 'hermes.tar').read_bytes()).hexdigest()}
    shutil.move(home / 'cache/uv', SEED / 'uv-cache')
    for path in (home, member, SEED / 'user'):
        if path.exists():
            shutil.rmtree(path)
    compatibility = CORE / '.venv'
    if compatibility.is_symlink():
        compatibility.unlink()
    elif compatibility.exists():
        raise ValueError('unexpected reusable native environment directory')
    # Native PM tools contain genuine tool manifests/facts; source-scoped union
    # generations/facts/receipts are NOT reused by the acceptance consumer.
    if any(path.name in {'selected.json', 'admission.json', 'native-enabled.json'} for path in SEED.rglob('*')):
        raise ValueError('native candidate/selection state in reusable base')
    readable_seed(SEED)
    readable_seed(Path('/opt/verifier'))
    record['seed_usage'] = inventory(SEED)
    record['verifier_usage'] = inventory(Path('/opt/verifier'))
    payload = json.dumps(record, sort_keys=True, indent=2).encode()
    if len(payload) > 512 * 1024:
        raise ValueError('public inventory export bound')
    (SEED / 'inventory.json').write_bytes(payload)
    return 0


if __name__ == '__main__':
    if sys.argv[1:] == ['inventory']:
        print(json.dumps(sorted((item.metadata['Name'], item.version) for item in importlib.metadata.distributions())))
    elif sys.argv[1:] == ['warm']:
        warm()
    elif sys.argv[1:] == ['fetch-tools']:
        fetch_tools()
    elif not sys.argv[1:]:
        raise SystemExit(main())
    else:
        raise ValueError('unknown public setup mode')
