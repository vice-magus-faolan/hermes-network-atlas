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
from hosted_contract import container_setup_guard, require_bootstrap_contract
from acquisition_support import bounded_run, finite_download, reconstruct_public_core
from base_setup import readable_seed, inventory

PUBLIC = Path('/opt/inputs')
SEED = Path('/opt/seed')
CORE = SEED / 'hermes-source'
HERMES = 'f42f579cf8bac4918ac9599bece71618afadd846'
TREE = '008b644d38770b7de0835592ddaf19a708e2fa82'


def run(argv: list[str]) -> str:
    return bounded_run(argv, CORE, timeout=900)


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
    require_bootstrap_contract()  # No direct-call/cache-only bypass of the full contract.
    snapshot = inputs['debian_snapshot']
    if snapshot != '20260919T000000Z':
        raise ValueError('exact Debian snapshot input required')
    sources = Path('/etc/apt/sources.list.d/debian.sources')
    sources.write_text('Types: deb\nURIs: https://snapshot.debian.org/archive/debian/' + snapshot +
                       '/\nSuites: bookworm\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n')
    logs = run(['apt-get', '-o', 'APT::Sandbox::User=root', '-o', 'Acquire::Retries=0', 'update'])
    logs += run(['apt-get', '-o', 'APT::Sandbox::User=root', '-o', 'Acquire::Retries=0', '-o', 'APT::Keep-Downloaded-Packages=true',
                 'install', '-y', '--no-install-recommends', 'git', 'openssh-client', 'ca-certificates'])
    indexes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
               for path in Path('/var/lib/apt/lists').iterdir() if path.is_file()}
    archives = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in Path('/var/cache/apt/archives').glob('*.deb')}
    if not indexes or not archives:
        raise ValueError('actual authenticated apt index/package proof absent')
    return {'snapshot': snapshot, 'indexes': indexes, 'archives': archives,
            'log': logs, 'installed': run(['dpkg-query', '-W'])}


def warm() -> None:
    container_setup_guard()  # BEFORE PM import, in the actual dispatcher too.
    require_bootstrap_contract()
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
    """Read actual native fetch-cache bytes against the unchanged public lock."""
    result = []
    for name in ('python', 'uv'):
        item = lock['packages'][name]['artifacts']['linux-x64']
        archive = SEED / 'tools' / ('fetch-' + item['sha256']) / Path(urlsplit(item['url']).path).name
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        if actual != item['sha256']:
            raise ValueError('actual native tool archive differs from source lock')
        result.append({'name': name, 'url': item['url'], 'sha256': actual, 'bytes': archive.stat().st_size})
    return result


def main() -> int:
    container_setup_guard()
    require_bootstrap_contract()  # Before filesystem, package, source, tool or PM setup.
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
    run([sys.executable, '-m', 'pm.cli', 'install', 'python', 'uv', '--tools-only'])
    wheels = verifier(inputs)
    member = SEED / 'dependency-input'
    member.mkdir()
    (member / 'plugin.yaml').write_text(json.dumps({'name': 'dependency-input', 'version': '1.0.0',
                                                 'python_dependencies': inputs['plugin_python_dependencies']}))
    run(['/opt/verifier/bin/python', str(PUBLIC / 'hosted_setup.py'), 'warm'])
    lock = json.loads((CORE / 'pm/lock.json').read_text())
    if lock['packages']['uv']['version'] != inputs['uv']:
        raise ValueError('literal native uv version mismatch')
    record = {'inputs': inputs, 'apt': apt_record, 'verifier_artifacts': wheels,
              'native_pm_lock_sha256': hashlib.sha256((CORE / 'pm/lock.json').read_bytes()).hexdigest(),
              'resolved_union_sha256': hashlib.sha256((SEED / 'resolved-union.lock').read_bytes()).hexdigest(),
              'union_packages': json.loads((SEED / 'union-packages.json').read_text()),
              'tools': {name: lock['packages'][name] for name in ('python', 'uv')},
              'actual_tool_artifacts': tool_artifacts(lock),
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
    elif not sys.argv[1:]:
        raise SystemExit(main())
    else:
        raise ValueError('unknown public setup mode')
