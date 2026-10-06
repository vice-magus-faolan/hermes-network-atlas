#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""One hosted-first diagnostic job. Local execution and workflow reruns refuse.

This wrapper is NOT an OS sandbox for a Docker-capable same-UID caller. The
reviewed standard GitHub-hosted VM/permissions provide the real boundary.
No fit assertion: finite VM exhaustion/OOM/deadline/refusal is job failure.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import time

from acceptance_support import HERMES_COMMIT, ROOT, git_head, git_tree
from docker_acceptance import Docker, clean_checkout, command, lease, require_supported_builder, run_attempt
from docker_builder import (BOOTSTRAP_NAME, BootstrapIdentity, UPSTREAM, UPSTREAM_DIGEST, CORE_TREE,
                            bootstrap_command, commit_command, export_bootstrap, finish_build,
                            registry_budget, reject_existing_owned, validate_bootstrap, verify_final_image,
                            resource_ids)
from docker_contract import ENDPOINT, OWNER, OWNER_VALUE
from docker_evidence import BoundedDirectory, json_bytes, regular_read
from hosted_contract import require_hosted

PUBLIC_FILES = {'Dockerfile': 'docker/Dockerfile', 'dependencies.json': 'docker/dependencies.json',
                'hosted_setup.py': 'docker/hosted_setup.py', 'base_setup.py': 'docker/base_setup.py',
                'acquisition_support.py': 'docker/acquisition_support.py', 'acquisition_plan.py': 'docker/acquisition_plan.py',
                'offline_guard.py': 'scripts/offline_guard.py', 'hosted_contract.py': 'scripts/hosted_contract.py'}
FAILURES = ('error', 'export_error', 'cleanup_error', 'outcome_export_error', 'registry_error', 'resource_error')


def context(source: Path, destination: Path) -> str:
    if git_head(source) != HERMES_COMMIT or git_tree(source) != CORE_TREE:
        raise ValueError('exact public core required')
    if command(['git', '-C', str(source), 'status', '--porcelain=v1', '--untracked-files=all']):
        raise ValueError('public core must be clean')
    destination.mkdir(mode=0o755)
    for name, path in PUBLIC_FILES.items():
        (destination / name).write_bytes(command(['git', '-C', str(ROOT), 'show', f'HEAD:{path}']))
    (destination / 'hermes.tar').write_bytes(command(['git', '-C', str(source), 'archive', HERMES_COMMIT], limit=256 * 1024 ** 2))
    (destination / 'hermes.commit').write_bytes(command(['git', '-C', str(source), 'cat-file', 'commit', HERMES_COMMIT]))
    hashes = {}
    for path in destination.iterdir():
        path.chmod(0o644)
        hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashlib.sha256(json_bytes(hashes)).hexdigest()


def diagnostic(docker: Docker) -> dict:
    roots = {docker.info['DockerRootDir'], '/var/lib/containerd', str(ROOT), os.environ['TMPDIR']}
    storage = {}
    for value in sorted(roots):
        path = Path(value)
        if path.exists():
            stat = os.statvfs(path)
            storage[value] = {'free_bytes': stat.f_bavail * stat.f_frsize, 'free_inodes': stat.f_favail,
                              'used_bytes': (stat.f_blocks - stat.f_bfree) * stat.f_frsize}
    return {'storage': storage, 'mounts': command(['findmnt', '--json'], limit=512 * 1024).decode(),
            'docker_root': docker.info['DockerRootDir'], 'containerd_root': '/var/lib/containerd',
            'diagnostics_only': True, 'fit_proven': False}


def wait_setup(docker: Docker, identity: BootstrapIdentity, public: Path, hosted: dict, evidence: Path) -> dict:
    deadline = time.monotonic() + 1800
    sample = 0
    while time.monotonic() < deadline:
        data = docker.inspect(BOOTSTRAP_NAME, name=BOOTSTRAP_NAME)
        if data is None:
            raise ValueError('owned setup disappeared')
        validate_bootstrap(data, identity, public, hosted=hosted)
        if time.monotonic() >= sample:
            BoundedDirectory(evidence).json('storage-latest.json', diagnostic(docker))
            sample = time.monotonic() + 10
        if not data['State']['Running']:
            return data
        time.sleep(0.5)
    raise TimeoutError('public setup deadline; no retry or local fallback')


def upstream(docker: Docker) -> dict:
    docker.run(['pull', '--platform', 'linux/amd64', UPSTREAM], timeout=900, limit=4 * 1024 ** 2)
    data = docker.json(['image', 'inspect', UPSTREAM])[0]
    refs = {'python@' + UPSTREAM_DIGEST, 'docker.io/library/python@' + UPSTREAM_DIGEST}
    if (data['Architecture'] != 'amd64' or data['Os'] != 'linux'
            or not refs.intersection(data.get('RepoDigests', [])) or not data.get('RootFS', {}).get('Layers')
            or data['Config'].get('Volumes') or data['Config'].get('ExposedPorts')):
        raise ValueError('actual digest-pulled public image/platform/config drift')
    return data


def export_provenance(docker: Docker, identifier: str, evidence: Path) -> None:
    from docker_contract import evidence_members
    for name in ('resolved-union.lock', 'verifier-resolution.json', 'union-packages.json'):
        archive = docker.run(['cp', f'{identifier}:/opt/seed/{name}', '-'], limit=8 * 1024 ** 2)
        rows = evidence_members(archive)
        if [row[0] for row in rows] != [name]:
            raise ValueError('exact retained public provenance required')
        BoundedDirectory(evidence).write(name, rows[0][1])


def build(docker: Docker, root: Path, source: Path, diagnostics: dict, registry: Path) -> tuple[dict, dict]:
    require_hosted(os.environ, workspace=ROOT, commit=git_head())
    before = reject_existing_owned(docker)
    key = context(source, root / 'context')
    initial = upstream(docker)
    identity = BootstrapIdentity(key, docker.daemon, initial['Id'], key)
    hosted = dict(diagnostics, GITHUB_WORKSPACE='/opt/inputs')
    evidence = root / 'bootstrap'
    evidence.mkdir(mode=0o700)
    outcome = {'identity': identity.labels(), 'unrelated_before': before, 'native_acceptance': False}
    try:
        docker.run(bootstrap_command(identity, root / 'context', hosted=hosted))
        data = docker.inspect(BOOTSTRAP_NAME, name=BOOTSTRAP_NAME)
        identifier = validate_bootstrap(data, identity, root / 'context', hosted=hosted)
        BoundedDirectory(evidence).json('created.json', data)
        docker.run(['start', identifier])
        data = wait_setup(docker, identity, root / 'context', hosted, evidence)
        outcome['export_hashes'] = export_bootstrap(docker, evidence, identity)
        export_provenance(docker, identifier, evidence)
        inventory = json.loads(regular_read(evidence / 'inventory.json', 512 * 1024))
        image = docker.run(commit_command(data, identity, root / 'context', hosted=hosted), timeout=300).decode().strip()
        outcome['returned_image'] = image
        record = verify_final_image(docker.json(['image', 'inspect', image])[0], identity)
        if record['rootfs_layers'][:-1] != initial['RootFS']['Layers']:
            raise ValueError('actual base does not extend pulled public rootfs')
        record.update(dependency_inventory=inventory, upstream_image=initial['Id'])
        registry_budget(registry).json('base.json', record)
        outcome['base'] = record
    except BaseException as exc:
        outcome['error'] = f'{type(exc).__name__}: {exc}'
    finally:
        finish_build(docker, evidence, identity, outcome)
    return outcome, initial


def successful(outcome: dict) -> None:
    if any(key in outcome for key in FAILURES) or outcome.get('cleanup_verified') is not True:
        raise RuntimeError('owned phase FAILED; inspect retained original/cleanup evidence')


def cleanup_image(docker: Docker, record: dict) -> None:
    current = docker.json(['image', 'inspect', record['image']])[0]
    if current['Config'].get('Labels') != record['labels'] or current['Id'] != record['image']:
        raise ValueError('owned base cleanup identity drift')
    if docker.run(['ps', '-aq', '--filter', 'ancestor=' + record['image']]).strip():
        raise ValueError('base still has a container consumer')
    docker.run(['image', 'rm', record['image']])
    if record['image'] in resource_ids(docker)['images']:
        raise RuntimeError('base cleanup residue')


def exercise(docker: Docker, root: Path, source: Path, diagnostics: dict, registry: Path, evidence: Path) -> None:
    outcome, initial = build(docker, root, source, diagnostics, registry)
    BoundedDirectory(evidence).json('build.json', outcome)
    record = outcome.get('base')
    original = None
    try:
        successful(outcome)
        if record is None:
            raise ValueError('verified base receipt absent')
        for mode in ('smoke', 'fail', 'interrupt', 'refusal', 'hosted-accept'):
            mapped = dict(diagnostics, GITHUB_WORKSPACE='/candidate') if mode == 'hosted-accept' else None
            result = run_attempt(docker, root, record['image'], mode, registry, hosted=mapped, hosted_export=True)
            BoundedDirectory(evidence).json(mode + '.json', result)
            successful(result)
    except BaseException as exc:
        original = exc
        raise
    finally:
        try:
            if record is None:
                raise ValueError('no verified base identity; residue needs readback, not blind removal')
            cleanup_image(docker, record)
            BoundedDirectory(evidence).json('base-cleanup.json', {'removed': record['image'], 'readback_absent': True,
                                                                 'upstream_retained_for_VM_disposal': initial['Id']})
        except BaseException as exc:
            BoundedDirectory(evidence).json('base-cleanup-error.json', {'error': str(exc)[:4096]})
            if original is None:
                raise
            original.add_note('owned image cleanup failed; evidence retained')


def interrupted(_signum: int, _frame: object) -> None:
    raise InterruptedError('hosted job interrupted; no retry')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--hermes-source', type=Path, required=True)
    parser.add_argument('--admission-mode', choices=('hosted-ci-caution',), required=True)
    args = parser.parse_args()
    diagnostics = require_hosted(os.environ, workspace=ROOT, commit=git_head())  # before ANY resource/daemon effects
    clean_checkout()
    scratch = Path(os.environ['TMPDIR'])
    if not scratch.is_absolute() or scratch.resolve(strict=True) != scratch:
        raise ValueError('literal hosted scratch required')
    root = scratch / 'atlas-docker'
    root.mkdir(mode=0o700)  # exclusive first job; never reuse/retry
    registry = root / 'registry'
    registry.mkdir(mode=0o700)
    evidence = root / 'summary'
    evidence.mkdir(mode=0o700)
    client = root / 'client'
    client.mkdir(mode=0o700)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    with lease(root):
        info = json.loads(command(['docker', '--host', ENDPOINT, '--config', str(client), 'info', '--format', '{{json .}}']))
        docker = Docker(client, info['ID'])
        require_supported_builder(docker.info)
        BoundedDirectory(evidence).json('source.json', {'commit': git_head(), 'tree': git_tree(), 'diagnostics': diagnostics})
        BoundedDirectory(evidence).json('before.json', diagnostic(docker))
        try:
            exercise(docker, root, args.hermes_source, diagnostics, registry, evidence)
        finally:
            BoundedDirectory(evidence).json('after.json', diagnostic(docker))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
