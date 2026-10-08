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
                            registry_budget, reject_existing_owned, validate_bootstrap, read_final_image,
                            resource_ids, require_bootstrap_success, require_base_command,
                            stopped_bootstrap, copy_seed_member, export_error_text)
from docker_contract import ENDPOINT, OWNER, OWNER_VALUE
from docker_evidence import BoundedDirectory, json_bytes, regular_read
from hosted_contract import require_bootstrap_contract, validate_setup_inventory

PUBLIC_FILES = {'Dockerfile': 'docker/Dockerfile', 'dependencies.json': 'docker/dependencies.json',
                'hosted_setup.py': 'docker/hosted_setup.py', 'base_setup.py': 'docker/base_setup.py',
                'acquisition_support.py': 'docker/acquisition_support.py', 'acquisition_plan.py': 'docker/acquisition_plan.py',
                'offline_guard.py': 'scripts/offline_guard.py', 'hosted_contract.py': 'scripts/hosted_contract.py',
                'hosted_apt.py': 'docker/hosted_apt.py', 'core_identity.py': 'scripts/core_identity.py',
                'native_union_diagnostics.py': 'scripts/native_union_diagnostics.py',
                'hosted_git.py': 'docker/hosted_git.py',
                'docker_evidence.py': 'scripts/docker_evidence.py'}
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


def build(docker: Docker, root: Path, source: Path, diagnostics: dict, registry: Path) -> tuple[dict, dict]:
    require_bootstrap_contract(workspace=ROOT, commit=git_head())  # Before context/archive, pull or daemon effects.
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
        require_bootstrap_success(data)
        outcome['export_hashes'] = export_bootstrap(docker, evidence, identity, provenance=True)
        export_git_preparation(docker, evidence, identity, root / 'context', hosted, outcome)
        if 'export_error' in outcome:
            raise ValueError('Git preparation provenance export refused before image commit')
        inventory = json.loads(regular_read(evidence / 'inventory.json', 512 * 1024))
        validate_setup_inventory(inventory)
        image = docker.run(commit_command(data, identity, root / 'context', hosted=hosted), timeout=300).decode().strip()
        outcome['returned_image'] = image[:128]
        record = read_final_image(docker, image, identity, evidence, registry, initial['RootFS']['Layers'])
        record.update(dependency_inventory=inventory, upstream_image=initial['Id'])
        registry_budget(registry).json('base.json', record)
        outcome['base'] = record
    except BaseException as exc:
        outcome['error'] = f'{type(exc).__name__}: {exc}'
    finally:
        export_git_preparation(docker, evidence, identity, root / 'context', hosted, outcome)
        export_union_diagnostics(docker, evidence, identity, root / 'context', hosted, outcome)
        finish_build(docker, evidence, identity, outcome, provenance=True)
    return outcome, initial


def export_union_diagnostics(docker, evidence: Path, identity, public: Path, hosted: dict, outcome: dict) -> None:
    """Independent failed-stage export; exact stopped ownership before reading."""
    try:
        data = stopped_bootstrap(docker, identity)
        validate_bootstrap(data, identity, public, hosted=hosted)
        budget = BoundedDirectory(evidence)
        row = copy_seed_member(docker, data['Id'], budget, 'union-diagnostics.json')
        budget.json('union-diagnostics-export.json', row)
        outcome['union_diagnostics'] = row
        if data['State']['ExitCode'] == 0 and row['status'] != 'present':
            raise ValueError('required union diagnostics absent after successful setup')
    except BaseException as exc:
        outcome.setdefault('export_error', export_error_text(exc))


def export_git_preparation(docker, evidence: Path, identity, public: Path, hosted: dict, outcome: dict) -> None:
    """Incremental Git proof exports independently, including failed preparation."""
    try:
        data = stopped_bootstrap(docker, identity)
        validate_bootstrap(data, identity, public, hosted=hosted)
        budget = BoundedDirectory(evidence)
        row = copy_seed_member(docker, data['Id'], budget, 'git-preparation.json')
        budget.json('git-preparation-export.json', row)
        outcome['git_preparation'] = row
        if data['State']['ExitCode'] == 0:
            if row['status'] != 'present':
                raise ValueError('required Git preparation absent after successful setup')
            proof = json.loads(regular_read(evidence / 'git-preparation.json', 32 * 1024))
            from hosted_git import require_complete
            require_complete(proof)
    except BaseException as exc:
        outcome.setdefault('export_error', export_error_text(exc))


def successful(outcome: dict) -> None:
    if any(key in outcome for key in FAILURES) or outcome.get('cleanup_verified') is not True:
        raise RuntimeError('owned phase FAILED; ' + str(outcome.get('error', 'inspect retained original/cleanup evidence')))


def cleanup_image(docker: Docker, record: dict) -> None:
    current = docker.json(['image', 'inspect', record['image']])[0]
    require_base_command(current['Config'])
    if current['Config'].get('Labels') != record['labels'] or current['Id'] != record['image']:
        raise ValueError('owned base cleanup identity drift')
    if docker.run(['ps', '-aq', '--filter', 'ancestor=' + record['image']]).strip():
        raise ValueError('base still has a container consumer')
    docker.run(['image', 'rm', record['image']])
    if record['image'] in resource_ids(docker)['images']:
        raise RuntimeError('base cleanup residue')


def finish_image(docker: Docker, record: dict | None, initial: dict, evidence: Path, original: BaseException | None) -> None:
    """Never delete unverified image identity or replace primary failure with export."""
    try:
        if record is None:
            raise ValueError('no verified base identity; residue needs readback, not blind removal')
        cleanup_image(docker, record)
        BoundedDirectory(evidence).json('base-cleanup.json', {'removed': record['image'], 'readback_absent': True,
                                                             'upstream_retained_for_VM_disposal': initial['Id']})
    except BaseException as exc:
        try:
            BoundedDirectory(evidence).json('base-cleanup-error.json', {'error': str(exc)[:4096]})
        except BaseException as export_error:
            exc.add_note(f'cleanup evidence export failed: {type(export_error).__name__}')
        if original is None:
            raise
        original.add_note('owned image cleanup failed; evidence may be incomplete: ' + str(exc)[:4096])
        for note in getattr(exc, '__notes__', ()):
            original.add_note(note)


def exercise(docker: Docker, root: Path, source: Path, diagnostics: dict, registry: Path, evidence: Path) -> None:
    outcome, initial = build(docker, root, source, diagnostics, registry)
    record = outcome.get('base')
    original = None
    try:
        successful(outcome)
        BoundedDirectory(evidence).json('build.json', outcome)
        if record is None:
            raise ValueError('verified base receipt absent')
        for mode in ('smoke', 'fail', 'interrupt', 'refusal', 'hosted-accept'):
            mapped = dict(diagnostics, GITHUB_WORKSPACE='/candidate') if mode == 'hosted-accept' else None
            result = run_attempt(docker, root, record['image'], mode, registry, hosted=mapped, hosted_export=True)
            BoundedDirectory(evidence).json(mode + '.json', result)
            successful(result)
    except BaseException as exc:
        original = exc
        try:
            BoundedDirectory(evidence).json('build.json', outcome)
        except BaseException as export_error:
            exc.add_note(f'build evidence export failed: {type(export_error).__name__}')
        raise
    finally:
        finish_image(docker, record, initial, evidence, original)


def interrupted(_signum: int, _frame: object) -> None:
    raise InterruptedError('hosted job interrupted; no retry')


def export_after(docker: Docker, evidence: Path, original: BaseException | None) -> None:
    """Final host diagnostics are secondary to the actual setup/acceptance error."""
    try:
        BoundedDirectory(evidence).json('after.json', diagnostic(docker))
    except BaseException as exc:
        if original is None:
            raise
        original.add_note(f'final diagnostic export failed: {type(exc).__name__}: {str(exc)[:4096]}')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--hermes-source', type=Path, required=True)
    parser.add_argument('--admission-mode', choices=('hosted-ci-caution',), required=True)
    args = parser.parse_args()
    diagnostics = require_bootstrap_contract(workspace=ROOT, commit=git_head())  # before ANY resource/daemon effects
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
        original = None
        try:
            exercise(docker, root, args.hermes_source, diagnostics, registry, evidence)
        except BaseException as exc:
            original = exc
            raise
        finally:
            export_after(docker, evidence, original)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
