#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail-closed feature-push routing for one reviewed source-only measurement.

A marker is a checked source contract, not consent or an ambient CI skip. Exact
independent review/publication still belongs to the coordinator. Main/PR keep
normal acceptance. A subsequent production successor must remove the marker.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'docker'))
from docker_evidence import regular_read
from acquisition_support import bounded_run

BASE = '2049396385def5af70e87bf5f67b994835b96d1a'
MARKER = 'docker/measurement-phase.json'
FEATURE = 'refs/heads/feat/6-host-discovery'
FILES = frozenset({'.github/workflows/verify.yml', 'README.md', 'docs/acceptance-matrix.md',
                   'docs/hosted-packing-measurement.md', 'docker/measurement-anchor.json',
                   'scripts/measurement_route.py', 'scripts/packing_measurement.py',
                   'scripts/verify.py', 'tests/test_docker_measurement.py',
                   'tests/test_hosted_docker.py', 'tests/test_docker_offline.py'})


def git(root: Path, *args: str) -> str:
    return bounded_run(['git', '-C', str(root), *args], root, timeout=60, limit=4 * 1024 ** 2).strip()


def marker_files(root: Path) -> dict[str, str]:
    """Authenticate every permitted changed leaf, with no production delta."""
    value = json.loads(regular_read(root / MARKER, 16 * 1024), object_pairs_hook=unique_keys)
    if not isinstance(value, dict) or type(value.get('schema')) is not int:
        raise ValueError('literal measurement marker schema required')
    if set(value) != {'schema', 'phase', 'base', 'files'} or value != {
        'schema': 1, 'phase': 'exact-core-packing-measurement-only', 'base': BASE,
        'files': value.get('files'),
    }:
        raise ValueError('malformed measurement marker')
    files = value['files']
    if not isinstance(files, dict) or set(files) != FILES:
        raise ValueError('exact measurement-only source allowlist required')
    for name, digest in files.items():
        if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError('literal measurement source hash required')
        if hashlib.sha256(regular_read(root / name, 512 * 1024)).hexdigest() != digest:
            raise ValueError('measurement source hash drift: ' + name)
    return files


def unique_keys(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate measurement marker key')
        result[key] = value
    return result


def validate_measurement(root: Path, sha: str) -> None:
    """Require one exact-base committed successor; reject mixed/malformed skips."""
    marker_files(root)
    if git(root, 'rev-list', '--parents', '-n', '1', 'HEAD').split() != [sha, BASE]:
        raise ValueError('one exact-base measurement successor required')
    # Compare all changes, not merely the last commit or a message/path hint.
    changed = set(git(root, 'diff', '--name-only', '-z', BASE, 'HEAD').split('\0'))
    changed.discard('')
    if changed != FILES | {MARKER}:
        raise ValueError('mixed production/measurement source changes refused')
    for name in changed:
        mode = git(root, 'ls-tree', 'HEAD', '--', name).split()[0]
        if mode != '100644':
            raise ValueError('regular nonexecutable measurement source required')
    if git(root, 'status', '--porcelain=v1', '--untracked-files=no'):
        raise ValueError('modified tracked measurement source refused')


def route(root: Path, event: str, ref: str, sha: str) -> str:
    """Return a named phase only after exact ref/source validation; never skip."""
    if not re.fullmatch(r'[0-9a-f]{40}', sha) or git(root, 'rev-parse', 'HEAD') != sha:
        raise ValueError('exact checked-out routing SHA required')
    if event == 'pull_request' and re.fullmatch(r'refs/pull/[1-9][0-9]*/merge', ref):
        return 'acceptance'
    if event != 'push' or ref not in {FEATURE, 'refs/heads/main'}:
        raise ValueError('unsupported measurement routing event/ref')
    if ref == FEATURE and git(root, 'status', '--porcelain=v1', '--untracked-files=no'):
        raise ValueError('tracked routing source/marker drift refused')
    marker = root / MARKER
    if ref != FEATURE or not (marker.exists() or marker.is_symlink()):
        return 'acceptance'
    validate_measurement(root, sha)
    return 'measurement'


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    phase = route(root, os.environ.get('GITHUB_EVENT_NAME', ''), os.environ.get('GITHUB_REF', ''),
                  os.environ.get('GITHUB_SHA', ''))
    # GITHUB_OUTPUT is provided by the fixed workflow, never a tool argument.
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as stream:
        stream.write('phase=' + phase + '\n')
    print(json.dumps({'phase': phase, 'native_acceptance': False, 'full_canonical': False,
                      'final_approval': False}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
