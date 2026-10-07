# SPDX-License-Identifier: GPL-3.0-or-later
"""Invocation diagnostics, not proof of VM isolation or independent approval.

Only the reviewed standard GitHub-hosted workflow is the execution boundary.
These fail-closed checks catch accidental local use; same-UID code can forge them.
"""
from __future__ import annotations
import os
from pathlib import Path
import re
from typing import Mapping

REPOSITORY = 'vice-magus-faolan/hermes-network-atlas'
DIAGNOSTICS = ('GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'RUNNER_OS', 'RUNNER_ARCH',
               'GITHUB_REPOSITORY', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'GITHUB_JOB',
               'GITHUB_SHA', 'GITHUB_WORKSPACE', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')
# Standard Docker Linux default diagnostic mask; the full named set and rationale
# are in docs/bootstrap-permission-contract.md. This does not change capabilities.
# Actual setup checks this mask as well as the host's create/inspect predicates.
BOOTSTRAP_CAP_MASK = 0xa80425fb


def require_hosted(env: Mapping[str, str], *, workspace: Path, commit: str) -> dict[str, str]:
    expected = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                'RUNNER_OS': 'Linux', 'RUNNER_ARCH': 'X64', 'GITHUB_REPOSITORY': REPOSITORY,
                'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/feat/6-host-discovery',
                'GITHUB_JOB': 'hosted-docker', 'GITHUB_SHA': commit, 'GITHUB_WORKSPACE': str(workspace),
                'GITHUB_RUN_ATTEMPT': '1'}
    if any(env.get(key) != value for key, value in expected.items()):
        raise ValueError('hosted-first diagnostics mismatch; local execution/retries prohibited')
    if not re.fullmatch(r'[0-9a-f]{40}', commit) or not re.fullmatch(r'[1-9][0-9]*', env.get('GITHUB_RUN_ID', '')):
        raise ValueError('exact source and initial hosted run required')
    return {key: env[key] for key in DIAGNOSTICS}


def container_setup_guard() -> dict[str, str]:
    """Require ordinary contained package provisioning before setup/PM imports.

    This is a diagnostic guard, not an unforgeable local execution permission.
    The reviewed hosted workflow and host-side immutable inspection are required.
    """
    require_bootstrap_contract(workspace=Path('/opt/inputs'), commit=os.environ.get('GITHUB_SHA', ''))
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (0, 0, 0, 0) or not Path('/.dockerenv').is_file():
        raise ValueError('private hosted prerequisite container required')
    return validate_setup_status(Path('/proc/self/status').read_text())


def validate_setup_status(status: str) -> dict[str, str]:
    """Check actual default capabilities and retained NNP/seccomp containment."""
    wanted = {'CapEff': f'{BOOTSTRAP_CAP_MASK:016x}', 'CapPrm': f'{BOOTSTRAP_CAP_MASK:016x}',
              'CapBnd': f'{BOOTSTRAP_CAP_MASK:016x}', 'CapInh': '0000000000000000',
              'CapAmb': '0000000000000000', 'NoNewPrivs': '1', 'Seccomp': '2'}
    observed = {}
    for line in status.splitlines():
        key, separator, value = line.partition(':')
        if separator and key in wanted:
            if key in observed:
                raise ValueError('duplicate bootstrap process diagnostic')
            observed[key] = value.strip()
    if observed != wanted:
        raise ValueError('bootstrap process capability/NNP/seccomp drift')
    return observed


def validate_setup_inventory(inventory: dict) -> None:
    """Require the exported actual process diagnostics before rootfs commit."""
    status = inventory.get('bootstrap_process')
    if not isinstance(status, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in status.items()):
        raise ValueError('bootstrap process inventory absent or malformed')
    observed = validate_setup_status('\n'.join(f'{key}: {value}' for key, value in status.items()))
    if status != observed:
        raise ValueError('unexpected bootstrap process inventory keys')


def require_bootstrap_contract(*, workspace: Path, commit: str) -> dict[str, str]:
    """Admit only the fixed hosted provisioning lane; never local/root fallback.

    Package ownership and maintainer scripts use Docker's standard defaults in
    the public-only bootstrap. Candidate acceptance still drops ALL capabilities.
    """
    return require_hosted(os.environ, workspace=workspace, commit=commit)
