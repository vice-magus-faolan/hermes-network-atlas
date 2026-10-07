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


def container_setup_guard() -> None:
    """Refuse before executable setup/PM imports, including dispatcher modes."""
    require_hosted(os.environ, workspace=Path('/opt/inputs'), commit=os.environ.get('GITHUB_SHA', ''))
    if os.getuid() != 0 or not Path('/.dockerenv').is_file():
        raise ValueError('private hosted prerequisite container required')
    # /.dockerenv is also a diagnostic, not an unforgeable trust anchor.


def require_bootstrap_contract() -> None:
    """Fail before effects: the pinned package recipe cannot run with CapDrop ALL.

    No argument/environment flag rearms this gate. A separately authorized,
    independently reviewed contract change must resolve ordinary dpkg and
    maintainer-script ownership requirements without silently bypassing them.
    """
    raise RuntimeError('BOOTSTRAP_CONTRACT_AUTHORITY_REQUIRED: pinned openssh-client '
                       '1:9.2p1-2+deb12u10 configures ssh-agent with chgrp _ssh and chmod 2755; '
                       'UID0/GID0 with all capabilities dropped cannot grant that group ownership. '
                       'Apt cache permissions alone do not repair the complete package contract.')
