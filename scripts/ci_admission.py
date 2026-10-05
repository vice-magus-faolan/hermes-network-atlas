# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit hosted-CI CAUTION policy; environment diagnostics are NOT a sandbox.

Only the reviewed workflow on a fresh GitHub-hosted VM provides the approved
isolation boundary. These checks reject accidental local/replacement use; a
same-UID caller can forge environment strings and must not treat them as consent.
Local setup never selects force. No actual force-install test runs on the server.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Callable, Mapping

from acceptance_support import ROOT, contained, git_head, git_tree
from caution_confirmation import scan_request

MODE = "hosted-ci-caution"
REPOSITORY = "vice-magus-faolan/hermes-network-atlas"
DIAGNOSTICS = ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "GITHUB_REPOSITORY",
               "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_JOB", "GITHUB_SHA", "GITHUB_WORKSPACE",
               "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")


def select_mode(mode: str, env: Mapping[str, str]) -> bool:
    """Require explicit mode and expected workflow diagnostics, never infer authority."""
    if mode == "local":
        return False
    if mode != MODE:
        raise ValueError("unknown admission mode")
    expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
                "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_JOB": "offline-verification",
                "GITHUB_SHA": git_head(ROOT), "GITHUB_WORKSPACE": str(ROOT)}
    if any(env.get(key) != value for key, value in expected.items()):
        raise ValueError("hosted CI diagnostics mismatch; local force is prohibited")
    event, ref = env.get("GITHUB_EVENT_NAME"), env.get("GITHUB_REF", "")
    # Match the reviewed workflow's push branch filter; a main test context is
    # not permission to merge, push main or install into a persistent home.
    refs = {"push": r"refs/heads/(?:main|feat/6-host-discovery)",
            "pull_request": r"refs/pull/[1-9][0-9]*/merge"}
    if event not in refs or not re.fullmatch(refs[event], ref):
        raise ValueError("only approved issue-6 push/pull_request workflow context permitted")
    if any(not re.fullmatch(r"[1-9][0-9]*", env.get(key, "")) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")):
        raise ValueError("explicit hosted run/attempt diagnostics required")
    return True


def fresh_fixture(root: Path, source: Path, candidate: Path, ref: str, env: Mapping[str, str]) -> None:
    """Refuse persistent homes, existing installs/receipts and path/ref substitution."""
    root = root.resolve(strict=True)
    marker = root / "synthetic-atlas-home"
    if marker.is_symlink() or not marker.is_file():
        raise ValueError("fresh marked synthetic fixture required")
    expected = {"TMPDIR": root, "HOME": root / "user", "HERMES_HOME": root / "hermes"}
    if any(Path(env.get(key, "")).resolve() != value for key, value in expected.items()):
        raise ValueError("CI state must use only the fixture's isolated homes")
    if source.is_symlink() or candidate.is_symlink():
        raise ValueError("CI source/candidate must not be substituted symlinks")
    if contained(root, str(source)) != root / "hermes-source":
        raise ValueError("exact fixture core snapshot required")
    if contained(root, str(candidate)) != root / "candidate" or git_head(candidate) != ref:
        raise ValueError("exact complete fixture candidate/ref required")
    home = root / "hermes"
    forbidden = (home / "plugins" / "network-atlas", root / "admission.json", root / "native-enabled.json")
    if any(path.exists() or path.is_symlink() for path in forbidden):
        raise ValueError("CI force cannot replace an existing install or reuse admission")
    config = json.loads((home / "config.yaml").read_text())
    if config != {"plugins": {"enabled": [], "disabled": []}}:
        raise ValueError("fresh default native scan/selection policy required")


def install_ci(source: Path, candidate: Path, ref: str, origin: str, root: Path,
               env: Mapping[str, str], installer: Callable[..., None]) -> dict:
    """Scan pinned full trees, record findings, then invoke unchanged native admission.

    The caller and this boundary verify explicit hosted context. Tests supply
    a mock installer only; actual hosted install performs its own native scan again.
    SAFE needs no force, CAUTION alone selects it, and DANGEROUS always refuses.
    """
    select_mode(MODE, env)
    if origin != env["GITHUB_SHA"]:
        raise ValueError("original candidate must match checked-out CI SHA")
    fresh_fixture(root, source, candidate, ref, env)
    if git_tree(candidate) != git_tree(ROOT):
        raise ValueError("complete candidate tree must match checked-out CI artifact")
    report = scan_request(source, candidate, origin, MODE)
    (root / "ci-scan.json").write_text(json.dumps(report, indent=2, sort_keys=True))
    if report["verdict"] not in {"safe", "caution"}:
        raise ValueError("native dangerous/unknown verdict refuses CI admission")
    installer(candidate.as_uri(), force=report["verdict"] == "caution", enable=False, ref=ref)
    return report
