#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prepare disposable native admission OUTSIDE offline tests; never activate a live home.

Setup may acquire dependencies online. Only the ordinary native declared-dependency
consent is answered; security refusals and other prompts fail closed. No source,
resolver, enabled selection or admission mocks. Run again for a changed candidate.
"""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

from acceptance_support import HERMES_COMMIT, ROOT, fixture_environment, git_head, git_tree, plugin_hashes


def run(command: list[str], root: Path, env: dict, timeout: int = 600) -> str:
    child = subprocess.Popen(command, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, start_new_session=True)
    try:
        output, error = child.communicate(timeout=timeout)
        if child.returncode:
            raise RuntimeError(output + error)
        return output
    finally:
        if child.returncode is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()


def enable(command: list[str], root: Path, env: dict) -> None:
    """Supply authorized dependency consent, never force/accept scan warnings."""
    master, slave = pty.openpty()
    process = subprocess.Popen(command, cwd=root, env=env, stdin=slave, stdout=slave, stderr=slave,
                               start_new_session=True)
    os.close(slave)
    output = bytearray()
    answered = False
    deadline = time.monotonic() + 900
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    break
                output.extend(data)
                if len(output) > 4 * 1024 * 1024:
                    raise RuntimeError("native setup exceeded log bound")
                if b"Prepare these with Hermes through PM now? [y/N]:" in output and not answered:
                    os.write(master, b"y\n")
                    answered = True
            if process.poll() is not None:
                break
        (root / "enable.log").write_bytes(output)
        if process.wait(timeout=5) != 0:
            raise RuntimeError(output.decode(errors="replace"))
    finally:
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        os.close(master)


def snapshot(source: Path, root: Path) -> Path:
    if git_head(source) != HERMES_COMMIT:
        raise ValueError("exact reviewed Hermes commit required")
    # Archive committed public code; never copy a source checkout's config/venv/.env.
    archive = subprocess.check_output(["git", "-C", str(source), "archive", HERMES_COMMIT], timeout=60)
    destination = root / "hermes-source"
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        bundle.extractall(destination, filter="data")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--hermes-source", type=Path, required=True, help="Git checkout of exact public Hermes commit")
    parser.add_argument("--software-seed", type=Path, help="Optional authorized disposable tools/uv-cache, never live state")
    args = parser.parse_args()
    scratch = Path(os.environ["TMPDIR"]).resolve()
    if not scratch.is_dir():
        raise ValueError("existing TMPDIR required")
    if shutil.disk_usage(scratch).free < 1024 * 1024 * 1024:
        raise RuntimeError("at least 1 GiB scratch capacity required before native setup")
    root = Path(tempfile.mkdtemp(prefix="atlas-admission-", dir=scratch))
    (root / "synthetic-atlas-home").touch()
    (root / "user").mkdir()
    home = root / "hermes"
    home.mkdir()
    (home / "config.yaml").write_text(json.dumps({"plugins": {"enabled": [], "disabled": []}}))
    env = fixture_environment(root)
    source = snapshot(args.hermes_source.resolve(), root)
    if args.software_seed:
        seed = args.software_seed.resolve()
        if not (seed / "tools").is_dir() or not (seed / "uv-cache").is_dir():
            raise ValueError("disposable software seed requires tools/uv-cache")
        # Copy public pinned tools, not mutable home state or hardlinks. Use a
        # fresh cache: recovered uv caches may contain dereferenced archive
        # symlinks and are unsuitable for native online URL revalidation.
        shutil.copytree(seed / "tools", root / "tools", symlinks=True)
        env["HERMES_RUNTIME_DIR"] = str(root / "tools")
    env["UV_CACHE_DIR"] = str(home / "cache" / "uv")
    # Install the ENTIRE committed repository, including docs/tests/harnesses:
    # scanning a reduced production-file subset would not prove admission of
    # the artifact an operator clones. Require a clean candidate before setup.
    run(["git", "-C", str(ROOT), "diff", "--exit-code", "HEAD"], root, env)
    archive = subprocess.check_output(["git", "-C", str(ROOT), "archive", git_head()], timeout=60)
    candidate = root / "candidate"
    candidate.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        bundle.extractall(candidate, filter="data")
    if plugin_hashes(candidate) != plugin_hashes():
        raise RuntimeError("worktree plugin differs from committed artifact")
    for argv in (["init", "-q"], ["add", "."], ["-c", "user.name=Atlas Fixture", "-c", "user.email=atlas@example.invalid",
                                                "commit", "-qm", "Synthetic candidate fixture"]):
        run(["git", "-C", str(candidate), *argv], root, env)
    fixture_commit = git_head(candidate)
    command = [sys.executable, str(ROOT / "scripts" / "native_install.py"), str(source)]
    print(f"Native setup scratch: {root}", flush=True)
    (root / "install.log").write_text(run([*command, "install", str(candidate), fixture_commit], root, env))
    enable([*command, "enable"], root, env)
    receipt = json.loads((root / "native-enabled.json").read_text())
    if (receipt["plugin_hashes"] != plugin_hashes() or receipt["installed_commit"] != fixture_commit
            or receipt["installed_tree"] != git_tree()):
        raise RuntimeError("installed bytes differ from candidate")
    receipt.update({"candidate_commit": git_head(), "candidate_tree": git_tree(), "fixture_commit": fixture_commit,
                    "setup_network": "authorized online dependency/setup only", "environment": env})
    (root / "admission.json").write_text(json.dumps(receipt, indent=2, sort_keys=True))
    print(f"NETWORK_ATLAS_ACCEPTANCE_FIXTURE={root}")
    print("Supported install/enable read back; acceptance NOT YET RUN", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
