#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prepare disposable native admission OUTSIDE offline tests; never activate a live home.

Setup may acquire dependencies online. Local CAUTION needs ordinary explicit
exact-artifact consent. Hosted CI has a separately approved explicit mode. No source,
resolver, enabled selection or admission mocks. Run again for a changed candidate.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
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
from caution_confirmation import install_confirmed, verify_approval
from native_install import approval_values, confirmation_arguments
from ci_admission import DIAGNOSTICS, MODE, select_mode


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
    """Supply only the native PM prompt; retain bounded evidence on failure."""
    if len(command) > 64 or len(json.dumps(command).encode()) > 8192:
        raise ValueError('native enable argv bound')
    master, slave = pty.openpty()
    try:
        process = subprocess.Popen(command, cwd=root, env=env, stdin=slave, stdout=slave, stderr=slave,
                                   start_new_session=True)
    except BaseException:
        os.close(master)
        raise
    finally:
        os.close(slave)
    output = bytearray()
    audit = {'argv': command, 'state': 'started', 'output_complete': False}
    started = time.monotonic()
    original = None
    try:
        audit['answered'] = enable_output(master, output, started + 900)
        audit.update(output_complete=True, exit_code=process.wait(timeout=5), state='complete')
        if audit['exit_code'] != 0:
            audit['state'] = 'failed'
            raise RuntimeError(f"native enable failed: exit={audit['exit_code']}; see enable.log/enable-command.json")
    except BaseException as exc:
        original = exc
        audit.update(state='failed', error=type(exc).__name__)
        raise
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        os.close(master)
        audit.update(exit_code=process.returncode, elapsed_seconds=time.monotonic() - started,
                     output_bytes=len(output), output_sha256=hashlib.sha256(output).hexdigest())
        try:
            enable_evidence(root, output, audit)
        except BaseException as exc:
            if original is None:
                raise
            original.add_note(f'native enable evidence failed: {type(exc).__name__}')


def enable_output(master: int, output: bytearray, deadline: float) -> bool:
    """Drain to actual PTY EOF, not the first observed child exit."""
    answered = False
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('native enable deadline')
        if not select.select([master], [], [], min(0.1, remaining))[0]:
            continue
        try:
            data = os.read(master, 65536)
        except OSError as exc:
            if exc.errno != errno.EIO:
                raise
            return answered
        if not data:
            return answered
        space = 4 * 1024 ** 2 - len(output)
        output.extend(data[:space])
        if len(data) > space:
            raise RuntimeError('native setup exceeded log bound')
        if b'Prepare these with Hermes through PM now? [y/N]:' in output and not answered:
            os.write(master, b'y\n')
            answered = True


def enable_evidence(root: Path, output: bytearray, audit: dict) -> None:
    """Private actual output and command audit, never repeated in traceback."""
    for name, payload in (('enable.log', bytes(output)),
                          ('enable-command.json', json.dumps(audit, sort_keys=True).encode())):
        fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)


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


def candidate_snapshot(root: Path, env: dict) -> Path:
    """Archive and verify the entire committed candidate before native admission."""
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
    if git_tree(candidate) != git_tree():
        raise RuntimeError("complete archived tree differs from committed artifact")
    return candidate


def install_candidate(source: Path, candidate: Path, root: Path, env: dict, args: argparse.Namespace) -> None:
    """Choose explicit admission transport, preserving ordinary local consent."""
    command = [sys.executable, str(ROOT / "scripts" / "native_install.py"), str(source)]
    fixture_commit = git_head(candidate)
    install_command = [*command, "install", str(candidate), fixture_commit]
    if args.admission_mode == MODE:
        install_command.extend(("--admission-mode", MODE, "--origin-commit", git_head()))
    consent = approval_values(args)
    if consent:
        request = json.loads(run([*command, "scan", str(candidate), fixture_commit,
                                  "--origin-commit", git_head(), "--confirmation-scope", args.confirmation_scope], root, env))
        # The detached authority is validated here AND by the child before its
        # marker. A PTY by itself is never interpreted as consent.
        verify_approval(request, consent[0], consent[1], consent[2], consent[3], (ROOT, root, source))
        for flag, value in zip(("--approval", "--approval-signature", "--allowed-signers", "--signer", "--confirmation-scope"), consent):
            install_command.extend((flag, str(value)))
        install_command.extend(("--origin-commit", git_head()))
        output = install_confirmed(install_command, root, env, request)
    else:
        output = run(install_command, root, env)
    (root / "install.log").write_text(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--hermes-source", type=Path, required=True, help="Git checkout of exact public Hermes commit")
    parser.add_argument("--software-seed", type=Path, help="Optional authorized disposable tools/uv-cache, never live state")
    parser.add_argument("--admission-mode", choices=("local", MODE), default="local")
    confirmation_arguments(parser)
    args = parser.parse_args()
    consent = approval_values(args)
    hosted = select_mode(args.admission_mode, os.environ)
    if hosted and consent:
        raise ValueError("hosted CI mode cannot use signed consent")
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
    if hosted:
        env.update({key: os.environ[key] for key in DIAGNOSTICS})
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
    candidate = candidate_snapshot(root, env)
    fixture_commit = git_head(candidate)
    command = [sys.executable, str(ROOT / "scripts" / "native_install.py"), str(source)]
    print(f"Native setup scratch: {root}", flush=True)
    install_candidate(source, candidate, root, env, args)
    enable([*command, "enable"], root, env)
    receipt = json.loads((root / "native-enabled.json").read_text())
    if (receipt["plugin_hashes"] != plugin_hashes() or receipt["installed_commit"] != fixture_commit
            or receipt["installed_tree"] != git_tree()):
        raise RuntimeError("installed bytes differ from candidate")
    receipt.update({"candidate_commit": git_head(), "candidate_tree": git_tree(), "fixture_commit": fixture_commit,
                    "setup_network": "authorized online dependency/setup only", "environment": env,
                    "admission_mode": args.admission_mode})
    (root / "admission.json").write_text(json.dumps(receipt, indent=2, sort_keys=True))
    print(f"NETWORK_ATLAS_ACCEPTANCE_FIXTURE={root}")
    print("Supported install/enable read back; acceptance NOT YET RUN", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
