#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Container entrypoint: fresh contained state, real local refusal/admission, offline tests.

Ordinary confirmation is provided by the operator's real terminal, never an
argument/env flag or synthesized answer. No hosted mode or local force exists.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import time

from acceptance_support import HERMES_COMMIT, ROOT, fixture_environment, git_head, git_tree, plugin_hashes, validate_receipt
from docker_contract import MODES, verification_result

WORK = Path("/work")
FIXTURE = WORK / "fixture"
EXPORT = Path("/export")
SEED = Path("/opt/seed")


def usage(root: Path) -> dict:
    files = [path for path in root.rglob("*") if path.is_file() and not path.is_symlink()]
    stat = os.statvfs(root)
    return {"files": len(files), "apparent_bytes": sum(path.stat().st_size for path in files),
            "allocated_bytes": sum(path.stat().st_blocks * 512 for path in files),
            "filesystem_used_bytes": (stat.f_blocks - stat.f_bfree) * stat.f_frsize,
            "filesystem_free_bytes": stat.f_bavail * stat.f_frsize}


def write_json(name: str, value: object) -> None:
    if len(json.dumps(value).encode()) + sum(path.stat().st_size for path in EXPORT.iterdir() if path.is_file()) > 32 * 1024 ** 2:
        raise ValueError("bounded evidence export exceeded")
    (EXPORT / name).write_text(json.dumps(value, sort_keys=True, indent=2))


def prepare() -> tuple[Path, dict[str, str]]:
    """Copies public seeds, not native selector/admission state; no external symlinks."""
    if os.getuid() != 1000 or os.getgid() != 1000:
        raise ValueError("non-root UID/GID 1000 required")
    if ROOT != Path("/candidate") or FIXTURE.exists():
        raise ValueError("fresh fixed container layout required")
    FIXTURE.mkdir(mode=0o700)
    (FIXTURE / "synthetic-atlas-home").touch()
    for name in ("hermes-source", "tools", "uv-cache"):
        shutil.copytree(SEED / name, FIXTURE / name, symlinks=True)
    shutil.copytree(ROOT, FIXTURE / "candidate", symlinks=True)
    home = FIXTURE / "hermes"
    home.mkdir()
    (home / "config.yaml").write_text('{"plugins":{"enabled":[],"disabled":[]}}')
    (FIXTURE / "user").mkdir()
    cache = home / "cache"
    cache.mkdir()
    shutil.move(FIXTURE / "uv-cache", cache / "uv")
    env = fixture_environment(FIXTURE)
    env.update(HERMES_RUNTIME_DIR=str(FIXTURE / "tools"), UV_CACHE_DIR=str(cache / "uv"))
    write_json("before.json", usage(WORK))
    shutil.copy2(SEED / "inventory.json", EXPORT / "base-inventory.json")
    return FIXTURE / "hermes-source", env


def execute(argv: list[str], env: dict, name: str, *, interactive: bool = False, timeout: int = 900) -> tuple[int, str]:
    """Logs on bounded export tmpfs; native ordinary prompts retain the real terminal."""
    if interactive:
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise ValueError("ordinary native consent requires real foreground terminal")
        result = subprocess.run(argv, env=env, timeout=timeout)
        return result.returncode, "native output retained in Docker container.log"
    from docker_acceptance import command
    try:
        output = command(argv, timeout=timeout, limit=4 * 1024 ** 2, env=env)
        code = 0
    except subprocess.CalledProcessError as exc:
        output, code = exc.output, exc.returncode
    (EXPORT / name).write_bytes(output)
    return code, output.decode(errors="replace")


def export_native() -> None:
    for name in ("native-enabled.json", "admission.json"):
        path = FIXTURE / name
        if path.is_file():
            shutil.copy2(path, EXPORT / name)
    atlas = FIXTURE / "hermes" / "network-atlas" / "atlas.sqlite3"
    if atlas.is_file():
        # Consistent synthetic snapshot, never raw live/WAL file copying.
        with sqlite3.connect(f"file:{atlas}?mode=ro", uri=True) as source:
            with sqlite3.connect(EXPORT / "synthetic-atlas.sqlite3") as destination:
                source.backup(destination)
    write_json("after.json", usage(WORK))


def scan_and_install(source: Path, env: dict, mode: str) -> int:
    candidate = FIXTURE / "candidate"
    base = ["/opt/verifier/bin/python", str(ROOT / "scripts" / "native_install.py"), str(source)]
    code, text = execute([*base, "scan", str(candidate), git_head(), "--origin-commit", git_head(),
                          "--confirmation-scope", "disposable-local-docker"], env, "scan.json")
    if code:
        raise RuntimeError("full native scan failed")
    report = json.loads(text)
    if report["candidate_commit"] != git_head() or report["candidate_tree"] != git_tree():
        raise ValueError("full native scan identity mismatch")
    if mode == "refusal":
        code, _text = execute([*base, "install", str(candidate), git_head()], env, "install.log")
        if code == 0 or (FIXTURE / "hermes" / "plugins" / "network-atlas").exists():
            raise RuntimeError("ordinary non-TTY refusal expected, installation must be absent")
        write_json("result.json", {"native_acceptance": False, "ordinary_refusal": True, "install_exit": code,
                                   "verdict": report["verdict"], "findings": len(report["findings"])})
        return 20
    if report["verdict"] == "dangerous":
        raise RuntimeError("native DANGEROUS refusal is unconditional")
    code, _text = execute([*base, "install", str(candidate), git_head()], env, "install.log", interactive=True)
    if code:
        raise RuntimeError("ordinary native installation failed")
    code, _text = execute([*base, "enable"], env, "enable.log", interactive=True)
    if code:
        raise RuntimeError("genuine native enable/PM failed")
    receipt = json.loads((FIXTURE / "native-enabled.json").read_text())
    receipt.update(candidate_commit=git_head(), candidate_tree=git_tree(), fixture_commit=git_head(),
                   setup_network="Docker network none; genuine fresh PM from public prerequisite cache", environment=env,
                   admission_mode="local")
    (FIXTURE / "admission.json").write_text(json.dumps(receipt, sort_keys=True, indent=2))
    return canonical(receipt, source)


def canonical(receipt: dict, source: Path) -> int:
    # Setup uses TMPDIR=fixture. Canonical fixture_root requires STRICTLY BELOW
    # TMPDIR, so validation and fresh-process tests use its parent scratch.
    os.environ["TMPDIR"] = str(WORK)
    validate_receipt(FIXTURE)
    env = fixture_environment(FIXTURE)
    env.update(TMPDIR=str(WORK), NETWORK_ATLAS_ACCEPTANCE_FIXTURE=str(FIXTURE),
               NETWORK_ATLAS_HERMES_ROOT=str(source))
    code, text = execute([receipt["python"], str(ROOT / "scripts" / "verify.py")], env, "canonical.log")
    result = verification_result(text, code)
    validate_receipt(FIXTURE)
    result.update(native_acceptance=True, candidate_commit=git_head(), candidate_tree=git_tree(), hermes_commit=HERMES_COMMIT,
                  native_generation=receipt["native_generation"], installed_tree=receipt["installed_tree"], network="none")
    write_json("result.json", result)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("mode", choices=MODES)
    mode = parser.parse_args().mode
    if mode == "accept" and (not sys.stdin.isatty() or not sys.stdout.isatty()):
        raise ValueError("ordinary foreground consent required before state creation")
    write_json("started.json", {"mode": mode, "native_acceptance": False, "commit": git_head(), "tree": git_tree()})
    try:
        if mode == "fail":
            write_json("result.json", {"native_acceptance": False, "intentional_failure": True})
            return 21
        if mode == "interrupt":
            signal.signal(signal.SIGTERM, interrupted)
            while True:
                time.sleep(1)
        source, env = prepare()
        if mode == "smoke":
            command = ["/opt/verifier/bin/python", str(ROOT / "scripts" / "network_denial_probe.py")]
            code, _text = execute(command, env, "packet-denial.log", timeout=30)
            if code:
                raise RuntimeError("inherited packet denial smoke failed")
            write_json("result.json", {"native_acceptance": False, "packet_denial_smoke": True,
                                       "nonroot_layout": True, "commit": git_head(), "tree": git_tree()})
            return 0
        return scan_and_install(source, env, mode)
    except BaseException as exc:
        write_json("error.json", {"error": type(exc).__name__, "message": str(exc), "native_acceptance": False})
        raise
    finally:
        export_native()


def interrupted(_signum: int, _frame: object) -> None:
    write_json("result.json", {"native_acceptance": False, "interrupted": True})
    raise SystemExit(22)


if __name__ == "__main__":
    raise SystemExit(main())
