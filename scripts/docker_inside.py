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
from docker_evidence import BoundedDirectory

WORK = Path("/work")
FIXTURE = WORK / "fixture"
EXPORT = Path("/export")
SEED = Path("/opt/seed")


def usage(root: Path) -> dict:
    count = apparent = allocated = 0
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        value = path.stat()
        count += 1
        apparent += value.st_size
        allocated += value.st_blocks * 512
        if count > 100000 or apparent > 2 * 1024 ** 3:
            raise ValueError("native copy/inventory bound")
    stat = os.statvfs(root)
    return {"files": count, "apparent_bytes": apparent, "allocated_bytes": allocated,
            "filesystem_used_bytes": (stat.f_blocks - stat.f_bfree) * stat.f_frsize,
            "filesystem_free_bytes": stat.f_bavail * stat.f_frsize}


def write_json(name: str, value: object) -> None:
    BoundedDirectory(EXPORT).json(name, value)


def prepare() -> tuple[Path, dict[str, str]]:
    """Copies public seeds, not native selector/admission state; no external symlinks."""
    if os.getuid() != 1000 or os.getgid() != 1000:
        raise ValueError("non-root UID/GID 1000 required")
    if ROOT != Path("/candidate") or FIXTURE.exists():
        raise ValueError("fresh fixed container layout required")
    FIXTURE.mkdir(mode=0o700)
    (FIXTURE / "synthetic-atlas-home").touch()
    expected = authenticate_source(SEED / 'hermes-source', 'consumer-seed')
    for name in ("hermes-source", "tools", "uv-cache"):
        shutil.copytree(SEED / name, FIXTURE / name, symlinks=True)
    authenticate_source(FIXTURE / 'hermes-source', 'consumer-copy', expected=expected)
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
    BoundedDirectory(EXPORT).copy(SEED / "inventory.json", "base-inventory.json")
    return FIXTURE / "hermes-source", env


def authenticate_source(source: Path, phase: str, *, expected: dict | None = None) -> dict:
    """Export complete hash manifests before refusal; never normalize source."""
    from core_identity import source_manifest, identity_report, require_identity
    from docker_evidence import regular_read
    if phase not in {'consumer-seed', 'consumer-copy'}:
        raise ValueError('fixed core diagnostic phase required')
    if expected is None:
        expected = json.loads(regular_read(SEED / 'core-source-manifest.json', 4 * 1024 ** 2))
    if not isinstance(expected, dict):
        raise ValueError('complete expected core manifest required')
    actual = source_manifest(source)
    report = identity_report(actual, expected, phase)
    original = None
    try:
        require_identity(expected)
        require_identity(actual)
    except BaseException as exc:
        original = exc
        raise
    finally:
        try:
            BoundedDirectory(EXPORT).json(phase + '-identity.json', report)
            BoundedDirectory(EXPORT).json(phase + '-manifest.json', actual)
        except BaseException as exc:
            if original is None:
                raise
            original.add_note(f'core identity export failed: {type(exc).__name__}')
    return expected


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
    BoundedDirectory(EXPORT).write(name, output)
    return code, output.decode(errors="replace")


def export_native() -> None:
    for name in ("native-enabled.json", "admission.json"):
        path = FIXTURE / name
        if path.is_file():
            BoundedDirectory(EXPORT).copy(path, name)
    atlas = FIXTURE / "hermes" / "network-atlas" / "atlas.sqlite3"
    if atlas.is_file():
        # Consistent synthetic snapshot, never raw live/WAL file copying.
        BoundedDirectory(EXPORT).sqlite_backup(atlas, "synthetic-atlas.sqlite3")
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
    if mode == "hosted-accept":
        return hosted_install(base, candidate, source, env)
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


def hosted_install(base: list[str], candidate: Path, source: Path, env: dict) -> int:
    """Genuine hosted-only admission, then ordinary native dependency consent."""
    from hosted_contract import require_hosted
    from prepare_acceptance import enable
    diagnostics = require_hosted(os.environ, workspace=ROOT, commit=git_head())
    env.update(diagnostics)
    env['UV_OFFLINE'] = '1'  # real native cache-only resolution, no online fallback
    install = [*base, "install", str(candidate), git_head(), "--admission-mode", "hosted-ci-caution",
               "--origin-commit", git_head()]
    code, _text = execute(install, env, "install.log")
    if code:
        raise RuntimeError("real hosted native admission failed")
    # Narrow supported PM prompt only, not blanket yes or scan confirmation.
    enable([*base, "enable"], FIXTURE, env)
    BoundedDirectory(EXPORT).copy(FIXTURE / "enable.log", "enable.log")
    receipt = json.loads((FIXTURE / "native-enabled.json").read_text())
    receipt.update(candidate_commit=git_head(), candidate_tree=git_tree(), fixture_commit=git_head(),
                   setup_network="Docker network none plus inherited syscall denial", environment=env,
                   admission_mode="hosted-ci-caution")
    (FIXTURE / "admission.json").write_text(json.dumps(receipt, sort_keys=True, indent=2))
    return canonical(receipt, source)


def canonical(receipt: dict, source: Path) -> int:
    # Setup uses TMPDIR=fixture. Canonical fixture_root requires STRICTLY BELOW
    # TMPDIR, so validation and fresh-process tests use its parent scratch.
    os.environ["TMPDIR"] = str(WORK)
    validate_receipt(FIXTURE)
    env = fixture_environment(FIXTURE)
    env.update(TMPDIR=str(WORK), NETWORK_ATLAS_ACCEPTANCE_FIXTURE=str(FIXTURE),
               NETWORK_ATLAS_HERMES_ROOT=str(source), HERMES_RUNTIME_DIR=str(FIXTURE / "tools"))
    image = os.environ["NETWORK_ATLAS_IMAGE_ID"]
    cold_code, cold_text = execute([receipt["python"], str(ROOT / "scripts" / "docker_cold.py"),
                                   str(FIXTURE), "--image", image], env, "cold.log", timeout=60)
    if cold_code:
        raise RuntimeError("fresh-process native consumer/PM selection failed")
    write_json("cold.json", json.loads(cold_text))
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
    original = None
    try:
        mode = parser.parse_args().mode
        startup(mode)
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
        original = exc
        try:
            write_json("error.json", {"error": type(exc).__name__, "message": str(exc)[:4096], "native_acceptance": False})
        except BaseException as export_error:
            exc.add_note(f"error evidence export failed: {type(export_error).__name__}")
        raise
    finally:
        try:
            export_native()
        except BaseException as export_error:
            if original is None:
                raise
            original.add_note(f"native evidence export failed: {type(export_error).__name__}")


def startup(mode: str) -> None:
    """Identity and pre-layout refusals are inside main's evidence/error boundary."""
    if ROOT == Path('/candidate'):
        from docker_snapshot import validate_snapshot
        validate_snapshot(ROOT)
    commit, tree = git_head(), git_tree()
    if mode == 'hosted-accept':
        from hosted_contract import require_hosted
        from offline_guard import deny_network
        require_hosted(os.environ, workspace=ROOT, commit=commit)
        deny_network()  # inherited by real native PM/resolver as well as tests
    if mode == 'accept' and (not sys.stdin.isatty() or not sys.stdout.isatty()):
        raise ValueError('ordinary foreground consent required before state creation')
    write_json('started.json', {'mode': mode, 'native_acceptance': False, 'commit': commit, 'tree': tree})


def interrupted(_signum: int, _frame: object) -> None:
    write_json("result.json", {"native_acceptance": False, "interrupted": True})
    raise SystemExit(22)


if __name__ == "__main__":
    raise SystemExit(main())
