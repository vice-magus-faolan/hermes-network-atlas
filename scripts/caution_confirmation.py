# SPDX-License-Identifier: GPL-3.0-or-later
"""Inactive, externally authorized ordinary CAUTION confirmation for scratch setup.

The invoker owns the trust anchor and scope, outside candidate-controlled paths.
This is not a sandbox for malicious candidate code or another same-UID process.
No trust anchor, signer, approval or workflow activation is shipped here.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import subprocess
import sys
import time

from acceptance_support import HERMES_COMMIT, ROOT, file_hash, git_head, git_tree
from core_identity import source_manifest, require_identity

NAMESPACE = "network-atlas-native-caution-v1"
PROMPT = b"Install anyway? Only continue if you trust the source. [y/N]:"
# Digest of path/type/executable-bit/content for EVERY member of the exact
# public git archive. Python bytecode caches/VCS metadata are not source members.
CORE_SOURCE_DIGEST = "6c136cc4cf643181091c0077b85ff1fc86615cd841425e91ae1269f951137c79"
CORE_TREE = "85282aca9d246911005dba7adbdf3ca3ddd04df5"
SCANNER_HASHES = {
    "tools/plugin_guard.py": "d4ad147e69b1768aa6ecc44d091f4ef09251c10160275ba99c8bb7cb53155788",
    "tools/plugin_guard_context.py": "c1788bd81b22684983aa748e960e3699132f49509a8d99d96e51f5a144e2b271",
    "tools/skills_guard.py": "c517505f60489797e321289726ca4cf101ee2e869e0e922983c7aed117d2eb92",
    "hermes_cli/plugins_cmd_install.py": "27468ecba0eb480bdc0ce04bb2827808ba3029dcb06f6a875de007452eeae79f",
}


def canonical(value: object) -> bytes:
    """Stable signed bytes; timestamps, scratch paths and summary names are excluded."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def marker(request: dict) -> bytes:
    return b"ATLAS_CAUTION_APPROVED:" + hashlib.sha256(canonical(request)).hexdigest().encode()


def verify_core(source: Path) -> None:
    """Authenticate the complete public core snapshot before importing its code."""
    require_identity(source_manifest(source), expected_digest=CORE_SOURCE_DIGEST)


def scan_request(source: Path, candidate: Path, origin_commit: str, scope: str) -> dict:
    """Scan the complete clean Git tree with the unchanged exact pinned scanner."""
    if not re.fullmatch(r"[0-9a-f]{40}", origin_commit):
        raise ValueError("full original candidate commit required")
    if not scope or len(scope) > 512 or any(ord(char) < 32 or ord(char) == 127 for char in scope):
        raise ValueError("explicit bounded confirmation scope required")
    if subprocess.check_output(["git", "-C", str(candidate), "status", "--porcelain=v1", "--untracked-files=all"]):
        raise ValueError("complete clean candidate tree required")
    if {name: file_hash(source / name) for name in SCANNER_HASHES} != SCANNER_HASHES:
        raise ValueError("pinned scanner/native installer identity mismatch")
    verify_core(source)
    sys.path.insert(0, str(source))
    from tools.plugin_guard import PLUGIN_SCANNER_VERSION, scan_plugin, should_allow_plugin_install
    result = scan_plugin(candidate)
    allowed, _reason = should_allow_plugin_install(result, force=False)
    findings = sorted((asdict(item) for item in result.findings), key=canonical)
    return {"schema": 1, "purpose": NAMESPACE, "scope": scope,
            "candidate_commit": origin_commit, "candidate_tree": git_tree(candidate),
            "hermes_commit": HERMES_COMMIT, "hermes_tree": CORE_TREE,
            "hermes_source_digest": CORE_SOURCE_DIGEST, "scanner_version": PLUGIN_SCANNER_VERSION,
            "scanner_files": SCANNER_HASHES, "verdict": result.verdict,
            "ordinary_decision": allowed, "findings": findings}


def external_file(path: Path, forbidden: tuple[Path, ...]) -> Path:
    """Reject candidate/fixture-local authority, including symlink escapes into it."""
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or any(resolved.is_relative_to(root.resolve()) for root in forbidden):
        raise ValueError("approval and trust anchor must be outside candidate-controlled roots")
    if resolved.stat().st_size > 1024 * 1024:
        raise ValueError("approval input exceeds bound")
    return resolved


def verify_approval(request: dict, approval: Path, signature: Path, allowed_signers: Path,
                    principal: str, forbidden: tuple[Path, ...]) -> None:
    """Require an exact detached SSH signature from the invoker's external anchor.

    Only CAUTION's ordinary pending decision can be confirmed. SAFE needs no route;
    DANGEROUS and unknown verdicts refuse even a correctly signed authorization.
    """
    if request.get("verdict") != "caution" or request.get("ordinary_decision") is not None:
        raise ValueError("only ordinary CAUTION may be confirmed; dangerous always refuses")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", principal):
        raise ValueError("explicit valid signer principal required")
    approval, signature, allowed_signers = (external_file(path, forbidden)
                                           for path in (approval, signature, allowed_signers))
    payload = approval.read_bytes()
    if payload != canonical(request):
        raise ValueError("approval does not bind exact commit/tree/scope/scanner/full findings")
    result = subprocess.run(["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(allowed_signers),
                             "-I", principal, "-n", NAMESPACE, "-s", str(signature)],
                            input=payload, capture_output=True, timeout=15)
    if result.returncode:
        raise ValueError("external approval signature refused")


def stop_owned(process: subprocess.Popen) -> None:
    # The leader can exit while its descendants still hold the PTY. This is
    # our isolated session/group, never an unrelated worker's process group.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def receive_prompt(master: int, output: bytearray, output_limit: int) -> bool:
    """Read one bounded PTY segment; EOF is not confirmation."""
    if not select.select([master], [], [], 0.1)[0]:
        return True
    try:
        data = os.read(master, 65536)
    except OSError:
        return False
    if not data:
        return False
    output.extend(data)
    if len(output) > output_limit:
        raise RuntimeError("native confirmation output bound exceeded")
    return True


def install_confirmed(command: list[str], root: Path, env: dict, request: dict,
                      timeout: float = 600, output_limit: int = 4 * 1024 * 1024) -> str:
    """PTY is only prompt transport, never authority. Child verifies before marker.

    Answer exactly once, only after the child has validated the external signature
    and printed the request-bound marker. Native scanning and its ordinary prompt
    remain unchanged. Unknown prompts, missing markers and bounds refuse/clean up.
    """
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
    answered = False
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if not receive_prompt(master, output, output_limit):
                break
            approved = marker(request) + b"\r\n" in output
            if approved and PROMPT in output and not answered:
                os.write(master, b"y\n")
                answered = True
            # Drain PTY output to EOF even after exit: the final segment may
            # contain the prompt/error, and must not disappear in a poll race.
        if time.monotonic() >= deadline:
            raise RuntimeError("native confirmation deadline exceeded")
        if process.wait(timeout=2) != 0 or not answered:
            raise RuntimeError("ordinary confirmed native installation failed: " + output.decode(errors="replace"))
        return output.decode(errors="replace")
    finally:
        stop_owned(process)
        os.close(master)


def main() -> int:
    """Packet-denied scan challenge only; never sign, install or enable anything."""
    import argparse
    from offline_guard import deny_network
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--hermes-source", required=True, type=Path)
    parser.add_argument("--candidate", type=Path, default=ROOT)
    parser.add_argument("--scope", required=True)
    args = parser.parse_args()
    deny_network()
    request = scan_request(args.hermes_source.resolve(), args.candidate.resolve(), git_head(args.candidate), args.scope)
    sys.stdout.buffer.write(canonical(request))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
