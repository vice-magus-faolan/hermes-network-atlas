#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Owned disposable Docker acceptance; explicit local daemon, never live state.

Build/setup acquires public prerequisites separately. Runs have network none.
Local ordinary consent is interactive only; this wrapper never supplies an answer.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import time

from acceptance_support import HERMES_COMMIT, ROOT, git_head, git_tree
from docker_contract import (ENDPOINT, EVIDENCE_LIMIT, Identity, MODES, NAME, OWNER, OWNER_VALUE,
                             check_endpoint, cleanup_allowed, create_command, export_archive, validate_container,
                             verification_result)

BASE_FILES = ("Dockerfile", "base_setup.py", "dependencies.json")
BASE_LABEL = "org.network-atlas.acceptance.base"
BASE_TAG = "network-atlas-acceptance-base:current"
LOG_LIMIT = 8 * 1024 ** 2
STORAGE_REQUIRED = 2684354560  # 2 GiB build envelope plus 512 MiB unrelated-host reserve.
UPSTREAM_DIGEST = "sha256:998acd06f485adfd6890e3e15a4b542543e0cf22ff904310095da328a5e3e561"


def command(argv: list[str], *, timeout: int = 120, limit: int = LOG_LIMIT, data: bytes | None = None,
            env: dict | None = None) -> bytes:
    """Bound bytes/time; kill only the owned CLI group and preserve its failure."""
    import selectors
    process = subprocess.Popen(argv, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
                               env=env if env is not None else docker_environment())
    output = bytearray()
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout
    try:
        if process.stdout is None:
            raise RuntimeError("owned output pipe absent")
        if data is not None:
            if process.stdin is None:
                raise RuntimeError("owned input pipe absent")
            process.stdin.write(data)
            process.stdin.close()
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise TimeoutError("owned command deadline exceeded")
            for key, _event in selector.select(0.1):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                output.extend(chunk)
                if len(output) > limit:
                    raise RuntimeError("owned command output exceeded bound")
        code = process.wait(timeout=5)
        if code:
            raise subprocess.CalledProcessError(code, argv, bytes(output))
        return bytes(output)
    finally:
        selector.close()
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        if process.stdout is not None:
            process.stdout.close()
        if process.stdin is not None:
            process.stdin.close()


def docker_environment() -> dict[str, str]:
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "DOCKER_BUILDKIT": "0"}


class Docker:
    """No inherited credentials, context, proxy or arbitrary endpoint."""
    def __init__(self, client: Path, daemon: str):
        self.prefix = ["docker", "--host", ENDPOINT, "--config", str(client)]
        self.daemon = daemon
        identity = Identity("0" * 40, "0" * 40, "sha256:" + "0" * 64, daemon)
        self.info = self.json(["info", "--format", "{{json .}}"])
        check_endpoint(dict(os.environ), self.info, identity)

    def run(self, args: list[str], **kwargs) -> bytes:
        if args[0] in {"create", "start", "stop", "rm", "build", "rmi"}:
            info = json.loads(command([*self.prefix, "info", "--format", "{{json .}}"] ))
            if info.get("ID") != self.daemon:
                raise ValueError("daemon drift before mutation")
        return command([*self.prefix, *args], **kwargs)

    def json(self, args: list[str]):
        return json.loads(self.run(args))

    def interactive_start(self, identifier: str) -> None:
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise ValueError("ordinary consent requires a real foreground terminal")
        info = self.json(["info", "--format", "{{json .}}"])
        if info.get("ID") != self.daemon:
            raise ValueError("daemon drift before interactive mutation")
        result = subprocess.run([*self.prefix, "start", "--attach", "--interactive", identifier],
                                env=docker_environment(), timeout=900)
        if result.returncode:
            raise RuntimeError("ordinary interactive native run failed")

    def inspect(self, identifier: str) -> dict | None:
        # A list read distinguishes absence from daemon errors; never swallow them.
        ids = self.run(["ps", "-aq", "--no-trunc", "--filter", f"name=^/{NAME}$"]).decode().splitlines()
        if not ids:
            return None
        if len(ids) != 1:
            raise ValueError("ambiguous owned container")
        data = self.json(["inspect", ids[0]])[0]
        if identifier not in (NAME, data["Id"]):
            raise ValueError("unexpected container ID")
        return data


def clean_checkout() -> tuple[str, str]:
    if command(["git", "-C", str(ROOT), "status", "--porcelain=v1", "--untracked-files=all"]):
        raise ValueError("commit complete clean candidate before Docker operations")
    return git_head(), git_tree()


def private_root() -> Path:
    scratch = Path(os.environ["TMPDIR"])
    if not scratch.is_absolute() or scratch.resolve(strict=True) != scratch:
        raise ValueError("existing literal scratch directory required")
    root = scratch / "atlas-docker"
    if root.is_symlink():
        raise ValueError("control root symlink refused")
    root.mkdir(mode=0o700, exist_ok=True)
    if root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
        raise ValueError("private owned control directory required")
    return root


@contextmanager
def lease(root: Path):
    """One attempt across all modes/candidates; retain evidence instead of suffix retries."""
    with (root / "lease").open("a+") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def snapshot(source: Path, commit: str, destination: Path) -> None:
    """Public committed archive plus its public shallow commit object, not host .git."""
    archive = command(["git", "-C", str(source), "archive", commit], limit=256 * 1024 ** 2)
    destination.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        bundle.extractall(destination, filter="data")
    command(["git", "-C", str(destination), "init", "-q"])
    command(["git", "-C", str(destination), "add", "."])
    tree = command(["git", "-C", str(destination), "write-tree"]).decode().strip()
    expected = command(["git", "-C", str(source), "rev-parse", f"{commit}^{{tree}}"] ).decode().strip()
    if tree != expected:
        raise ValueError("archived complete tree differs")
    commit_bytes = command(["git", "-C", str(source), "cat-file", "commit", commit])
    restored = command(["git", "-C", str(destination), "hash-object", "-t", "commit", "-w", "--stdin"], data=commit_bytes).decode().strip()
    if restored != commit:
        raise ValueError("public commit object differs")
    command(["git", "-C", str(destination), "update-ref", "HEAD", commit])
    (destination / ".git" / "shallow").write_text(commit + "\n")
    if command(["git", "-C", str(destination), "status", "--porcelain=v1", "--untracked-files=all"]):
        raise ValueError("archived candidate not clean")


def base_context(source: Path, destination: Path) -> str:
    """Only three explicit committed recipe files plus complete public core archive."""
    if git_head(source) != HERMES_COMMIT:
        raise ValueError("pinned public Hermes checkout required")
    destination.mkdir(mode=0o700)
    hashes = {}
    for name in BASE_FILES:
        payload = command(["git", "-C", str(ROOT), "show", f"HEAD:docker/{name}"])
        (destination / name).write_bytes(payload)
        hashes[name] = hashlib.sha256(payload).hexdigest()
    archive = command(["git", "-C", str(source), "archive", HERMES_COMMIT], limit=256 * 1024 ** 2)
    (destination / "hermes.tar").write_bytes(archive)
    hashes["hermes.tar"] = hashlib.sha256(archive).hexdigest()
    return hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()


def require_supported_builder(info: dict) -> None:
    """Fail before effects where the proposed legacy build/cache plan is not established."""
    if info.get("Driver") != "overlay2" or info.get("DriverStatus"):
        raise ValueError("no reviewed bounded/owned build backend for this daemon; legacy build refused before effects")


def build_base(docker: Docker, root: Path, source: Path) -> dict:
    """No global prune/cache cleanup; legacy --rm builder avoids a persistent BuildKit cache."""
    require_supported_builder(docker.info)
    if docker.run(["ps", "-aq", "--filter", f"label={OWNER}={OWNER_VALUE}"]).strip():
        raise ValueError("active owned container prevents base build")
    if docker.run(["image", "ls", "-q", "--filter", f"label={OWNER}={OWNER_VALUE}"]).strip():
        raise ValueError("existing owned base: reuse it or explicitly retire after last consumer")
    for path in (Path("/var/lib/containerd"), root):
        if shutil.disk_usage(path).free < STORAGE_REQUIRED:
            raise RuntimeError(f"insufficient conservative build headroom at {path}: require {STORAGE_REQUIRED} bytes")
    context = root / "context"
    if context.exists():
        raise ValueError("owned context residue requires explicit inspection")
    try:
        key = base_context(source, context)
        argv = ["build", "--rm=true", "--force-rm=true", "--no-cache", "--memory", "3g",
                "--build-arg", f"BASE_KEY={key}",
                "--label", f"{OWNER}={OWNER_VALUE}", "--label", f"{BASE_LABEL}={key}",
                "--tag", BASE_TAG, str(context)]
        log = docker.run(argv, timeout=1800)
        (root / "build.log").write_bytes(log)
        data = docker.json(["image", "inspect", BASE_TAG])[0]
        if data["Config"]["Labels"].get(BASE_LABEL) != key:
            raise ValueError("built base identity mismatch")
        result = {"image": data["Id"], "base_key": key, "size": data["Size"], "daemon": docker.daemon,
                  "upstream_digest": UPSTREAM_DIGEST, "core_commit": HERMES_COMMIT,
                  "dependency_inputs": json.loads((context / "dependencies.json").read_text()),
                  "dependency_inventory": None}
        (root / "base.json").write_text(json.dumps(result, indent=2))
        return result
    except subprocess.CalledProcessError as exc:
        (root / "build.log").write_bytes(exc.output)
        raise
    finally:
        if context.exists() and not context.is_symlink():
            shutil.rmtree(context)
        # Intermediate image ownership is explicit but deletion needs ID/consumer readback.
        # Leave failures visible, never silently prune unrelated shared layers.
        rows = docker.run(["image", "ls", "--filter", f"label={OWNER}={OWNER_VALUE}", "--format", "{{json .}}"]).decode().splitlines()
        (root / "build-residue.json").write_text(json.dumps([json.loads(row) for row in rows]))


def teardown(docker: Docker, identity: Identity) -> None:
    data = docker.inspect(NAME)
    if data is None or not cleanup_allowed(data, identity):
        return
    identifier = data["Id"]
    if data["State"]["Running"]:
        docker.run(["stop", "--time", "5", identifier], timeout=20)
    data = docker.inspect(identifier)
    if data is None or not cleanup_allowed(data, identity):
        raise ValueError("cleanup target drift")
    docker.run(["rm", identifier])
    if docker.inspect(NAME) is not None:
        raise RuntimeError("owned container cleanup residue")


def wait_container(docker: Docker, identifier: str, deadline: float) -> dict:
    while time.monotonic() < deadline:
        data = docker.inspect(identifier)
        if data is None:
            raise RuntimeError("container disappeared before evidence export")
        if not data["State"]["Running"]:
            return data
        time.sleep(0.2)
    raise TimeoutError("container operation deadline exceeded")


def validate_base(data: dict, record: dict, daemon: str) -> None:
    labels = data["Config"].get("Labels", {})
    expected = {OWNER: OWNER_VALUE, BASE_LABEL: record["base_key"],
                "org.network-atlas.acceptance.hermes": HERMES_COMMIT,
                "org.network-atlas.acceptance.upstream": UPSTREAM_DIGEST}
    if (data["Id"] != record["image"] or record["daemon"] != daemon
            or record["upstream_digest"] != UPSTREAM_DIGEST or record["core_commit"] != HERMES_COMMIT
            or any(labels.get(key) != value for key, value in expected.items())):
        raise ValueError("owned base key/upstream/core/image/daemon identity mismatch")


def attempt_preflight(docker: Docker, root: Path, image: str, mode: str) -> tuple[Identity, Path]:
    if mode == "accept" and (not sys.stdin.isatty() or not sys.stdout.isatty()):
        raise ValueError("unattended ordinary consent refused before effects")
    commit, tree = clean_checkout()
    identity = Identity(commit, tree, image, docker.daemon)
    base = docker.json(["image", "inspect", image])[0]
    record = json.loads((root / "base.json").read_text())
    validate_base(base, record, docker.daemon)
    if base["Id"] != image:
        raise ValueError("requested image differs from base record")
    if mode == "accept" and record["dependency_inventory"] is None:
        raise ValueError("real base inventory canary required before native acceptance")
    if docker.run(["ps", "-aq", "--filter", f"label={OWNER}={OWNER_VALUE}"]).strip() or docker.inspect(NAME):
        raise ValueError("existing container/active lease refused, never replacement")
    attempts = root / "evidence"
    attempts.mkdir(mode=0o700, exist_ok=True)
    if len(list(attempts.iterdir())) >= 8 or sum(path.stat().st_size for path in attempts.rglob("*") if path.is_file()) > 256 * 1024 ** 2:
        raise ValueError("retained evidence storage bound; last-consumer retirement required")
    attempt = attempts / f"{commit}-{mode}"
    attempt.mkdir(mode=0o700)
    (attempt / "incoming").mkdir(mode=0o700)
    return identity, attempt


def collect_export(docker: Docker, attempt: Path, identity: Identity) -> dict:
    current = docker.inspect(NAME)
    if current is None:
        return {}
    cleanup_allowed(current, identity)
    if current["State"]["Running"]:
        docker.run(["stop", "--time", "5", current["Id"]], timeout=20)
    (attempt / "container.log").write_bytes(docker.run(["logs", current["Id"]]))
    incoming = attempt / "incoming"
    archive = evidence_archive(incoming)
    hashes = export_archive(archive, attempt / "export")
    return {"export_hashes": hashes}


def evidence_archive(incoming: Path) -> bytes:
    """Validate mounted export without following any untrusted link or directory."""
    buffer = io.BytesIO()
    total = 0
    entries = list(incoming.iterdir())
    if len(entries) > 64:
        raise ValueError("too many export members")
    with tarfile.open(fileobj=buffer, mode="w") as bundle:
        for path in entries:
            if path.is_symlink() or not path.is_file():
                raise ValueError("unsafe export member")
            total += path.stat().st_size
            if total > EVIDENCE_LIMIT:
                raise ValueError("export exceeds byte bound")
            with path.open("rb") as stream:
                member = tarfile.TarInfo(path.name)
                member.size = path.stat().st_size
                bundle.addfile(member, stream)
    return buffer.getvalue()


def exported_outcome(attempt: Path, mode: str, identity: Identity, code: int) -> dict:
    result = json.loads((attempt / "export" / "result.json").read_text())
    expected = {"smoke": 0, "fail": 21, "refusal": 20, "interrupt": 22, "accept": 0}
    if code != expected.get(mode) or result.get("native_acceptance") != (mode == "accept"):
        raise ValueError("unexpected container exit/acceptance outcome")
    fields = {"smoke": "packet_denial_smoke", "fail": "intentional_failure", "refusal": "ordinary_refusal",
              "interrupt": "interrupted"}
    if mode != "accept":
        if result.get(fields[mode]) is not True:
            raise ValueError("missing genuine canary result")
        return {"canary_verified": True}
    native = json.loads((attempt / "export" / "admission.json").read_text())
    if (native.get("candidate_commit") != identity.commit or native.get("candidate_tree") != identity.tree
            or native.get("installed_tree") != identity.tree or native.get("enabled") is not True):
        raise ValueError("exported native receipt identity/selection mismatch")
    log = (attempt / "export" / "canonical.log").read_text()
    parsed = verification_result(log, code)
    if result.get("tests") != parsed["tests"]:
        raise ValueError("exported count differs from real canonical result")
    return {"native_acceptance": True, "canonical": parsed}


def finish_attempt(docker: Docker, root: Path, attempt: Path, identity: Identity, outcome: dict) -> None:
    try:
        outcome.update(collect_export(docker, attempt, identity))
        if "error" not in outcome:
            outcome.update(exported_outcome(attempt, outcome["mode"], identity, outcome["exit_code"]))
        inventory = attempt / "export" / "base-inventory.json"
        if inventory.is_file():
            record = json.loads((root / "base.json").read_text())
            value = json.loads(inventory.read_text())
            if value["inputs"] != record["dependency_inputs"]:
                raise ValueError("actual image dependency inputs mismatch")
            record["dependency_inventory"] = value
            (root / "base.json").write_text(json.dumps(record, sort_keys=True, indent=2))
    except BaseException as exc:
        outcome["export_error"] = type(exc).__name__ + ": " + str(exc)
    try:
        teardown(docker, identity)
        outcome["cleanup_verified"] = True
    except BaseException as exc:
        outcome["cleanup_error"] = type(exc).__name__ + ": " + str(exc)
    candidate = root / "candidate"
    if candidate.exists() and not candidate.is_symlink() and docker.inspect(NAME) is None:
        shutil.rmtree(candidate)
    (attempt / "outcome.json").write_text(json.dumps(outcome, indent=2, sort_keys=True))


def run_attempt(docker: Docker, root: Path, image: str, mode: str) -> dict:
    identity, attempt = attempt_preflight(docker, root, image, mode)
    candidate = root / "candidate"
    outcome = {"identity": identity.labels(), "mode": mode, "native_acceptance": False}
    try:
        snapshot(ROOT, identity.commit, candidate)
        docker.run(create_command(identity, candidate, mode, attempt / "incoming"))
        inspected = docker.inspect(NAME)
        if inspected is None:
            raise RuntimeError("created container absent")
        identifier = validate_container(inspected, identity, candidate, mode, attempt / "incoming")
        (attempt / "created.json").write_text(json.dumps(docker.inspect(identifier), indent=2))
        if mode == "accept":
            docker.interactive_start(identifier)
        else:
            docker.run(["start", identifier])
        deadline = time.monotonic() + (2 if mode == "interrupt" else 900)
        try:
            state = wait_container(docker, identifier, deadline)
        except TimeoutError:
            if mode != "interrupt":
                raise
            docker.run(["stop", "--time", "5", identifier], timeout=20)
            state = wait_container(docker, identifier, time.monotonic() + 5)
        outcome["exit_code"] = state["State"]["ExitCode"]
        outcome["oom_killed"] = state["State"].get("OOMKilled", False)
    except BaseException as exc:
        outcome["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        finish_attempt(docker, root, attempt, identity, outcome)
    return outcome


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("action", choices=("build", "run", "preflight"))
    parser.add_argument("--daemon", required=True)
    parser.add_argument("--hermes-source", type=Path)
    parser.add_argument("--image")
    parser.add_argument("--mode", choices=MODES, default="smoke")
    args = parser.parse_args()
    clean_checkout()
    root = private_root()
    with lease(root):
        client = root / "client"
        client.mkdir(mode=0o700, exist_ok=True)
        docker = Docker(client, args.daemon)
        if args.action == "preflight":
            require_supported_builder(docker.info)
            result = {"preflight_only": True, "daemon": docker.daemon}
        elif args.action == "build":
            if args.hermes_source is None:
                raise ValueError("exact public Hermes source required")
            result = build_base(docker, root, args.hermes_source)
        else:
            if args.image is None:
                raise ValueError("immutable owned image required")
            result = run_attempt(docker, root, args.image, args.mode)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1 if any(key in result for key in ("error", "export_error", "cleanup_error")) else 0


if __name__ == "__main__":
    raise SystemExit(main())
