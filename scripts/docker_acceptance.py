#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Owned disposable Docker acceptance; explicit local daemon, never live state.

Build/setup acquires public prerequisites separately. Runs have network none.
Local ordinary consent is interactive only; this wrapper never supplies an answer.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import replace
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
from docker_builder import (BOOTSTRAP_NAME, INPUT_FILES, build_owned, registry_path, validate_plan,
                            register_consumer, BootstrapIdentity, verify_final_image)
from acquisition_plan import parse_plan
from docker_evidence import BoundedDirectory, archive_directory, json_bytes, regular_read
from docker_contract import (ENDPOINT, EVIDENCE_LIMIT, Identity, MODES, NAME, OWNER, OWNER_VALUE,
                             check_endpoint, cleanup_allowed, create_command, export_archive, validate_container,
                             verification_result, container_identity_validation)

BASE_FILES = tuple(name for name in INPUT_FILES if name not in {"hermes.tar", "hermes.commit"})
BASE_LABEL = "org.network-atlas.acceptance.base"
BASE_TAG = "network-atlas-acceptance-base:current"
LOG_LIMIT = 8 * 1024 ** 2

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
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}


class Docker:
    """No inherited credentials, context, proxy or arbitrary endpoint."""
    def __init__(self, client: Path, daemon: str):
        self.prefix = ["docker", "--host", ENDPOINT, "--config", str(client)]
        self.daemon = daemon
        identity = Identity("0" * 40, "0" * 40, "sha256:" + "0" * 64, daemon)
        self.info = self.json(["info", "--format", "{{json .}}"])
        check_endpoint(dict(os.environ), self.info, identity)

    def run(self, args: list[str], **kwargs) -> bytes:
        if args[0] in {"create", "start", "stop", "rm", "commit", "pull"}:
            info = json.loads(command([*self.prefix, "info", "--format", "{{json .}}"] ))
            identity = Identity("0" * 40, "0" * 40, "sha256:" + "0" * 64, self.daemon)
            check_endpoint(dict(os.environ), info, identity)
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

    def inspect(self, identifier: str, *, name: str = NAME) -> dict | None:
        # A list read distinguishes absence from daemon errors; never swallow them.
        if name not in (NAME, BOOTSTRAP_NAME):
            raise ValueError("fixed owned container names only")
        ids = self.run(["ps", "-aq", "--no-trunc", "--filter", f"name=^/{name}$"]).decode().splitlines()
        if not ids:
            return None
        if len(ids) != 1:
            raise ValueError("ambiguous owned container")
        data = self.json(["inspect", ids[0]])[0]
        if identifier != name and identifier != data.get("Id"):
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
    # Independent controller identity, outside the candidate's committed tree.
    # Only this verified reconstruction is mounted read-only at /candidate.
    from docker_snapshot import CONFIG, RECORD
    (destination / '.git' / 'config').write_bytes(CONFIG)
    path = destination / '.git' / RECORD
    with path.open('xb') as stream:
        stream.write(json_bytes({'commit': commit, 'tree': expected}))
    path.chmod(0o444)


def base_context(source: Path, destination: Path, plan: dict) -> str:
    """Fixed committed public inputs; retained artifacts go into ordinary rootfs."""
    validate_plan(plan)
    top = command(["git", "-C", str(source), "rev-parse", "--show-toplevel"]).decode().strip()
    if top != str(source.resolve()) or git_head(source) != HERMES_COMMIT:
        raise ValueError("pinned public Hermes checkout required")
    if command(["git", "-C", str(source), "status", "--porcelain=v1", "--untracked-files=all"]):
        raise ValueError("clean actual public core checkout required")
    validate_pinned_sources(source, plan)
    destination.mkdir(mode=0o755)
    hashes = {}
    for name in BASE_FILES:
        target = "scripts/offline_guard.py" if name == "offline_guard.py" else f"docker/{name}"
        payload = command(["git", "-C", str(ROOT), "show", f"HEAD:{target}"])
        (destination / name).write_bytes(payload)
        hashes[name] = hashlib.sha256(payload).hexdigest()
    archive = command(["git", "-C", str(source), "archive", HERMES_COMMIT], limit=256 * 1024 ** 2)
    expected_archive = next(item for item in plan["artifacts"] if item["category"] == "core-archive")
    if len(archive) != expected_archive["compressed_bytes"]:
        raise ValueError("public core archive differs from resolved acquisition length")
    (destination / "hermes.tar").write_bytes(archive)
    hashes["hermes.tar"] = hashlib.sha256(archive).hexdigest()
    commit = command(["git", "-C", str(source), "cat-file", "commit", HERMES_COMMIT], limit=65536)
    (destination / "hermes.commit").write_bytes(commit)
    hashes["hermes.commit"] = hashlib.sha256(commit).hexdigest()
    if hashes != plan["inputs"]:
        raise ValueError("committed recipe/core public input hash mismatch")
    (destination / "acquisition.json").write_bytes(json_bytes(plan))
    # Exact PUBLIC context only, under a private controller parent. Setup UID0
    # with cap-drop ALL cannot bypass a host UID1000 mode0700 input mount.
    destination.chmod(0o755)
    for path in destination.iterdir():
        path.chmod(0o644)
    return hashlib.sha256(json_bytes({"inputs": hashes, "plan": plan})).hexdigest()


def validate_pinned_sources(source: Path, plan: dict) -> None:
    """Bind source projections to actual committed public inputs, not caller hashes."""
    lock = command(["git", "-C", str(source), "show", f"{HERMES_COMMIT}:pm/lock.json"])
    uv = command(["git", "-C", str(source), "show", f"{HERMES_COMMIT}:uv.lock"])
    deps = command(["git", "-C", str(ROOT), "show", "HEAD:docker/dependencies.json"])
    expected = plan["sources"]
    if (lock != expected["pm"]["lock"]["text"].encode() or deps != expected["dependencies"]["text"].encode()
            or hashlib.sha256(uv).hexdigest() != expected["uv_lock_sha256"]):
        raise ValueError("source projection differs from exact native/recipe committed metadata")


def require_supported_builder(info: dict) -> None:
    """Container commit needs no Dockerfile builder; unknown storage still refuses."""
    supported = info.get("Driver") == "overlay2" or (info.get("Driver") == "overlayfs" and
                 ["driver-type", "io.containerd.snapshotter.v1"] in info.get("DriverStatus", []))
    if not supported:
        raise ValueError("unknown image storage backend refused before effects")


def build_base(docker: Docker, root: Path, source: Path, plan: dict | None = None, registry: Path | None = None) -> dict:
    """Separately reviewed foreground root-inside-container public setup ONLY."""
    require_supported_builder(docker.info)
    if plan is None or registry is None:
        raise ValueError("complete resolved public plan/durable registry required before effects")
    return build_owned(docker, root, source, plan, registry,
                       foreground=sys.stdin.isatty() and sys.stdout.isatty())


def teardown(docker: Docker, identity: Identity, *, attempt: Path | None = None) -> None:
    data = read_container(docker, identity, attempt, 'cleanup')
    if data is None:
        return
    identity = replace(identity, container_id=data['Id'])
    identifier = data["Id"]
    if data["State"]["Running"]:
        docker.run(["stop", "--time", "5", identifier], timeout=20)
    data = read_container(docker, identity, attempt, 'cleanup-stopped')
    if data is None:
        raise ValueError("cleanup target drift")
    docker.run(["rm", identifier])
    if read_container(docker, identity, attempt, 'cleanup-absent') is not None:
        raise RuntimeError("owned container cleanup residue")


def wait_container(docker: Docker, identifier: str, deadline: float, *, identity: Identity | None = None) -> dict:
    while time.monotonic() < deadline:
        data = docker.inspect(identifier)
        if data is None:
            raise RuntimeError("container disappeared before evidence export")
        if identity is not None:
            cleanup_allowed(data, identity)
        if not data["State"]["Running"]:
            return data
        time.sleep(0.2)
    raise TimeoutError("container operation deadline exceeded")


def validate_base(data: dict, record: dict, daemon: str) -> None:
    """Reconstruct exact eight-label authority, not a receipt/inspect subset match."""
    identity = BootstrapIdentity(record['base_key'], daemon, record['image'], record['plan_hash'])
    actual = verify_final_image(data, identity, returned_image=record['image'])
    keys = ('base_key', 'daemon', 'upstream_digest', 'core_commit', 'core_tree', 'plan_hash', 'labels', 'rootfs_layers')
    if any(record.get(key) != actual[key] for key in keys):
        raise ValueError("owned base key/upstream/core/image/daemon identity mismatch")


def attempt_preflight(docker: Docker, root: Path, image: str, mode: str, registry: Path | None = None) -> tuple[Identity, Path]:
    if mode == "accept" and (not sys.stdin.isatty() or not sys.stdout.isatty()):
        raise ValueError("unattended ordinary consent refused before effects")
    commit, tree = clean_checkout()
    identity = Identity(commit, tree, image, docker.daemon)
    base = docker.json(["image", "inspect", image])[0]
    if registry is None:
        raise ValueError("durable owned base registry required")
    record = json.loads(regular_read(registry / "base.json", 512 * 1024))
    validate_base(base, record, docker.daemon)
    identity = replace(identity, base_labels=tuple(sorted(record['labels'].items())))
    if base["Id"] != image:
        raise ValueError("requested image differs from base record")
    if mode == "accept" and record["dependency_inventory"] is None:
        raise ValueError("real base inventory canary required before native acceptance")
    if docker.run(["ps", "-aq", "--filter", f"label={OWNER}={OWNER_VALUE}"]).strip() or docker.inspect(NAME):
        raise ValueError("existing container/active lease refused, never replacement")
    attempts = root / "evidence"
    attempts.mkdir(mode=0o700, exist_ok=True)
    reserved = 3 * EVIDENCE_LIMIT + LOG_LIMIT + 1024 ** 2
    if len(list(attempts.iterdir())) >= 8 or sum(path.stat().st_size for path in attempts.rglob("*") if path.is_file()) + reserved > 256 * 1024 ** 2:
        raise ValueError("retained evidence storage bound; last-consumer retirement required")
    attempt = attempts / f"{commit}-{mode}"
    attempt.mkdir(mode=0o700)
    (attempt / "incoming").mkdir(mode=0o700)
    register_consumer(registry, identity, attempt, "active")
    return identity, attempt


def read_container(docker: Docker, identity: Identity, attempt: Path | None, stage: str,
                   *, validator: Callable[[dict], object] | None = None, required: bool = False) -> dict | None:
    """Retain actual fixed-name inspect BEFORE predicates; evidence is not authority.

    A stricter 512 KiB parsed readback ceiling fits the existing aggregate/count
    budgets. Diagnostic errors never displace a primary inspect/predicate error;
    valid readback with failed mandatory persistence still fails before effects.
    """
    metadata = attempt / 'metadata' if attempt is not None else None
    errors = []
    audit = {'stage': stage, 'daemon': identity.daemon, 'commit': identity.commit, 'tree': identity.tree,
             'image': identity.image, 'returned_container_id': identity.container_id,
             'base_labels': dict(identity.base_labels), 'verified': False,
             'provenance': 'actual parsed fixed-name Docker container inspect; not inferred config'}
    original = None
    try:
        data = docker.inspect(NAME)
        payload = json_bytes(data)
        audit.update(readback_bytes=len(payload), readback_sha256=hashlib.sha256(payload).hexdigest())
        if len(payload) > 512 * 1024:
            raise ValueError('container readback diagnostic bound exceeded')
        container_diagnostic_write(metadata, stage + '.json', data, errors)
        audit['absent'] = data is None
        validate_container_readback(data, identity, audit, validator, required)
        return data
    except BaseException as exc:
        original = exc
        audit.update(verified=False, error=type(exc).__name__ + ': ' + str(exc)[:2048])
        raise
    finally:
        finish_container_diagnostics(metadata, stage, audit, errors, original)


def validate_container_readback(data: object, identity: Identity, audit: dict,
                                validator: Callable[[dict], object] | None, required: bool) -> None:
    if data is None:
        if required:
            raise RuntimeError('created container absent')
        return
    if not isinstance(data, dict):
        raise ValueError('container inspect requires one actual object')
    audit.update(container_identity_validation(data, identity))
    cleanup_allowed(data, identity)
    if validator is not None:
        validator(data)


def container_diagnostic_write(metadata: Path | None, name: str, value: object, errors: list) -> None:
    if metadata is None:
        return
    try:
        metadata.mkdir(mode=0o700, exist_ok=True)
        BoundedDirectory(metadata).json(name, value)
    except BaseException as exc:
        errors.append(exc)


def finish_container_diagnostics(metadata: Path | None, stage: str, audit: dict, errors: list,
                                 original: BaseException | None) -> None:
    audit['diagnostic_errors'] = [type(exc).__name__ + ': ' + str(exc)[:2048] for exc in errors]
    container_diagnostic_write(metadata, stage + '-validation.json', audit, errors)
    if not errors:
        return
    if original is None:
        raise errors[0]
    for exc in errors:
        original.add_note('container diagnostic export failed: ' + type(exc).__name__ + ': ' + str(exc)[:2048])


def collect_export(docker: Docker, attempt: Path, identity: Identity, *, hosted_export: bool = False) -> dict:
    current = read_container(docker, identity, attempt, 'export')
    if current is None:
        return {}
    identity = replace(identity, container_id=current['Id'])
    if current["State"]["Running"]:
        docker.run(["stop", "--time", "5", current["Id"]], timeout=20)
    metadata = attempt / "metadata"
    metadata.mkdir(mode=0o700, exist_ok=True)
    # A container can fail before its log driver starts. Preserve State.Error
    # before log export, which may fail too, and still perform owned teardown.
    stopped = read_container(docker, identity, attempt, 'stopped')
    if stopped is None:
        raise ValueError("container absent or changed before stopped evidence export")
    BoundedDirectory(metadata).write("container.log", docker.run(["logs", current["Id"]], limit=4 * 1024 ** 2))
    incoming = attempt / "incoming"
    # Hosted runner UID can differ from container UID1000. Read ONLY the exact
    # owned export through Docker's bounded archive API; no host chown/sudo.
    archive = (docker.run(["cp", f"{current['Id']}:/export/.", "-"], limit=EVIDENCE_LIMIT)
               if hosted_export else evidence_archive(incoming))
    hashes = export_archive(archive, attempt / "export")
    return {"export_hashes": hashes}


def evidence_archive(incoming: Path) -> bytes:
    return archive_directory(incoming)


def validate_cold(cold: dict, native: dict, identity: Identity) -> None:
    expected = {"candidate_commit": identity.commit, "candidate_tree": identity.tree,
                "native_generation": native.get("native_generation"), "image": identity.image,
                "collected": False, "cold_native_selection": True}
    if any(cold.get(key) != value for key, value in expected.items()):
        raise ValueError("missing exact-image genuine cold native selection")


def exported_outcome(attempt: Path, mode: str, identity: Identity, code: int) -> dict:
    result = json.loads((attempt / "export" / "result.json").read_text())
    expected = {"smoke": 0, "fail": 21, "refusal": 20, "interrupt": 22, "accept": 0, "hosted-accept": 0}
    acceptance = mode in {"accept", "hosted-accept"}
    if code != expected.get(mode) or result.get("native_acceptance") != acceptance:
        raise ValueError("unexpected container exit/acceptance outcome")
    fields = {"smoke": "packet_denial_smoke", "fail": "intentional_failure", "refusal": "ordinary_refusal",
              "interrupt": "interrupted"}
    if not acceptance:
        if result.get(fields[mode]) is not True:
            raise ValueError("missing genuine canary result")
        return {"canary_verified": True}
    native = json.loads((attempt / "export" / "admission.json").read_text())
    if (native.get("candidate_commit") != identity.commit or native.get("candidate_tree") != identity.tree
            or native.get("installed_tree") != identity.tree or native.get("enabled") is not True):
        raise ValueError("exported native receipt identity/selection mismatch")
    cold = json.loads((attempt / "export" / "cold.json").read_text())
    validate_cold(cold, native, identity)
    log = (attempt / "export" / "canonical.log").read_text()
    parsed = verification_result(log, code)
    if result.get("tests") != parsed["tests"]:
        raise ValueError("exported count differs from real canonical result")
    return {"native_acceptance": True, "canonical": parsed}


def finish_attempt(docker: Docker, root: Path, attempt: Path, identity: Identity, outcome: dict, registry: Path | None = None) -> None:
    try:
        if outcome.get("hosted_export"):
            outcome.update(collect_export(docker, attempt, identity, hosted_export=True))
        else:
            outcome.update(collect_export(docker, attempt, identity))
        if "error" not in outcome:
            outcome.update(exported_outcome(attempt, outcome["mode"], identity, outcome["exit_code"]))
        inventory = attempt / "export" / "base-inventory.json"
        if inventory.is_file():
            if registry is None:
                raise ValueError("durable registry required for inventory readback")
            record = json.loads(regular_read(registry / "base.json", 512 * 1024))
            value = json.loads(inventory.read_text())
            if value != record["dependency_inventory"]:
                raise ValueError("actual image dependency inventory differs from registered base")
            verify_representation_export(attempt, value, outcome)
    except BaseException as exc:
        outcome["export_error"] = type(exc).__name__ + ": " + str(exc)
        outcome['export_error_notes'] = getattr(exc, '__notes__', [])
    try:
        teardown(docker, identity, attempt=attempt)
        outcome["cleanup_verified"] = True
    except BaseException as exc:
        outcome["cleanup_error"] = type(exc).__name__ + ": " + str(exc)
        outcome['cleanup_error_notes'] = getattr(exc, '__notes__', [])
    retain_attempt_consumer(registry, identity, attempt, outcome)
    try:
        export_attempt_outcome(docker, root, attempt, outcome)
    except BaseException as exc:
        outcome["outcome_export_error"] = type(exc).__name__ + ": " + str(exc)


def verify_representation_export(attempt: Path, inventory: dict, outcome: dict) -> None:
    if 'core_representation' not in inventory or 'error' in outcome:
        return  # Deliberate legacy-controller compatibility; new prepare refuses it.
    if outcome['mode'] not in {'smoke', 'refusal', 'accept', 'hosted-accept'}:
        return  # Intentional fail/interrupt modes do not materialize source.
    from core_representation import require_materialization
    proof = json.loads(regular_read(attempt / 'export/core-materialization.json', 32 * 1024))
    manifest = json.loads(regular_read(attempt / 'export/consumer-copy-manifest.json', 4 * 1024 ** 2))
    require_materialization(proof, inventory, manifest)


def export_attempt_outcome(docker: Docker, root: Path, attempt: Path, outcome: dict) -> None:
    candidate = root / 'candidate'
    if candidate.exists() and not candidate.is_symlink() and docker.inspect(NAME) is None:
        shutil.rmtree(candidate)
    metadata = attempt / 'metadata'
    metadata.mkdir(mode=0o700, exist_ok=True)
    BoundedDirectory(metadata).json('outcome.json', outcome)


def retain_attempt_consumer(registry: Path | None, identity: Identity, attempt: Path, outcome: dict) -> None:
    """Evidence persistence failure must not prevent durable consumer retention."""
    if registry is None:
        return
    try:
        register_consumer(registry, identity, attempt, 'retained-awaiting-review')
    except BaseException as exc:
        outcome['registry_error'] = type(exc).__name__ + ': ' + str(exc)


def run_attempt(docker: Docker, root: Path, image: str, mode: str, registry: Path | None = None, *, hosted: dict | None = None, hosted_export: bool = False) -> dict:
    if mode == "hosted-accept" or hosted_export:
        from hosted_contract import require_hosted
        require_hosted(os.environ, workspace=ROOT, commit=git_head())
    identity, attempt = attempt_preflight(docker, root, image, mode, registry)
    if registry is None:
        raise ValueError('durable registry required')
    candidate = root / "candidate"
    outcome = {"identity": identity.container_labels(), "mode": mode, "native_acceptance": False, "hosted_export": hosted_export}
    try:
        snapshot(ROOT, identity.commit, candidate)
        # Public snapshot search permissions only; private host controller parent
        # is not visible through the container bind. No broad host permission edit.
        candidate.chmod(0o755)
        if hosted_export:
            prepare_hosted_export(root, attempt)
        returned = docker.run(create_command(identity, candidate, mode, attempt / "incoming", hosted=hosted)).decode().strip()
        identity = replace(identity, container_id=returned)
        outcome['container_id'] = returned
        inspected = read_container(docker, identity, attempt, 'created', required=True,
                                   validator=lambda data: validate_container(data, identity, candidate, mode, attempt / 'incoming', hosted=hosted))
        if inspected is None:
            raise RuntimeError('created container absent')
        identifier = inspected['Id']
        register_consumer(registry, identity, attempt, 'active')
        if mode == "accept":
            docker.interactive_start(identifier)
        else:
            docker.run(["start", identifier])
        deadline = time.monotonic() + (2 if mode == "interrupt" else 900)
        try:
            state = wait_container(docker, identifier, deadline, identity=identity)
        except TimeoutError:
            if mode != "interrupt":
                raise
            read_container(docker, identity, attempt, 'interrupt', required=True)
            docker.run(["stop", "--time", "5", identifier], timeout=20)
            state = wait_container(docker, identifier, time.monotonic() + 5, identity=identity)
        outcome["exit_code"] = state["State"]["ExitCode"]
        outcome["oom_killed"] = state["State"].get("OOMKilled", False)
        if outcome["oom_killed"]:
            raise RuntimeError("owned acceptance OOM is failure")
    except BaseException as exc:
        outcome["error"] = type(exc).__name__ + ": " + str(exc)
        outcome['error_notes'] = getattr(exc, '__notes__', [])
    finally:
        finish_attempt(docker, root, attempt, identity, outcome, registry)
    return outcome


def prepare_hosted_export(root: Path, attempt: Path) -> None:
    """Permit UID1000 listing/write ONLY on an empty ephemeral export mount.

    All host ancestors stay private0700/owned. Docker exposes only this leaf;
    sticky mode prevents cross-owner replacement. Files remain container0600
    and the controller reads via the existing bounded Docker archive API.
    """
    if not root.is_absolute() or root.resolve(strict=True) != root or attempt.parent != root / 'evidence':
        raise ValueError('fixed owned attempt layout required')
    for path in (root, attempt.parent, attempt):
        require_private_directory(path)
    incoming = attempt / 'incoming'
    require_private_directory(incoming)
    if any(incoming.iterdir()):
        raise ValueError('empty one-use incoming directory required')
    incoming.chmod(0o1777)
    if incoming.stat().st_mode & 0o7777 != 0o1777:
        raise ValueError('ephemeral export mode readback drift')


def require_private_directory(path: Path) -> None:
    info = path.lstat()
    if path.is_symlink() or not path.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o7777 != 0o700:
        raise ValueError('private owned controller directory required')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("action", choices=("build", "run", "preflight"))
    parser.add_argument("--daemon", required=True)
    parser.add_argument("--hermes-source", type=Path)
    parser.add_argument("--image")
    parser.add_argument("--plan", type=Path, help="reviewed complete finite public acquisition plan")
    parser.add_argument("--registry", type=Path, required=True, help="explicit durable default-profile ownership registry")
    parser.add_argument("--mode", choices=MODES, default="smoke")
    args = parser.parse_args()
    if args.action == "build":
        from acquisition_plan import require_execution_ready
        require_execution_ready()
    clean_checkout()
    registry = registry_path(args.registry, Path(os.environ["TMPDIR"]))
    if args.action == "build" and (args.plan is None or not sys.stdin.isatty() or not sys.stdout.isatty()):
        raise ValueError("resolved plan and reviewed foreground first-setup invocation required before daemon access")
    plan = parse_plan(regular_read(args.plan, 1024 ** 2)) if args.plan is not None else None
    if args.action in ("preflight", "build"):
        validate_plan(plan if plan is not None else {})
    root = private_root()
    if args.action != "preflight":
        registry.mkdir(mode=0o700, parents=True, exist_ok=True)
    with lease(root):
        if args.action == "preflight":
            return preflight_only(root, args.daemon, plan)
        with lease(registry):
            return dispatch_action(root, args, plan, registry)


def preflight_only(root: Path, daemon: str, plan: dict) -> int:
    client = root / "client"
    client.mkdir(mode=0o700, exist_ok=True)
    docker = Docker(client, daemon)
    require_supported_builder(docker.info)
    from docker_builder import require_space
    result = require_space(plan, shutil.disk_usage("/var/lib/containerd").free)
    print(json.dumps({"preflight_only": True, "daemon": docker.daemon, "budget": result}, indent=2))
    return 0


def dispatch_action(root: Path, args, plan: dict | None, registry: Path) -> int:
        client = root / "client"
        client.mkdir(mode=0o700, exist_ok=True)
        docker = Docker(client, args.daemon)
        if args.action == "build":
            if args.hermes_source is None:
                raise ValueError("exact public Hermes source required")
            result = build_base(docker, root, args.hermes_source, plan, registry)
        else:
            if args.image is None:
                raise ValueError("immutable owned image required")
            result = run_attempt(docker, root, args.image, args.mode, registry)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1 if any(key in result for key in ("error", "export_error", "cleanup_error", "outcome_export_error", "registry_error", "resource_error")) else 0


if __name__ == "__main__":
    raise SystemExit(main())
