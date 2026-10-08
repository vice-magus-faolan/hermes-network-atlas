# SPDX-License-Identifier: GPL-3.0-or-later
"""Owned bootstrap/stopped-rootfs commit. No BuildKit, fallback or admission consent.

Execution requires an externally reviewed invocation, a resolved finite public
acquisition plan, a foreground operator and sufficient containerd headroom.
Plan validation alone is NOT operator authority or measured build success.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import time

from acceptance_support import HERMES_COMMIT
from docker_contract import OWNER, OWNER_VALUE, MEMORY, source_path, validate_environment
from docker_evidence import BoundedDirectory, json_bytes, regular_read
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "docker"))
from acquisition_plan import artifact, exact, validate_linkage, require_execution_ready
from acquisition_support import BASE_COMMAND

CORE_TREE = "008b644d38770b7de0835592ddaf19a708e2fa82"
UPSTREAM_DIGEST = "sha256:998acd06f485adfd6890e3e15a4b542543e0cf22ff904310095da328a5e3e561"
UPSTREAM = "python:3.14.7-slim-bookworm@" + UPSTREAM_DIGEST
BOOTSTRAP_NAME = "network-atlas-bootstrap"
BASE_TAG = "network-atlas-acceptance-base:current"
BASE_LABEL = "org.network-atlas.acceptance.base"
INPUT_FILES = ("Dockerfile", "base_setup.py", "dependencies.json", "acquisition_support.py", "acquisition_plan.py", "offline_guard.py", "hermes.tar", "hermes.commit")
RESERVE = 512 * 1024 ** 2
OVERHEAD = 128 * 1024 ** 2
CATEGORIES = {"upstream-layer", "apt-index", "apt-package", "pm-tool", "verifier-wheel", "union-wheel", "core-archive"}



def digest(value: object, *, prefixed: bool = False) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}" if prefixed else r"[0-9a-f]{64}", value):
        raise ValueError("exact lowercase digest required")


def positive(value: object, ceiling: int) -> int:
    if type(value) is not int or not 0 < value <= ceiling:
        raise ValueError("known finite positive integer artifact bound required")
    return value


def validate_artifact(item: dict) -> None:
    artifact(item)


def validate_plan(plan: dict) -> dict[str, int]:
    expected = {"schema": 2, "status": "linked_metadata_only", "unknowns": [], "core_commit": HERMES_COMMIT,
                "core_tree": CORE_TREE, "platform": "linux/amd64", "upstream": UPSTREAM_DIGEST}
    exact(plan, set(expected) | {"upstream_image", "rootfs_layers", "inputs", "sources", "artifacts"})
    if any(plan.get(key) != value for key, value in expected.items()):
        raise ValueError("strict pinned source-linkage projection required; not live authority")
    digest(plan.get("upstream_image"), prefixed=True)
    layers = plan.get("rootfs_layers", [])
    if type(layers) is not list or not 1 <= len(layers) <= 16:
        raise ValueError("source-linked upstream rootfs layers required")
    for layer in layers:
        digest(layer, prefixed=True)

    exact(plan["inputs"], set(INPUT_FILES))
    for value in plan["inputs"].values():
        digest(value)
    validate_linkage(plan)
    return artifact_totals(plan["artifacts"])


def artifact_totals(artifacts: list[dict]) -> dict[str, int]:
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 512:
        raise ValueError("finite complete artifact count required")
    names = set()
    for item in artifacts:
        validate_artifact(item)
        if item["filename"] in names:
            raise ValueError("duplicate artifact filename")
        names.add(item["filename"])
    if {item["category"] for item in artifacts} != CATEGORIES:
        raise ValueError("missing acquisition category")
    compressed = sum(item["compressed_bytes"] for item in artifacts)
    unpacked = sum(item["unpacked_bytes"] for item in artifacts)
    members = sum(item["members"] for item in artifacts)
    # Conservative declared envelope: download/PM partial/final duplication plus
    # unpacked parent, setup/staging, committed blob and retained snapshot overlap.
    # Every individual expansion ceiling still needs source metadata/review; a
    # formula or sampled monitor cannot turn an unknown expansion into proof.
    peak = 3 * compressed + 4 * unpacked + OVERHEAD + members * 8192
    return {"compressed_bytes": compressed, "unpacked_bytes": unpacked,
            "members": members, "peak_bytes": peak, "reserve_bytes": RESERVE,
            "planning_only": True, "fit_proven": False}


def require_space(plan: dict, free: int) -> dict[str, int]:
    """Compare a DECLARED estimate only; never prove authenticated bounds or fit."""
    result = validate_plan(plan)
    gap = result["peak_bytes"] + RESERVE - free
    if gap > 0:
        raise ValueError(f"declared estimate needs {gap} additional bytes; actual deficit unknown, no mutation permitted")
    return dict(result, free_before=free)


@dataclass(frozen=True)
class BootstrapIdentity:
    base_key: str
    daemon: str
    image: str
    plan_hash: str

    def __post_init__(self) -> None:
        for value in (self.base_key, self.plan_hash):
            digest(value)
        digest(self.image, prefixed=True)
        if not re.fullmatch(r"[A-Za-z0-9-]{1,128}", self.daemon):
            raise ValueError("explicit daemon ID required")

    def labels(self) -> dict[str, str]:
        return {OWNER: OWNER_VALUE, BASE_LABEL: self.base_key, "org.network-atlas.acceptance.kind": "bootstrap",
                "org.network-atlas.acceptance.daemon": self.daemon, "org.network-atlas.acceptance.upstream": UPSTREAM_DIGEST,
                "org.network-atlas.acceptance.hermes": HERMES_COMMIT, "org.network-atlas.acceptance.core-tree": CORE_TREE,
                "org.network-atlas.acceptance.plan": self.plan_hash}


def bootstrap_host_config(*, hosted: dict | None = None) -> dict:
    """Hosted public provisioning uses standard Docker package capabilities.

    The permanently disabled legacy builder retains its original capless model.
    No capability is added beyond defaults, and candidate acceptance is separate.
    """
    return {"NetworkMode": "bridge", "ReadonlyRootfs": False, "CapDrop": ["ALL"] if hosted is None else None, "CapAdd": None,
            "SecurityOpt": ["no-new-privileges=true"], "Privileged": False, "Init": True,
            "PidMode": "", "IpcMode": "private", "UTSMode": "", "UsernsMode": "", "Memory": MEMORY, "MemorySwap": MEMORY,
            "NanoCpus": 2000000000, "PidsLimit": 256, "Devices": [], "DeviceRequests": None,
            "Binds": None, "PortBindings": {}, "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            "Tmpfs": {"/tmp": "rw,nosuid,nodev,size=64m,mode=0700"},
            "LogConfig": {"Type": "local", "Config": {"max-size": "4m", "max-file": "1", "compress": "false"}}}


def bootstrap_command(identity: BootstrapIdentity, context: Path, *, hosted: dict | None = None) -> list[str]:
    source_path(context)
    argv = ["create", "--name", BOOTSTRAP_NAME, "--platform", "linux/amd64", "--pull", "never",
            "--network", "bridge", "--user", "0:0", "--security-opt", "no-new-privileges=true",
            "--init", "--memory", str(MEMORY), "--memory-swap", str(MEMORY), "--cpus", "2", "--pids-limit", "256",
            "--ipc", "private", "--restart", "no", "--log-driver", "local", "--log-opt", "max-size=4m",
            "--log-opt", "max-file=1", "--log-opt", "compress=false", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=0700",
            "--mount", f"type=bind,src={context},dst=/opt/inputs,readonly",
            "--env", "PYTHONDONTWRITEBYTECODE=1", "--entrypoint", ""]
    for key, value in identity.labels().items():
        argv.extend(("--label", f"{key}={value}"))
    if hosted is None:
        argv.extend(("--cap-drop", "ALL"))
    if hosted is not None:
        for key, value in hosted.items():
            argv.extend(("--env", f"{key}={value}"))
    script = "hosted_setup.py" if hosted is not None else "base_setup.py"
    return [*argv, identity.image, "python3", f"/opt/inputs/{script}"]


def owned_bootstrap(data: dict, identity: BootstrapIdentity) -> str:
    if (data.get("Name") != "/" + BOOTSTRAP_NAME or data.get("Image") != identity.image
            or data.get("Config", {}).get("Labels") != identity.labels()
            or not re.fullmatch(r"[0-9a-f]{64}", data.get("Id", ""))):
        raise ValueError("bootstrap ownership/immutable identity mismatch")
    return data["Id"]


def validate_bootstrap(data: dict, identity: BootstrapIdentity, context: Path, *, hosted: dict | None = None) -> str:
    identifier = owned_bootstrap(data, identity)
    host = data["HostConfig"]
    if any(host.get(key) != value for key, value in bootstrap_host_config(hosted=hosted).items()):
        raise ValueError("bootstrap isolation drift")
    config = data["Config"]
    script = "hosted_setup.py" if hosted is not None else "base_setup.py"
    if (config.get("User") != "0:0" or config.get("Entrypoint") or config.get("Volumes")
            or config.get("Cmd") != ["python3", f"/opt/inputs/{script}"]):
        raise ValueError("bootstrap image/user/command/volume drift")
    validate_environment(config.get("Env", []), hosted, native=True)
    mounts = [value for value in data["Mounts"] if value["Type"] != "tmpfs"]
    expected = {"Type": "bind", "Source": str(context), "Destination": "/opt/inputs", "RW": False}
    if len(mounts) != 1 or any(mounts[0].get(key) != value for key, value in expected.items()):
        raise ValueError("bootstrap only permits fixed readonly public input mount")
    if set(data["NetworkSettings"]["Networks"]) != {"bridge"}:
        raise ValueError("unexpected bootstrap network")
    return identifier


def commit_command(data: dict, identity: BootstrapIdentity, context: Path, *, hosted: dict | None = None) -> list[str]:
    identifier = validate_bootstrap(data, identity, context, hosted=hosted)
    if data["State"]["Running"] or data["State"].get("Status") != "exited":
        raise ValueError("stopped exited rootfs required before commit")
    if data["State"].get("ExitCode") != 0 or data["State"].get("OOMKilled", False) or data["State"].get("Error"):
        raise ValueError("successful bootstrap required before commit")
    changes = ["USER 1000:1000", "WORKDIR /work", "CMD " + json.dumps(BASE_COMMAND), "ENTRYPOINT []", "ENV PYTHONDONTWRITEBYTECODE=1"]
    if hosted is not None:
        changes.extend(f"ENV {key}=" for key in hosted)
    labels = dict(identity.labels(), **{"org.network-atlas.acceptance.kind": "base"})
    changes.extend(f"LABEL {key}={value}" for key, value in labels.items())
    argv = ["commit"]
    for change in changes:
        argv.extend(("--change", change))
    return [*argv, identifier, BASE_TAG]


def registry_path(path: Path, scratch: Path) -> Path:
    """Explicit durable default-profile registry, never infer active profile HOME."""
    expected = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".hermes/network-atlas/docker-acceptance"
    return _registry_identity(path, scratch, expected)


def _registry_identity(path: Path, scratch: Path, expected: Path) -> Path:
    """Pure test seam; production callers cannot supply their own expected root."""
    if path != expected:
        raise ValueError("exact account-default durable registry identity required")
    if not path.is_absolute() or path.is_symlink() or path.resolve() != path:
        raise ValueError("literal nonsymlink durable registry required")
    if path.is_relative_to(scratch) or path.parts[-3:] != (".hermes", "network-atlas", "docker-acceptance"):
        raise ValueError("durable network-atlas/docker-acceptance registry outside prunable scratch required")
    if path.exists() and (path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077):
        raise ValueError("private owned durable registry required")
    return path


def validate_upstream(data: dict, plan: dict) -> None:
    references = {"python@" + UPSTREAM_DIGEST, "docker.io/library/python@" + UPSTREAM_DIGEST}
    if (data["Id"] != plan["upstream_image"] or data.get("Architecture") != "amd64" or data.get("Os") != "linux"
            or data.get("RootFS", {}).get("Layers") != plan["rootfs_layers"]
            or not references.intersection(data.get("RepoDigests", []))):
        raise ValueError("upstream manifest/config/platform/rootfs drift")
    if data["Config"].get("Volumes") or data["Config"].get("ExposedPorts"):
        raise ValueError("unexpected upstream volume/ports")


def teardown_bootstrap(docker, identity: BootstrapIdentity) -> None:
    data = docker.inspect(BOOTSTRAP_NAME, name=BOOTSTRAP_NAME)
    if data is None:
        return
    identifier = owned_bootstrap(data, identity)
    if data["State"]["Running"]:
        docker.run(["stop", "--time", "5", identifier], timeout=20)
    data = docker.inspect(identifier, name=BOOTSTRAP_NAME)
    if data is None or owned_bootstrap(data, identity) != identifier:
        raise ValueError("bootstrap cleanup target drift")
    docker.run(["rm", identifier])
    if docker.inspect(BOOTSTRAP_NAME, name=BOOTSTRAP_NAME) is not None:
        raise RuntimeError("owned bootstrap cleanup residue")


def stopped_bootstrap(docker, identity: BootstrapIdentity) -> dict:
    """Revalidate the exact owned stopped container before reading any evidence."""
    data = docker.inspect(BOOTSTRAP_NAME, name=BOOTSTRAP_NAME)
    if data is None:
        raise ValueError("bootstrap absent before evidence export")
    identifier = owned_bootstrap(data, identity)
    if data["State"]["Running"]:
        docker.run(["stop", "--time", "5", identifier], timeout=20)
    stopped = docker.inspect(identifier, name=BOOTSTRAP_NAME)
    if stopped is None or owned_bootstrap(stopped, identity) != identifier or stopped["State"]["Running"]:
        raise ValueError("stopped bootstrap immutable identity/state drift")
    return stopped


def require_bootstrap_success(data: dict) -> None:
    """Promote stopped-state failure before success-only export can mask it."""
    state = data["State"]
    if (state.get("Running") is not False or state.get("Status") != "exited"
            or state.get("ExitCode") != 0 or state.get("OOMKilled", False) or state.get("Error")):
        raise RuntimeError(f'public bootstrap failed: status={state.get("Status")} '
                           f'exit={state.get("ExitCode")} oom={state.get("OOMKilled", False)} '
                           f'error={str(state.get("Error", ""))[:4096]}; see stopped.json/bootstrap.log')


def copy_seed_member(docker, identifier: str, budget: BoundedDirectory, name: str) -> dict:
    """Missing means the exact Docker absent-file response, not any copy failure."""
    from docker_contract import evidence_members
    try:
        limit = 1024 ** 2 if name == "inventory.json" else 8 * 1024 ** 2
        payload = docker.run(["cp", f"{identifier}:/opt/seed/{name}", "-"], limit=limit)
    except subprocess.CalledProcessError as exc:
        absent = f'Error response from daemon: Could not find the file /opt/seed/{name} in container {identifier}'
        output = exc.output.decode(errors="replace") if isinstance(exc.output, bytes) else str(exc.output)
        if exc.returncode == 1 and output.strip() == absent:
            return {"status": "missing"}
        raise
    members = evidence_members(payload)
    if [member for member, _data in members] != [name]:
        raise ValueError("only exact retained-rootfs evidence may be copied")
    if name in {"inventory.json", "apt-diagnostics.json"} and len(members[0][1]) > 512 * 1024:
        raise ValueError("bootstrap inventory bound exceeded")
    budget.write(name, members[0][1])
    return {"status": "present", "sha256": hashlib.sha256(members[0][1]).hexdigest()}


def export_seed_members(docker, data: dict, budget: BoundedDirectory, *, provenance: bool) -> dict:
    """Fixed member-by-member export; secondary errors cannot erase earlier files."""
    names = ("inventory.json",)
    if provenance:
        names += ("resolved-union.lock", "verifier-resolution.json", "union-packages.json", "apt-diagnostics.json")
    members = {}
    for name in names:
        try:
            members[name] = copy_seed_member(docker, data["Id"], budget, name)
        except BaseException as exc:
            members[name] = {"status": "error", "error": export_error_text(exc)}
    try:
        require_bootstrap_success(data)
        success = True
    except RuntimeError:
        success = False
    budget.json("export-members.json", {"setup_success": success, "native_acceptance": False, "members": members})
    if any(row["status"] == "error" for row in members.values()):
        raise ValueError("bootstrap evidence export failed; see export-members.json")
    if success and any(row["status"] != "present" for row in members.values()):
        raise ValueError("required bootstrap evidence missing on successful setup; see export-members.json")
    return {name: row["sha256"] for name, row in members.items() if row["status"] == "present"}


def export_error_text(exc: BaseException) -> str:
    """Retain bounded CLI stderr/stdout as well as the secondary exception type."""
    output = getattr(exc, "output", b"")
    if isinstance(output, bytes):
        output = output.decode(errors="replace")
    return f"{type(exc).__name__}: {exc}; {str(output)[:2048]}"[:4096]


def export_bootstrap(docker, root: Path, identity: BootstrapIdentity, *, provenance: bool = False) -> dict:
    """Retain primary state/logs even when success-only files do not exist."""
    data = stopped_bootstrap(docker, identity)
    budget = BoundedDirectory(root)
    budget.json("stopped.json", data)
    budget.write("bootstrap.log", docker.run(["logs", data["Id"]], limit=4 * 1024 ** 2))
    return export_seed_members(docker, data, budget, provenance=provenance)


def finish_build(docker, root: Path, identity: BootstrapIdentity, outcome: dict, *, provenance: bool = False) -> None:
    try:
        outcome["export_hashes"] = export_bootstrap(docker, root, identity, provenance=provenance)
    except BaseException as exc:
        outcome["export_error"] = f"{type(exc).__name__}: {exc}"
    try:
        teardown_bootstrap(docker, identity)
        outcome["cleanup_verified"] = True
    except BaseException as exc:
        outcome["cleanup_error"] = f"{type(exc).__name__}: {exc}"
    try:
        BoundedDirectory(root).json("outcome.json", outcome)
    except BaseException as exc:
        outcome["outcome_export_error"] = f"{type(exc).__name__}: {exc}"


def wait_bootstrap(docker, identity: BootstrapIdentity, context: Path, deadline: float, samples: dict) -> dict:
    while time.monotonic() < deadline:
        free = shutil.disk_usage("/var/lib/containerd").free
        samples["free_minimum"] = min(samples["free_minimum"], free)
        if free < RESERVE:
            raise RuntimeError("sampled containerd reserve crossed; stop, never relax budget")
        data = docker.inspect(BOOTSTRAP_NAME, name=BOOTSTRAP_NAME)
        if data is None:
            raise RuntimeError("bootstrap disappeared")
        validate_bootstrap(data, identity, context)
        if not data["State"]["Running"]:
            return data
        time.sleep(0.2)
    raise TimeoutError("bootstrap deadline exceeded")


def image_validation(data: dict, identity: BootstrapIdentity, returned_image: str | None,
                     upstream_layers: list[str] | None) -> dict:
    """Compare exact safety fields, including the single inert exec-form CMD."""
    expected = dict(identity.labels(), **{"org.network-atlas.acceptance.kind": "base"})
    config = data.get("Config", {})
    if not isinstance(config, dict):
        raise ValueError("committed base Config shape drift")
    wanted = {"Config.Labels": expected, "Config.User": "1000:1000", "Config.WorkingDir": "/work",
              "Config.Cmd": list(BASE_COMMAND)}
    observed = {key: config.get(key.split('.')[1]) for key in wanted}
    mismatches = [key for key in wanted if observed[key] != wanted[key]]
    for key in ("Volumes", "Entrypoint", "ExposedPorts"):
        field = "Config." + key
        wanted[field], observed[field] = "empty", config.get(key)
        if observed[field]:
            mismatches.append(field)
    observed["Id"] = data.get("Id")
    wanted["Id"] = returned_image or "exact lowercase sha256 image digest"
    if not valid_image_digest(data.get("Id")) or (returned_image is not None and data.get("Id") != returned_image):
        mismatches.append("Id")
    rootfs = data.get("RootFS", {})
    layers = rootfs.get("Layers") if isinstance(rootfs, dict) else None
    observed["RootFS.Layers"] = layers
    wanted["RootFS.Layers"] = {"exact_upstream": upstream_layers, "one_new_layer": True} if upstream_layers is not None else "nonempty digest list"
    if not valid_image_layers(layers, upstream_layers):
        mismatches.append("RootFS.Layers")
    return {"expected": wanted, "observed": observed, "mismatches": mismatches, "verified": not mismatches}


def require_base_command(config: dict) -> None:
    """Recheck the same default contract before reuse or verified-image cleanup."""
    if config.get("Cmd") != list(BASE_COMMAND) or config.get("Entrypoint"):
        raise ValueError("owned base Config.Cmd/Config.Entrypoint drift")


def valid_image_digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def valid_image_layers(layers: object, upstream: list[str] | None) -> bool:
    if not isinstance(layers, list) or not 1 <= len(layers) <= 17:
        return False
    if not all(valid_image_digest(layer) for layer in layers):
        return False
    return upstream is None or layers[:-1] == upstream


def verify_final_image(data: dict, identity: BootstrapIdentity, *, returned_image: str | None = None,
                       upstream_layers: list[str] | None = None, audit: dict | None = None) -> dict:
    validation = image_validation(data, identity, returned_image, upstream_layers)
    if audit is not None:
        audit.update(validation)
    if validation["mismatches"]:
        raise ValueError("committed base labels/config/nonroot/rootfs drift: " + ', '.join(validation["mismatches"]))
    expected = validation["expected"]["Config.Labels"]
    return {"image": data["Id"], "base_key": identity.base_key, "daemon": identity.daemon,
            "upstream_digest": UPSTREAM_DIGEST, "core_commit": HERMES_COMMIT, "core_tree": CORE_TREE,
            "plan_hash": identity.plan_hash, "labels": expected, "rootfs_layers": data["RootFS"]["Layers"],
            "size": data["Size"], "consumers": [], "retention": "retain-until-explicit-last-consumer-retirement"}


def image_diagnostic_write(root: Path, name: str, value: object, errors: list,
                           *, registry: bool = False) -> None:
    """Diagnostic failures are secondary if actual readback/validation failed."""
    try:
        budget = registry_budget(root) if registry else BoundedDirectory(root)
        budget.json(name, value)
    except BaseException as exc:
        errors.append(exc)


def read_final_image(docker, image: str, identity: BootstrapIdentity, evidence: Path,
                     registry: Path, upstream_layers: list[str]) -> dict:
    """Journal before inspect; export actual parsed readback before validation.

    No receipt or deletion authority is issued for an unverified image. New
    diagnostic members use existing aggregate/count budgets, with a stricter
    512 KiB readback ceiling; no child/export limit or cleanup rule is widened.
    """

    errors: list[BaseException] = []
    journal = {"identity": identity.labels(), "evidence": str(evidence), "returned_image": image[:128],
               "upstream_image": identity.image, "status": "commit-returned-awaiting-readback", "verified": False}
    image_diagnostic_write(evidence, "image-commit.json", journal, errors)
    image_diagnostic_write(registry, "bootstrap.json", journal, errors, registry=True)
    audit = {"returned_image": image[:128], "daemon": identity.daemon, "stage": "image-inspect",
             "provenance": "actual parsed Docker image inspect; not inferred config", "verified": False}
    original = None
    try:
        digest(image, prefixed=True)
        data = docker.json(["image", "inspect", image])
        payload = json_bytes(data)
        audit.update(readback_bytes=len(payload), readback_sha256=hashlib.sha256(payload).hexdigest())
        if len(payload) > 512 * 1024:
            raise ValueError("committed image readback diagnostic bound exceeded")
        image_diagnostic_write(evidence, "committed-image.json", data, errors)
        if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
            raise ValueError("committed image inspect requires one actual object")
        audit["stage"] = "final-image-validation"
        return verify_final_image(data[0], identity, returned_image=image, upstream_layers=upstream_layers, audit=audit)
    except BaseException as exc:
        original = exc
        audit.update(verified=False, error=export_error_text(exc))
        raise
    finally:
        image_diagnostic_write(evidence, "image-validation.json", audit, errors)
        if errors:
            if original is None:
                raise errors[0]
            for exc in errors:
                original.add_note(f'image diagnostic export failed: {type(exc).__name__}: {str(exc)[:2048]}')


def registry_budget(root: Path) -> BoundedDirectory:
    return BoundedDirectory(root, total=1024 ** 2, per_file=512 * 1024, count=8)


def register_consumer(registry: Path, identity, attempt: Path, status: str) -> None:
    """Consumers survive scratch pruning; no automatic audit/base retirement."""
    record = json.loads(regular_read(registry / "base.json", 512 * 1024))
    if record["image"] != identity.image or record["daemon"] != identity.daemon:
        raise ValueError("consumer/base identity mismatch")
    if identity.base_labels and record['labels'] != dict(identity.base_labels):
        raise ValueError('consumer/base provenance drift')
    consumers = record["consumers"]
    wanted = {"evidence": str(attempt), "commit": identity.commit, "tree": identity.tree, "status": status}
    wanted.update(labels=identity.container_labels(), container_id=identity.container_id)
    index = next((index for index, row in enumerate(consumers) if row["evidence"] == str(attempt)), None)
    if index is None:
        if len(consumers) >= 8:
            raise ValueError("retained base consumer bound; explicit last-consumer retirement required")
        consumers.append(wanted)
    else:
        consumers[index] = wanted
    registry_budget(registry).json("base.json", record)


def reject_existing_owned(docker) -> dict:
    containers = docker.run(["ps", "-aq", "--no-trunc", "--filter", f"label={OWNER}={OWNER_VALUE}"])
    images = docker.run(["image", "ls", "-q", "--no-trunc", "--filter", f"label={OWNER}={OWNER_VALUE}"])
    if containers.strip() or images.strip():
        raise ValueError("existing owned attempt/base: reuse or last-consumer retirement, no replacement")
    return resource_ids(docker)


def resource_ids(docker) -> dict:
    return {"containers": sorted(set(docker.run(["ps", "-aq", "--no-trunc"]).decode().splitlines())),
            "images": sorted(set(docker.run(["image", "ls", "-q", "--no-trunc"]).decode().splitlines()))}


def verify_unrelated_preserved(docker, outcome: dict, identity: BootstrapIdentity) -> None:
    before = outcome["unrelated_before"]
    after = resource_ids(docker)
    expected_images = set(before["images"])
    if outcome.get("upstream_readback_verified"):
        expected_images.add(identity.image)
    if "base" in outcome:
        expected_images.add(outcome["base"]["image"])
    if after["containers"] != before["containers"] or set(after["images"]) != expected_images:
        raise RuntimeError("resource drift/residue after owned cleanup; unrelated resources never removed")
    outcome["unrelated_after"] = after
    outcome["unrelated_preserved"] = True


def build_owned(docker, root: Path, source: Path, plan: dict, registry: Path, *, foreground: bool) -> dict:
    if not foreground:
        raise ValueError("reviewed first setup requires a real foreground operator")
    require_execution_ready()
    budget = require_space(plan, shutil.disk_usage("/var/lib/containerd").free)
    registry_path(registry, root.parent)
    if (registry / "base.json").exists() or (registry / "bootstrap.json").exists():
        raise ValueError("durable base/attempt already registered; no replacement/retry")
    from docker_acceptance import base_context
    context = root / "context"
    key = base_context(source, context, plan)
    identity = BootstrapIdentity(key, docker.daemon, plan["upstream_image"], hashlib.sha256(json_bytes(plan)).hexdigest())
    evidence = root / "bootstrap"
    evidence.mkdir(mode=0o700)
    outcome = {"identity": identity.labels(), "budget": budget, "native_acceptance": False}
    try:
        outcome["unrelated_before"] = reject_existing_owned(docker)
        registry.mkdir(mode=0o700, parents=True, exist_ok=True)
        registry_budget(registry).json("bootstrap.json", {"identity": identity.labels(), "evidence": str(evidence),
            "status": "active", "upstream_image": identity.image, "before": outcome["unrelated_before"]})
        docker.run(["pull", "--platform", "linux/amd64", UPSTREAM], timeout=900, limit=4 * 1024 ** 2)
        validate_upstream(docker.json(["image", "inspect", identity.image])[0], plan)
        outcome["upstream_readback_verified"] = True
        docker.run(bootstrap_command(identity, context))
        data = docker.inspect(BOOTSTRAP_NAME, name=BOOTSTRAP_NAME)
        identifier = validate_bootstrap(data, identity, context)
        BoundedDirectory(evidence).json("created.json", data)
        docker.run(["start", identifier])
        samples = {"free_minimum": budget["free_before"]}
        data = wait_bootstrap(docker, identity, context, time.monotonic() + 1800, samples)
        outcome["samples"] = dict(samples, free_after=shutil.disk_usage("/var/lib/containerd").free)
        require_bootstrap_success(data)
        # Check retained-rootfs inventory before stopped commit. Input/cache/HOME
        # data in the mount cannot supply this proof and is not retained by commit.
        outcome["export_hashes"] = export_bootstrap(docker, evidence, identity)
        inventory = json.loads(regular_read(evidence / "inventory.json", 512 * 1024))
        if inventory.get("plan_sha256") != identity.plan_hash:
            raise ValueError("retained rootfs inventory/acquisition-plan drift")
        image_id = docker.run(commit_command(data, identity, context), timeout=300).decode().strip()
        outcome["returned_image"] = image_id[:128]
        result = read_final_image(docker, image_id, identity, evidence, registry, plan["rootfs_layers"])
        result.update(input_hashes=plan["inputs"], dependency_inventory=inventory, evidence=str(evidence),
                      upstream_image=identity.image, acquisition_budget=budget)
        # Register immediately after immutable readback; later failure must not orphan the image.
        registry_budget(registry).json("base.json", result)
        outcome["base"] = result
    except BaseException as exc:
        outcome["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        finish_build(docker, evidence, identity, outcome)
        if "unrelated_before" in outcome and outcome.get("cleanup_verified"):
            try:
                verify_unrelated_preserved(docker, outcome, identity)
            except BaseException as exc:
                outcome["resource_error"] = f"{type(exc).__name__}: {exc}"
        try:
            registry_budget(registry).json("bootstrap.json", {"identity": identity.labels(), "evidence": str(evidence),
                "status": "retained-awaiting-review", "outcome": outcome})
        except BaseException as exc:
            outcome["registry_error"] = f"{type(exc).__name__}: {exc}"
    return outcome
