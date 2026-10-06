# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail-closed Docker identities, commands and bounded evidence; no daemon effects."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import os
from pathlib import Path
import re
import tarfile

OWNER = "org.network-atlas.acceptance.owner"
OWNER_VALUE = "network-atlas-docker-v1"
NAME = "network-atlas-acceptance"
ENDPOINT = "unix:///var/run/docker.sock"
MEMORY = 3 * 1024 ** 3
EVIDENCE_LIMIT = 32 * 1024 ** 2
TMPFS = {"/work": "rw,nosuid,nodev,size=2g,uid=1000,gid=1000,mode=0700",
         "/tmp": "rw,nosuid,nodev,noexec,size=64m,uid=1000,gid=1000,mode=0700"}
MODES = ("smoke", "fail", "interrupt", "refusal", "accept")


@dataclass(frozen=True)
class Identity:
    """Bind resource ownership to exact public artifact, image and daemon."""
    commit: str
    tree: str
    image: str
    daemon: str

    def __post_init__(self) -> None:
        if not all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (self.commit, self.tree)):
            raise ValueError("full lowercase commit/tree required")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.image):
            raise ValueError("immutable image ID required")
        if not re.fullmatch(r"[A-Za-z0-9-]{1,128}", self.daemon):
            raise ValueError("explicit daemon identity required")

    def labels(self) -> dict[str, str]:
        return {OWNER: OWNER_VALUE, "org.network-atlas.acceptance.commit": self.commit,
                "org.network-atlas.acceptance.tree": self.tree,
                "org.network-atlas.acceptance.image": self.image,
                "org.network-atlas.acceptance.daemon": self.daemon}


def check_endpoint(env: dict, info: dict, identity: Identity) -> None:
    """Reject redirect diagnostics; an env string is never endpoint authority."""
    if any(env.get(key) for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")):
        raise ValueError("ambient Docker endpoint/config redirection refused")
    if (info.get("ID"), info.get("OSType"), info.get("Architecture")) != (identity.daemon, "linux", "x86_64"):
        raise ValueError("daemon/platform mismatch")


def source_path(candidate: Path) -> Path:
    if candidate.is_symlink() or not candidate.is_absolute() or candidate.resolve(strict=True) != candidate:
        raise ValueError("literal absolute nonsymlink snapshot required")
    if not candidate.is_dir() or any(char in str(candidate) for char in ",\n\r"):
        raise ValueError("invalid snapshot mount path")
    return candidate


def create_command(identity: Identity, candidate: Path, mode: str, evidence: Path | None = None) -> list[str]:
    """Public readonly snapshot and separate private evidence export directory."""
    source_path(candidate)
    evidence = source_path(evidence if evidence is not None else candidate.parent / "incoming")
    if mode not in MODES:
        raise ValueError("unknown Docker acceptance mode")
    command = ["create", "--name", NAME, "--network", "none", "--user", "1000:1000", "--read-only",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--init",
               "--memory", str(MEMORY), "--memory-swap", str(MEMORY), "--cpus", "2", "--pids-limit", "256",
               "--ipc", "private", "--log-driver", "local", "--log-opt", "max-size=4m", "--log-opt", "max-file=1",
               "--mount", f"type=bind,src={candidate},dst=/candidate,readonly",
               "--mount", f"type=bind,src={evidence},dst=/export"]
    for path, options in TMPFS.items():
        command.extend(("--tmpfs", f"{path}:{options}"))
    for key, value in identity.labels().items():
        command.extend(("--label", f"{key}={value}"))
    if mode == "accept":
        command.extend(("--interactive", "--tty"))
    command.extend((identity.image, "python3", "/candidate/scripts/docker_inside.py", mode))
    return command


def cleanup_allowed(inspected: dict | None, identity: Identity) -> bool:
    """Absent is idempotent; a mismatching existing resource is never ours to kill."""
    if inspected is None:
        return False
    if (inspected.get("Name") != "/" + NAME or inspected.get("Image") != identity.image
            or inspected.get("Config", {}).get("Labels") != identity.labels()
            or not re.fullmatch(r"[0-9a-f]{64}", inspected.get("Id", ""))):
        raise ValueError("container ownership/immutable identity mismatch")
    return True


def validate_container(data: dict, identity: Identity, candidate: Path, mode: str, evidence: Path | None = None) -> str:
    """Read back actual isolation, not merely intended create arguments."""
    if not cleanup_allowed(data, identity):
        raise ValueError("container absent")
    expected = {"NetworkMode": "none", "ReadonlyRootfs": True, "CapDrop": ["ALL"], "Privileged": False,
                "SecurityOpt": ["no-new-privileges=true"], "Init": True, "PidMode": "", "IpcMode": "private",
                "Memory": MEMORY, "MemorySwap": MEMORY, "NanoCpus": 2000000000, "PidsLimit": 256, "Tmpfs": TMPFS,
                "LogConfig": {"Type": "local", "Config": {"max-size": "4m", "max-file": "1"}}}
    host = data["HostConfig"]
    if any(host.get(key) != value for key, value in expected.items()):
        raise ValueError("Docker isolation drift")
    if any(host.get(key) for key in ("CapAdd", "Devices", "Binds", "PortBindings", "DeviceRequests")):
        raise ValueError("unexpected Docker privilege/mount/device/port")
    config = data["Config"]
    if (config.get("User") != "1000:1000" or config.get("Entrypoint") or config.get("Volumes")
            or config.get("Cmd") != ["python3", "/candidate/scripts/docker_inside.py", mode]):
        raise ValueError("image command/user/volume drift")
    if any(value.split("=", 1)[0].startswith(("GITHUB_", "DOCKER_")) for value in config.get("Env", [])):
        raise ValueError("unexpected hosted/daemon environment")
    check_mounts(data["Mounts"], candidate, evidence if evidence is not None else candidate.parent / "incoming")
    if set(data["NetworkSettings"]["Networks"]) != {"none"}:
        raise ValueError("unexpected attached network")
    return data["Id"]


def check_mounts(mounts: list[dict], candidate: Path, evidence: Path) -> None:
    binds = [item for item in mounts if item["Type"] != "tmpfs"]
    expected = [{"Type": "bind", "Source": str(candidate), "Destination": "/candidate", "RW": False},
                {"Type": "bind", "Source": str(evidence), "Destination": "/export", "RW": True}]
    actual = sorted(binds, key=lambda row: row["Destination"])
    if len(actual) != 2:
        raise ValueError("unexpected mounts")
    for mount, wanted in zip(actual, expected):
        if any(mount.get(key) != value for key, value in wanted.items()):
            raise ValueError("readonly public/evidence mount drift")


def verification_result(log: str, code: int) -> dict:
    """Totals must agree with unittest's actual outcome; never duplicate a constant."""
    discovered = re.findall(r"Canonical verification: (\d+) tests discovered;", log)
    ran = re.findall(r"^Ran (\d+) tests in [0-9.]+s$", log, re.MULTILINE)
    if code or len(discovered) != 1 or len(ran) != 1 or discovered != ran or int(ran[0]) < 1:
        raise ValueError("missing/failed/mismatched canonical result")
    if not re.search(r"^OK\s*$", log, re.MULTILINE) or re.search(r"skipped|FAILED|ERROR:", log):
        raise ValueError("canonical skip/failure/non-success")
    return {"tests": int(ran[0]), "exit_code": code, "passed": True}


def evidence_members(data: bytes) -> list[tuple[str, bytes]]:
    """Validate the entire export before creating any host file; no links/devices."""
    if len(data) > EVIDENCE_LIMIT:
        raise ValueError("evidence archive exceeds bound")
    result = []
    total = 0
    names = set()
    with tarfile.open(fileobj=io.BytesIO(data)) as bundle:
        for member in bundle:
            name = member.name.removeprefix("./")
            if member.isdir() and name in ("", "."):
                continue
            path = Path(name)
            if not member.isfile() or path.is_absolute() or ".." in path.parts or name in names:
                raise ValueError("unsafe/duplicate export member")
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
                raise ValueError("export must contain bounded flat files")
            total += member.size
            if total > EVIDENCE_LIMIT or len(result) >= 64:
                raise ValueError("export content exceeds bound")
            stream = bundle.extractfile(member)
            if stream is None:
                raise ValueError("export member unavailable")
            payload = stream.read(member.size + 1)
            if len(payload) != member.size:
                raise ValueError("truncated export")
            result.append((name, payload))
            names.add(name)
    if not result:
        raise ValueError("missing exported evidence")
    return result


def export_archive(data: bytes, destination: Path) -> dict[str, str]:
    members = evidence_members(data)
    destination.mkdir(mode=0o700)
    hashes = {}
    for name, payload in members:
        path = destination / name
        with path.open("xb") as stream:
            stream.write(payload)
        path.chmod(0o600)
        hashes[name] = hashlib.sha256(payload).hexdigest()
    return hashes
