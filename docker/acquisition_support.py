# SPDX-License-Identifier: GPL-3.0-or-later
"""Finite public acquisition in a private bootstrap rootfs, before offline PM setup.

No floating resolution, unknown lengths, retry families or host input copying.
The acquisition plan is independently reviewed metadata, not permission to run.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tarfile
import time
import urllib.request
from urllib.parse import urlsplit
import zipfile

HOSTS = {"files.pythonhosted.org", "github.com", "snapshot.debian.org", "registry-1.docker.io",
         "release-assets.githubusercontent.com", "objects.githubusercontent.com"}


def public_url(url: str) -> None:
    value = urlsplit(url)
    if value.scheme != "https" or value.hostname not in HOSTS or value.username or value.password or value.port:
        raise ValueError("public HTTPS artifact origin/redirect required")


class PublicRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        public_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def bounded_run(argv: list[str], cwd: Path, *, timeout: float = 900, limit: int = 4 * 1024 ** 2) -> str:
    """Bound setup output before retaining it; reap only the owned process group."""
    child = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, start_new_session=True)
    selector = selectors.DefaultSelector()
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        if child.stdout is None:
            raise RuntimeError("owned setup output absent")
        selector.register(child.stdout, selectors.EVENT_READ)
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise TimeoutError("public setup command deadline")
            for key, _event in selector.select(0.1):
                block = os.read(key.fd, min(65536, limit - len(output) + 1))
                if not block:
                    selector.unregister(key.fileobj)
                if len(output) + len(block) > limit:
                    raise ValueError("public setup output bound exceeded")
                output.extend(block)
        if child.wait(timeout=5):
            raise RuntimeError(output.decode(errors="replace"))
        return output.decode(errors="replace")
    finally:
        selector.close()
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        if child.stdout is not None:
            child.stdout.close()


def finite_download(item: dict, directory: Path, *, opener=None, deadline: float) -> Path:
    """Exact length/hash, bounded blocks and deadline checked BEFORE every write."""
    public_url(item["url"])
    name = item["filename"]
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,199}", name):
        raise ValueError("literal artifact filename required")
    size = item["compressed_bytes"]
    if type(size) is not int or not 0 < size <= 1024 ** 3:
        raise ValueError("known finite artifact length required")
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), PublicRedirect())
    path = directory / name
    request = urllib.request.Request(item["url"], headers={"Accept-Encoding": "identity", "User-Agent": "network-atlas-public-setup/1"})
    with opener.open(request, timeout=30) as response:
        public_url(response.geturl())
        if response.status != 200 or response.headers.get("Content-Length") != str(size):
            raise ValueError("artifact length/status differs from resolved metadata")
        if response.headers.get("Content-Encoding", "identity") != "identity":
            raise ValueError("unexpected artifact content encoding")
        write_download(response, path, item, deadline)
    return path


def write_download(response, path: Path, item: dict, deadline: float) -> None:
    remaining = item["compressed_bytes"]
    digest = hashlib.sha256()
    created = False
    try:
        with path.open("xb") as stream:
            created = True
            while remaining:
                if time.monotonic() >= deadline:
                    raise TimeoutError("public acquisition deadline exceeded")
                block = response.read(min(65536, remaining))
                if not block or len(block) > remaining:
                    raise ValueError("truncated/overlong public artifact")
                stream.write(block)
                digest.update(block)
                remaining -= len(block)
            if response.read(1) or digest.hexdigest() != item["sha256"]:
                raise ValueError("public artifact exact length/hash mismatch")
    except BaseException:
        if created:
            path.unlink(missing_ok=True)
        raise


def archive_bounds(path: Path, item: dict) -> dict[str, int]:
    """Check complete archive metadata before PM/native extraction writes anything."""
    if path.name.endswith(".whl"):
        with zipfile.ZipFile(path) as bundle:
            entries = [(value.filename, value.file_size) for value in bundle.infolist()]
    elif path.name.endswith(".deb"):
        return deb_bounds(path, item)
    elif tarfile.is_tarfile(path):
        with tarfile.open(path) as bundle:
            return tar_bounds(bundle, item)
    else:
        return index_bounds(path, item)
    return entry_bounds(entries, item)


def entry_bounds(entries: list[tuple[str, int]], item: dict) -> dict[str, int]:
    total = 0
    for name, size in entries:
        if Path(name).is_absolute() or ".." in Path(name).parts or size < 0:
            raise ValueError("unsafe archive member")
        total += size
        if total > item["unpacked_bytes"] or len(entries) > item["members"]:
            raise ValueError("archive expansion ceiling exceeded before extraction")
    return {"members": len(entries), "bytes": total}


def tar_bounds(bundle: tarfile.TarFile, item: dict) -> dict[str, int]:
    entries = []
    for member in bundle:
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            raise ValueError("unexpected archive device/member")
        if member.islnk() or member.issym():
            import posixpath
            target = member.linkname if member.islnk() else posixpath.join(posixpath.dirname(member.name), member.linkname)
            normalized = posixpath.normpath(target)
            if normalized.startswith(("/", "../")) or normalized == "..":
                raise ValueError("archive link escapes root")
        entries.append((member.name, member.size))
        if len(entries) > item["members"]:
            raise ValueError("archive member ceiling exceeded")
    return entry_bounds(entries, item)


def deb_bounds(path: Path, item: dict) -> dict[str, int]:
    entries = []
    with path.open("rb") as stream:
        if stream.read(8) != b"!<arch>\n":
            raise ValueError("invalid Debian ar archive")
        while header := stream.read(60):
            if len(header) != 60 or header[-2:] != b"`\n":
                raise ValueError("invalid Debian member header")
            size = int(header[48:58].strip())
            if not 0 <= size <= item["compressed_bytes"]:
                raise ValueError("Debian compressed member bound")
            data = stream.read(size)
            if len(data) != size:
                raise ValueError("truncated Debian member")
            name = header[:16].strip().rstrip(b"/").decode("ascii")
            if name.startswith(("data.tar", "control.tar")):
                with tarfile.open(fileobj=io.BytesIO(data)) as bundle:
                    result = tar_bounds(bundle, item)
                entries.append((name, result["bytes"]))
            if size % 2:
                stream.read(1)
    if {name.split(".", 1)[0] for name, _size in entries} != {"data", "control"}:
        raise ValueError("missing Debian data/control metadata")
    return entry_bounds(entries, item)


def index_bounds(path: Path, item: dict) -> dict[str, int]:
    import lzma
    if item["category"] != "apt-index":
        raise ValueError("unknown artifact format, expansion not proven")
    opener = lzma.open if path.name.endswith(".xz") else open
    total = 0
    with opener(path, "rb") as stream:
        while block := stream.read(min(65536, item["unpacked_bytes"] - total + 1)):
            total += len(block)
            if total > item["unpacked_bytes"]:
                raise ValueError("apt index expansion bound")
    return {"members": 1, "bytes": total}


def validate_inputs(inputs: Path, plan: dict) -> None:
    expected = plan["inputs"]
    if set(path.name for path in inputs.iterdir()) != set(expected) | {"acquisition.json"}:
        raise ValueError("unexpected public bootstrap inputs")
    for name, wanted in expected.items():
        path = inputs / name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != wanted:
            raise ValueError("public input identity changed")


def acquire(inputs: Path, destination: Path, plan: dict) -> list[dict]:
    from acquisition_plan import require_execution_ready
    require_execution_ready()
    validate_inputs(inputs, plan)
    if plan.get("status") != "resolved" or plan.get("unknowns") != []:
        raise ValueError("complete finite resolved acquisition required")
    destination.mkdir(mode=0o700)
    record = []
    deadline = time.monotonic() + 900
    for item in plan["artifacts"]:
        if item["category"] in {"upstream-layer", "core-archive"}:
            continue  # Parent identity is daemon-read back; exact core archive is a fixed input.
        path = finite_download(item, destination, deadline=deadline)
        record.append({"name": item["name"], "sha256": item["sha256"], "compressed_bytes": path.stat().st_size,
                       "archive": archive_bounds(path, item)})
    return record


def reconstruct_public_core(core: Path, commit: Path, expected_commit: str, expected_tree: str) -> None:
    """Reconstruct one public commit, never copy a host common Git directory."""
    env_keys = [name for name in os.environ if name.startswith("GIT_")]
    if env_keys or (core / ".git").exists():
        raise ValueError("fresh isolated public core Git state required")
    bounded_run(["git", "init", "--quiet"], core)
    bounded_run(["git", "add", "--force", "--all"], core)
    if bounded_run(["git", "write-tree"], core).strip() != expected_tree:
        raise ValueError("complete public core archive tree mismatch")
    if bounded_run(["git", "hash-object", "-t", "commit", "-w", str(commit)], core).strip() != expected_commit:
        raise ValueError("literal public core commit object mismatch")
    (core / ".git" / "shallow").write_text(expected_commit + "\n")
    bounded_run(["git", "update-ref", "HEAD", expected_commit], core)
    if bounded_run(["git", "status", "--porcelain=v1", "--untracked-files=all"], core):
        raise ValueError("reconstructed public core has extra files")
