# SPDX-License-Identifier: GPL-3.0-or-later
"""Tiny invented metadata for PURE linkage tests; never a resolved public plan."""
import hashlib
import json


def doc(value):
    text = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return {"text": text, "sha256": hashlib.sha256(text.encode()).hexdigest()}


def linked_plan(builder):
    inputs = {name: "c" * 64 for name in builder.INPUT_FILES}
    deps = doc({"schema": 1, "hermes_commit": builder.HERMES_COMMIT, "python": "3.14.7", "uv": "0.12.3",
                "debian_snapshot": "20260919T000000Z", "plugin_python_dependencies": ["member>=1,<2"],
                "verifier_requirements": ["verifier==1"]})
    inputs["dependencies.json"] = deps["sha256"]
    config = doc({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "b" * 64]}})
    manifest = doc({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + config["sha256"], "size": len(config["text"].encode())},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:" + "d" * 64, "size": 100}]})
    artifacts = []
    def row(category, name, filename=None, version="1"):
        host = {"apt-index": "snapshot.debian.org", "apt-package": "snapshot.debian.org", "pm-tool": "github.com",
                "verifier-wheel": "files.pythonhosted.org", "union-wheel": "files.pythonhosted.org"}[category]
        return {"category": category, "name": name, "version": version, "filename": filename or name + ".tar",
                "url": "https://" + host + "/" + (filename or name + ".tar"), "sha256": "d" * 64, "compressed_bytes": 100}
    def graph(kind, pin, records, roots):
        return doc({"kind": kind, "pin": pin, "roots": roots, "records": records})
    apt = {name: dict(row("apt-package", name), requires=["index"], metadata_sha256="d" * 64)
           for name in ("ca-certificates", "git", "openssh-client")}
    apt["index"] = dict(row("apt-index", "index", version="20260919T000000Z"), requires=[], metadata_sha256="e" * 64)
    verifier = {"verifier": dict(row("verifier-wheel", "verifier", "verifier-1-py3-none-any.whl"), requires=[], metadata_sha256=deps["sha256"])}
    union = {"member": dict(row("union-wheel", "member", "member-1-py3-none-any.whl"), requires=[], metadata_sha256="f" * 64)}
    versions = {"python": "3.14.7+fixture", "uv": "0.12.3"}
    packages = {name: {"version": versions[name], "artifacts": {"linux-x64": {"url": "https://github.com/" + name + ".tar", "sha256": "d" * 64}}} for name in ("python", "uv")}
    pm = {"commit": builder.HERMES_COMMIT, "lock": doc({"packages": packages})}
    sources = {"oci": {"manifest": manifest, "config": config}, "pm": pm, "dependencies": deps, "uv_lock_sha256": "f" * 64,
        "apt": graph("debian-snapshot-projection", "20260919T000000Z", apt, list(apt)[:-1]),
        "verifier": graph("verifier-lock-projection", deps["sha256"], verifier, ["verifier"]),
        "union": graph("member-lock-projection", "f" * 64, union, ["member"]),
        "core": {"commit": builder.HERMES_COMMIT, "tree": builder.CORE_TREE, "archive_sha256": inputs["hermes.tar"], "archive_bytes": 100, "format": "tar"}}
    for group, records in (("apt", apt), ("verifier", verifier), ("union", union)):
        for key, value in records.items():
            artifacts.append(dict({k: v for k, v in value.items() if k not in ("requires", "metadata_sha256")}, source=group, record=key, unpacked_bytes=1000, members=10))
    for name in ("python", "uv"):
        artifacts.append(dict(row("pm-tool", name, version=versions[name]), source="pm", record=name, unpacked_bytes=1000, members=10))
    artifacts.extend([
        {"category": "upstream-layer", "name": "layer-0", "version": manifest["sha256"], "filename": "d" * 64 + ".tar.gz", "url": "https://registry-1.docker.io/v2/library/python/blobs/sha256:" + "d" * 64,
         "sha256": "d" * 64, "compressed_bytes": 100, "unpacked_bytes": 1000, "members": 10, "source": "oci", "record": "0"},
        {"category": "core-archive", "name": "hermes", "version": builder.HERMES_COMMIT, "filename": "hermes.tar", "url": "https://github.com/NousResearch/hermes-agent",
         "sha256": inputs["hermes.tar"], "compressed_bytes": 100, "unpacked_bytes": 1000, "members": 10, "source": "core", "record": "archive"}])
    return {"schema": 2, "status": "linked_metadata_only", "core_commit": builder.HERMES_COMMIT, "core_tree": builder.CORE_TREE,
            "platform": "linux/amd64", "upstream": "sha256:" + manifest["sha256"], "upstream_image": "sha256:" + config["sha256"],
            "rootfs_layers": ["sha256:" + "b" * 64], "inputs": inputs, "sources": sources, "artifacts": artifacts, "unknowns": []}
