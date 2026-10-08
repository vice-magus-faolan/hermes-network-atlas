# SPDX-License-Identifier: GPL-3.0-or-later
"""Pure acquisition linkage checks, not authenticated resolution or build authority.

Source projections must still be independently authenticated. Production execution
is deliberately disabled until signed Debian closure and aggregate storage proof
have a reviewed implementation; no plan field can enable it.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import re
from urllib.parse import urlsplit

CATEGORIES = {"upstream-layer", "apt-index", "apt-package", "pm-tool", "verifier-wheel", "union-wheel", "core-archive"}
SOURCE_NAMES = {"oci", "apt", "pm", "verifier", "union", "core"}
IDENTITY_KEYS = {"name", "version", "filename", "url", "sha256", "compressed_bytes"}
ARTIFACT_KEYS = IDENTITY_KEYS | {"category", "unpacked_bytes", "members", "source", "record"}
HOSTS = {"files.pythonhosted.org", "github.com", "snapshot.debian.org", "registry-1.docker.io"}
CATEGORY_HOST = {"upstream-layer": "registry-1.docker.io", "apt-index": "snapshot.debian.org",
                 "apt-package": "snapshot.debian.org", "pm-tool": "github.com",
                 "verifier-wheel": "files.pythonhosted.org", "union-wheel": "files.pythonhosted.org",
                 "core-archive": "github.com"}
CATEGORY_SOURCE = {"upstream-layer": "oci", "apt-index": "apt", "apt-package": "apt", "pm-tool": "pm",
                   "verifier-wheel": "verifier", "union-wheel": "union", "core-archive": "core"}


def exact(value: object, keys: set[str]) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise ValueError("missing/unknown source or artifact schema fields")
    return value


def sha(value: object, *, prefix: bool = False) -> None:
    pattern = r"sha256:[0-9a-f]{64}" if prefix else r"[0-9a-f]{64}"
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ValueError("literal lowercase source digest required")


def bounded_int(value: object, maximum: int) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        raise ValueError("finite positive source bound required")
    return value


def document(value: object) -> dict:
    """Retain exact metadata bytes; recomputing a hash is integrity, NOT authenticity."""
    row = exact(value, {"text", "sha256"})
    if not isinstance(row["text"], str) or len(row["text"].encode()) > 512 * 1024:
        raise ValueError("bounded literal metadata text required")
    sha(row["sha256"])
    if hashlib.sha256(row["text"].encode()).hexdigest() != row["sha256"]:
        raise ValueError("source document digest mismatch")
    result = json.loads(row["text"], object_pairs_hook=unique_object)
    if type(result) is not dict:
        raise ValueError("source document object required")
    return result


def unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate metadata key")
        result[key] = value
    return result


def parse_plan(text: str | bytes) -> dict:
    """Bound the outer JSON and reject duplicate keys before schema projection."""
    size = len(text.encode()) if isinstance(text, str) else len(text)
    if size > 1024 ** 2:
        raise ValueError("acquisition metadata exceeds 1 MiB")
    value = json.loads(text, object_pairs_hook=unique_object)
    if type(value) is not dict:
        raise ValueError("acquisition metadata object required")
    return value


def identity(row: dict) -> None:
    sha(row["sha256"])
    bounded_int(row["compressed_bytes"], 1024 ** 3)
    for key in ("name", "version", "filename"):
        if not isinstance(row[key], str) or re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+:-]{0,199}", row[key]) is None:
            raise ValueError("literal resolved artifact identity required")
    parsed = urlsplit(row["url"])
    if parsed.scheme != "https" or parsed.hostname not in HOSTS or parsed.username or parsed.password or parsed.port:
        raise ValueError("public source-linked HTTPS origin required")
    if parsed.query or parsed.fragment:
        raise ValueError("artifact query/fragment refused")
    if ":" in row["filename"]:
        raise ValueError("literal artifact filename required")


def artifact(row: object) -> dict:
    row = exact(row, ARTIFACT_KEYS)
    identity(row)
    bounded_int(row["unpacked_bytes"], 4 * 1024 ** 3)
    bounded_int(row["members"], 200000)
    if row["category"] not in CATEGORIES or row["source"] != CATEGORY_SOURCE[row["category"]]:
        raise ValueError("category/source mismatch")
    if urlsplit(row["url"]).hostname != CATEGORY_HOST[row["category"]]:
        raise ValueError("category/public origin mismatch")
    if not isinstance(row["record"], str) or not re.fullmatch(r"[A-Za-z0-9_.+:-]{1,128}", row["record"]):
        raise ValueError("literal source record reference required")
    return row


def descriptor(row: object, media: str) -> dict:
    row = exact(row, {"mediaType", "digest", "size"})
    sha(row["digest"], prefix=True)
    bounded_int(row["size"], 1024 ** 3)
    if row["mediaType"] != media:
        raise ValueError("unexpected OCI descriptor type")
    return row


def oci_sources(source: dict, plan: dict) -> dict:
    exact(source, {"manifest", "config"})
    manifest = document(source["manifest"])
    config = document(source["config"])
    if "sha256:" + source["manifest"]["sha256"] != plan["upstream"]:
        raise ValueError("OCI manifest not bound to pinned upstream")
    exact(manifest, {"schemaVersion", "mediaType", "config", "layers"})
    if type(manifest["schemaVersion"]) is not int or manifest["schemaVersion"] != 2:
        raise ValueError("OCI schema version mismatch")
    if manifest["mediaType"] != "application/vnd.oci.image.manifest.v1+json":
        raise ValueError("OCI manifest type mismatch")
    desc = descriptor(manifest["config"], "application/vnd.oci.image.config.v1+json")
    if desc["digest"] != plan["upstream_image"] or desc["digest"] != "sha256:" + source["config"]["sha256"]:
        raise ValueError("OCI config image identity mismatch")
    if desc["size"] != len(source["config"]["text"].encode()):
        raise ValueError("OCI config byte length mismatch")
    return oci_layers(manifest, config, plan)


def oci_layers(manifest: dict, config: dict, plan: dict) -> dict:
    if (config.get("architecture"), config.get("os")) != ("amd64", "linux"):
        raise ValueError("OCI platform mismatch")
    rootfs = exact(config.get("rootfs"), {"type", "diff_ids"})
    if rootfs["type"] != "layers" or rootfs["diff_ids"] != plan["rootfs_layers"]:
        raise ValueError("OCI ordered diff-ID mismatch")
    layers = manifest["layers"]
    if type(layers) is not list or not 1 <= len(layers) <= 16 or len(layers) != len(rootfs["diff_ids"]):
        raise ValueError("OCI layer/diff-ID correspondence required")
    records = {}
    for index, value in enumerate(layers):
        desc = descriptor(value, "application/vnd.oci.image.layer.v1.tar+gzip")
        sha(rootfs["diff_ids"][index], prefix=True)
        records[str(index)] = {"category": "upstream-layer", "sha256": desc["digest"][7:], "compressed_bytes": desc["size"],
            "name": f"layer-{index}", "version": plan["upstream"][7:], "filename": desc["digest"][7:] + ".tar.gz",
            "url": "https://registry-1.docker.io/v2/library/python/blobs/" + desc["digest"]}
    if len(set(rootfs["diff_ids"])) != len(layers) or len({r["sha256"] for r in records.values()}) != len(layers):
        raise ValueError("duplicate OCI layer/diff-ID")
    return records


def graph(source: dict, kind: str, pin: str, roots: list[str]) -> dict:
    """Exact reachable closure over source-selected dependency edges; no Boolean claims."""
    value = document(source)
    exact(value, {"kind", "pin", "roots", "records"})
    if value["kind"] != kind or value["pin"] != pin or value["roots"] != roots:
        raise ValueError("closure source/root pin mismatch")
    records = value["records"]
    if type(records) is not dict or not 1 <= len(records) <= 512:
        raise ValueError("bounded closure records required")
    for key, row in records.items():
        exact(row, IDENTITY_KEYS | {"requires", "metadata_sha256", "category"})
        identity(row)
        if row["name"] != key:
            raise ValueError("closure member/name mismatch")
        sha(row["metadata_sha256"])
        if CATEGORY_SOURCE.get(row["category"]) != {"debian-snapshot-projection": "apt", "verifier-lock-projection": "verifier", "member-lock-projection": "union"}[kind]:
            raise ValueError("closure record/category mismatch")
        references(row["requires"], records)
    references(roots, records)
    validate_metadata_anchors(records, kind, pin)
    pending, reached = list(roots), set()
    while pending:
        key = pending.pop()
        if key not in reached:
            reached.add(key)
            pending.extend(records[key]["requires"])
    if reached != set(records):
        raise ValueError("extra/disconnected closure metadata")
    return records


def validate_metadata_anchors(records: dict, kind: str, pin: str) -> None:
    for row in records.values():
        if kind != "debian-snapshot-projection":
            if row["metadata_sha256"] != pin:
                raise ValueError("wheel closure metadata/source lock mismatch")
        elif row["category"] == "apt-package":
            indexes = [records[key]["sha256"] for key in row["requires"] if records[key]["category"] == "apt-index"]
            if row["metadata_sha256"] not in indexes:
                raise ValueError("Debian package not linked to selected index")
        elif row["version"] != pin:
            raise ValueError("Debian index snapshot mismatch")


def requirement_roots(requirements: list[str]) -> list[str]:
    if type(requirements) is not list or not requirements:
        raise ValueError("explicit dependency roots required")
    roots = []
    for spec in requirements:
        if not isinstance(spec, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:==|>=)[0-9.]+(?:,<[0-9.]+)?", spec):
            raise ValueError("unsupported requirement projection; no implicit resolution")
        roots.append(re.split(r"[<>=]", spec)[0])
    if len(set(roots)) != len(roots):
        raise ValueError("duplicate requirement root")
    return roots


def check_requirements(records: dict, requirements: list[str]) -> dict:
    for name, spec in zip(requirement_roots(requirements), requirements):
        version = tuple(int(part) for part in records[name]["version"].split("."))
        for op, text in re.findall(r"(==|>=|<)([0-9.]+)", spec):
            wanted = tuple(int(part) for part in text.split("."))
            allowed = {"==": version == wanted, ">=": version >= wanted, "<": version < wanted}
            if not allowed[op]:
                raise ValueError("locked version violates declared requirement")
    return records


def references(values: object, records: dict) -> None:
    if type(values) is not list or len(values) > 512:
        raise ValueError("bounded source dependency references required")
    if any(not isinstance(key, str) or key not in records for key in values) or len(set(values)) != len(values):
        raise ValueError("missing/duplicated closure member")


def pm_sources(source: dict, commit: str) -> dict:
    exact(source, {"commit", "lock"})
    if source["commit"] != commit:
        raise ValueError("PM source commit mismatch")
    lock = document(source["lock"])
    records = {}
    for name in ("python", "uv"):
        package = exact(lock["packages"][name], {"version", "artifacts"})
        item = exact(package["artifacts"]["linux-x64"], {"sha256", "url"})
        records[name] = {"category": "pm-tool", "name": name, "version": package["version"], "sha256": item["sha256"],
                         "url": item["url"], "filename": PurePosixPath(urlsplit(item["url"]).path).name}
    return records


def core_sources(source: dict, plan: dict) -> dict:
    row = exact(source, {"commit", "tree", "archive_sha256", "archive_bytes", "format"})
    if (row["commit"], row["tree"], row["format"]) != (plan["core_commit"], plan["core_tree"], "tar"):
        raise ValueError("complete uncompressed core tar identity required")
    if row["archive_sha256"] != plan["inputs"]["hermes.tar"]:
        raise ValueError("core archive/input digest mismatch")
    return {"archive": {"category": "core-archive", "sha256": row["archive_sha256"], "compressed_bytes": row["archive_bytes"],
                        "name": "hermes", "version": row["commit"], "filename": "hermes.tar",
                        "url": "https://github.com/vice-magus-faolan/hermes-agent"}}


def source_records(plan: dict) -> dict:
    sources = exact(plan["sources"], SOURCE_NAMES | {"dependencies", "uv_lock_sha256"})
    deps = document(sources["dependencies"])
    if sources["dependencies"]["sha256"] != plan["inputs"]["dependencies.json"]:
        raise ValueError("recipe dependencies/input hash mismatch")
    exact(deps, {"schema", "hermes_commit", "python", "uv", "debian_snapshot", "plugin_python_dependencies", "verifier_requirements"})
    if deps["hermes_commit"] != plan["core_commit"]:
        raise ValueError("dependency core pin mismatch")
    sha(sources["uv_lock_sha256"])
    tools = pm_sources(sources["pm"], plan["core_commit"])
    if tools["uv"]["version"] != deps["uv"] or tools["python"]["version"].partition("+")[0] != deps["python"]:
        raise ValueError("native tool/recipe version mismatch")
    return {"oci": oci_sources(sources["oci"], plan), "pm": tools,
        "core": core_sources(sources["core"], plan),
        "apt": graph(sources["apt"], "debian-snapshot-projection", deps["debian_snapshot"], ["ca-certificates", "git", "openssh-client"]),
        "verifier": check_requirements(graph(sources["verifier"], "verifier-lock-projection", sources["dependencies"]["sha256"], requirement_roots(deps["verifier_requirements"])), deps["verifier_requirements"]),
        "union": check_requirements(graph(sources["union"], "member-lock-projection", sources["uv_lock_sha256"], requirement_roots(deps["plugin_python_dependencies"])), deps["plugin_python_dependencies"])}


def validate_linkage(plan: dict) -> None:
    """Convert malformed input structures to a uniform pre-effect refusal."""
    try:
        _validate_linkage(plan)
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError("malformed acquisition source schema") from exc


def _validate_linkage(plan: dict) -> None:
    records = source_records(plan)
    used = {name: set() for name in SOURCE_NAMES}
    filenames = set()
    rows = plan["artifacts"]
    if type(rows) is not list or not 1 <= len(rows) <= 512:
        raise ValueError("finite complete artifact list required")
    for value in rows:
        row = artifact(value)
        group, key = row["source"], row["record"]
        if key not in records[group] or key in used[group] or row["filename"] in filenames:
            raise ValueError("unknown/duplicate artifact source member")
        expected = records[group][key]
        if any(row[field] != expected[field] for field in (IDENTITY_KEYS | {"category"}) & set(expected)):
            raise ValueError("artifact/source identity mismatch")
        used[group].add(key)
        filenames.add(row["filename"])
    if any(used[name] != set(records[name]) for name in SOURCE_NAMES):
        raise ValueError("omitted source closure artifact")
    if {row["category"] for row in rows} != CATEGORIES:
        raise ValueError("missing acquisition category")


def require_execution_ready() -> None:
    """No argument/env/metadata switch bypasses unresolved production proof."""
    raise ValueError("live build disabled: authenticated Debian/member closure and aggregate storage architecture remain unresolved")
