#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Public prerequisite-only image construction; never candidate admission."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import itertools
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import resource

from acquisition_support import acquire, archive_bounds, validate_inputs, reconstruct_public_core

SEED = Path("/opt/seed")
CORE = SEED / "hermes-source"


def run(argv: list[str]) -> str:
    from acquisition_support import bounded_run
    return bounded_run(argv, CORE)


def inventory(path: Path) -> dict[str, int]:
    count = total = 0
    for entry in path.rglob("*"):
        if entry.is_symlink() or not entry.is_file():
            continue
        count += 1
        total += entry.stat().st_size
        if count > 100000 or total > 1024 ** 3:
            raise ValueError("public retained inventory bound")
    return {"files": count, "bytes": total}


def main() -> int:
    public = Path("/opt/inputs")
    plan = json.loads((public / "acquisition.json").read_text())
    validate_inputs(public, plan)
    inputs = json.loads((public / "dependencies.json").read_text())
    if sys.version_info[:3] != (3, 14, 7) or os.getuid() != 0:
        raise ValueError("pinned Python and private setup UID 0 required")
    acquired = Path("/opt/acquisition")
    downloads = acquire(public, acquired, plan)
    # All network acquisition precedes inherited syscall denial. Package scripts,
    # PM, uv and their descendants cannot acquire an unplanned artifact later.
    from offline_guard import deny_network
    deny_network()
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 ** 3, 1024 ** 3))
    debs = [str(acquired / item["filename"]) for item in plan["artifacts"] if item["category"] == "apt-package"]
    CORE.mkdir(parents=True)
    run(["dpkg", "--install", *debs])
    core_artifact = next(item for item in plan["artifacts"] if item["category"] == "core-archive")
    archive_bounds(public / "hermes.tar", core_artifact)
    with tarfile.open("/opt/inputs/hermes.tar") as bundle:
        bundle.extractall(CORE, filter="data")
    reconstruct_public_core(CORE, public / "hermes.commit", plan["core_commit"], plan["core_tree"])
    # Supply only isolated writable build state. PM authenticates/downloads its
    # own public tools from the complete pinned core lock, not copied host tools.
    home = SEED / "hermes"
    home.mkdir()
    (home / "config.yaml").write_text('{"plugins":{"enabled":[],"disabled":[]}}')
    os.environ.update(HOME=str(SEED / "user"), HERMES_HOME=str(home), TMPDIR=str(SEED),
                      HERMES_RUNTIME_DIR=str(SEED / "tools"), HERMES_MANAGED="false",
                      UV_PYTHON_DOWNLOADS="never", HERMES_ENABLE_PROJECT_PLUGINS="0")
    os.environ.pop("PYTHONPATH", None)
    seed_tools(plan, acquired)
    run([sys.executable, "-m", "pm.cli", "install", "python", "uv", "--tools-only"])
    requirements = acquired / "requirements.txt"
    requirements.write_text("\n".join(inputs["verifier_requirements"]) + "\n")
    wheels = wheelhouse(plan, acquired)
    run([sys.executable, "-m", "pm.build_env", "--requirements", str(requirements), "--out", "/opt/verifier",
         "--wheelhouse", str(wheels), "--offline"])
    warm_union(plan, wheels, acquired)
    # Prewarm genuine member-union resolution for the explicit dependency INPUT
    # only. No candidate code, installed plugin or selector is retained. Fresh
    # native install/enable must redo admission/publication in each runtime.
    member = SEED / "dependency-input"
    member.mkdir()
    (member / "plugin.yaml").write_text(json.dumps({"name": "dependency-input", "version": "1.0.0",
                                                 "python_dependencies": inputs["plugin_python_dependencies"]}))
    run(["/opt/verifier/bin/python", "/opt/inputs/base_setup.py", "prewarm"])
    lock = json.loads((CORE / "pm" / "lock.json").read_text())
    if lock["packages"]["uv"]["version"] != inputs["uv"]:
        raise ValueError("pinned uv differs")
    record = {"inputs": inputs, "tools": {name: lock["packages"][name] for name in ("python", "uv")},
              "plan_sha256": hashlib.sha256((public / "acquisition.json").read_bytes()).hexdigest(),
              "acquired": downloads,
              "source_archive_sha256": hashlib.sha256(Path("/opt/inputs/hermes.tar").read_bytes()).hexdigest(),
              "os_packages": run(["dpkg-query", "-W"]),
              "verifier_packages": run(["/opt/verifier/bin/python", "/opt/inputs/base_setup.py", "inventory"])}
    cache = home / "cache" / "uv"
    shutil.move(cache, SEED / "uv-cache")
    # No old HOME, facts, selected generation, candidate selector or receipts in
    # the reusable image. Tool entry manifests are authentic public prerequisites.
    for entry in (home, member, SEED / "user"):
        if entry.exists():
            shutil.rmtree(entry)
    shutil.rmtree(acquired)
    if (SEED / "prewarm").exists():
        shutil.rmtree(SEED / "prewarm")
    # Private container-owned files only; no host chmod/chown or capability grant.
    readable_seed(SEED)
    readable_seed(Path("/opt/verifier"))
    record["seed_usage"] = inventory(SEED)
    record["verifier_usage"] = inventory(Path("/opt/verifier"))
    if record["seed_usage"]["bytes"] + record["verifier_usage"]["bytes"] > 1024 ** 3:
        raise RuntimeError("base prerequisites exceed 1 GiB recipe envelope")
    payload = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    if len(payload) > 512 * 1024:
        raise ValueError("retained public inventory export bound before write")
    (SEED / "inventory.json").write_bytes(payload)
    forbidden = {"admission.json", "native-enabled.json", "selected.json", "install-stamp.json"}
    if any(path.name in forbidden for path in SEED.rglob("*")):
        raise ValueError("candidate/admission/native selection state in reusable base")
    return 0


def seed_tools(plan: dict, acquired: Path) -> None:
    """Public hash-verified fetch cache; native PM still verifies/installs its own tools."""
    for item in plan["artifacts"]:
        if item["category"] != "pm-tool":
            continue
        entry = SEED / "tools" / ("fetch-" + item["sha256"])
        entry.mkdir(parents=True)
        shutil.copyfile(acquired / item["filename"], entry / item["filename"])


def wheelhouse(plan: dict, acquired: Path) -> Path:
    root = acquired / "wheelhouse"
    root.mkdir()
    for item in plan["artifacts"]:
        if item["category"] in {"verifier-wheel", "union-wheel"}:
            if not item["filename"].endswith(".whl"):
                raise ValueError("offline prerequisite setup forbids source builds")
            os.link(acquired / item["filename"], root / item["filename"])
    return root


def warm_union(plan: dict, wheels: Path, acquired: Path) -> None:
    requirements = acquired / "union-requirements.txt"
    rows = [item["name"] + "==" + item["version"] for item in plan["artifacts"] if item["category"] == "union-wheel"]
    requirements.write_text("\n".join(rows) + "\n")
    run([sys.executable, "-m", "pm.build_env", "--requirements", str(requirements), "--out", str(SEED / "prewarm"),
         "--wheelhouse", str(wheels), "--offline"])


def readable_seed(root: Path) -> None:
    for count, path in enumerate(itertools.chain((root,), root.rglob("*"))):
        if count >= 100000:
            raise ValueError("public retained permission inventory bound")
        if path.is_symlink():
            continue
        mode = 0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644
        path.chmod(mode)


if __name__ == "__main__":
    if sys.argv[1:] == ["prewarm"]:
        sys.path.insert(0, str(CORE))
        from pm.plugin_inputs import Members
        import pm
        pm.sync_venv(explicit=True, plugins=Members([SEED / "dependency-input"]), project_root=CORE)
        raise SystemExit(0)
    if sys.argv[1:] == ["inventory"]:
        print(json.dumps(sorted((item.metadata["Name"], item.version) for item in importlib.metadata.distributions())))
        raise SystemExit(0)
    raise SystemExit(main())
