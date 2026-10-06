#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Public prerequisite-only image construction; never candidate admission."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

SEED = Path("/opt/seed")
CORE = SEED / "hermes-source"


def run(argv: list[str]) -> str:
    result = subprocess.run(argv, cwd=CORE, capture_output=True, text=True, timeout=900)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout


def inventory(path: Path) -> dict[str, int]:
    files = [entry for entry in path.rglob("*") if entry.is_file() and not entry.is_symlink()]
    return {"files": len(files), "bytes": sum(entry.stat().st_size for entry in files)}


def main() -> int:
    inputs = json.loads(Path("/opt/inputs/dependencies.json").read_text())
    if sys.version_info[:3] != (3, 14, 7):
        raise ValueError("pinned Python required")
    CORE.mkdir(parents=True)
    with tarfile.open("/opt/inputs/hermes.tar") as bundle:
        bundle.extractall(CORE, filter="data")
    # Supply only isolated writable build state. PM authenticates/downloads its
    # own public tools from the complete pinned core lock, not copied host tools.
    home = SEED / "hermes"
    home.mkdir()
    (home / "config.yaml").write_text('{"plugins":{"enabled":[],"disabled":[]}}')
    os.environ.update(HOME=str(SEED / "user"), HERMES_HOME=str(home), TMPDIR=str(SEED),
                      HERMES_RUNTIME_DIR=str(SEED / "tools"), HERMES_MANAGED="false",
                      UV_PYTHON_DOWNLOADS="never", HERMES_ENABLE_PROJECT_PLUGINS="0")
    os.environ.pop("PYTHONPATH", None)
    run([sys.executable, "-m", "pm.cli", "install", "python", "uv", "--tools-only"])
    requirements = Path("/opt/inputs/requirements.txt")
    requirements.write_text("\n".join(inputs["verifier_requirements"]) + "\n")
    run([sys.executable, "-m", "pm.build_env", "--requirements", str(requirements), "--out", "/opt/verifier"])
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
    record["seed_usage"] = inventory(SEED)
    record["verifier_usage"] = inventory(Path("/opt/verifier"))
    if record["seed_usage"]["bytes"] + record["verifier_usage"]["bytes"] > 1024 ** 3:
        raise RuntimeError("base prerequisites exceed 1 GiB recipe envelope")
    (SEED / "inventory.json").write_text(json.dumps(record, indent=2, sort_keys=True))
    return 0


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
