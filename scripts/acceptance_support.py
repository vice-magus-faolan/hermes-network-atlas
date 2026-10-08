# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared fixture identity/containment checks; never consult a live Hermes home."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

HERMES_COMMIT = "f42f579cf8bac4918ac9599bece71618afadd846"
ROOT = Path(__file__).resolve().parents[1]
PLUGIN_FILES = ("plugin.yaml", "__init__.py", "config.py", "schemas.py", "updates.py", "tools.py", "commands.py",
                "storage.py", "storage_schema.sql", "facts.py", "identity.py", "core.py", "query.py", "batches.py", "render.py",
                "probes.py", "discovery_parse.py", "discovery.py", "reconcile.py", "inspection.py",
                "inspection_parse.py", "inspection_evidence.py", "ssh_identity.py", "unresolved.py", "host_discovery.py",
                "host_transport.py", "host_schedule.py")


def file_hash(path: Path) -> str:
    """Hash actual bytes, not timestamps or mutable selection names."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def plugin_hashes(root: Path = ROOT) -> dict[str, str]:
    return {name: file_hash(root / name) for name in PLUGIN_FILES}


def git_head(root: Path = ROOT) -> str:
    from docker_snapshot import CANDIDATE, git_identity
    if root == CANDIDATE:
        return git_identity(root, 'commit')
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def git_tree(root: Path = ROOT) -> str:
    from docker_snapshot import CANDIDATE, git_identity
    if root == CANDIDATE:
        return git_identity(root, 'tree')
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD^{tree}"], text=True).strip()


def fixture_root(value: str) -> Path:
    """Require a marked directory below declared scratch; refuse symlink escapes."""
    scratch = Path(os.environ["TMPDIR"]).resolve()
    root = Path(value).resolve()
    if root == scratch or not root.is_relative_to(scratch):
        raise ValueError("acceptance fixture must be below TMPDIR")
    if not (root / "synthetic-atlas-home").is_file():
        raise ValueError("synthetic fixture marker required")
    return root


def contained(root: Path, value: str) -> Path:
    path = Path(value).resolve()
    if not path.is_relative_to(root):
        raise ValueError("fixture state escapes scratch fixture")
    return path


def fixture_environment(root: Path) -> dict[str, str]:
    """No credentials, ambient Python paths, profile config, or proxy inheritance."""
    env = {"PATH": "/usr/bin:/bin", "HOME": str(root / "user"), "HERMES_HOME": str(root / "hermes"),
            "TMPDIR": str(root), "PYTHONDONTWRITEBYTECODE": "1", "UV_PYTHON_DOWNLOADS": "never",
            "HERMES_DISABLE_LAZY_INSTALLS": "1", "HERMES_MANAGED": "false",
            "HERMES_BUNDLED_PLUGINS": str(root / "empty-bundled"), "HERMES_ENABLE_PROJECT_PLUGINS": "0",
            "XDG_CONFIG_HOME": str(root / "xdg-config"), "XDG_DATA_HOME": str(root / "xdg-data"),
            "XDG_CACHE_HOME": str(root / "xdg-cache")}
    from docker_snapshot import CANDIDATE, git_settings, validate_snapshot
    if ROOT == CANDIDATE:
        validate_snapshot(ROOT)
        env.update(git_settings(ROOT))
    return env


def validate_receipt(root: Path) -> dict:
    """Invalidate admission evidence when candidate, installed code or PM selection drifts."""
    receipt = json.loads((root / "admission.json").read_text())
    if receipt["candidate_commit"] != git_head() or receipt["plugin_hashes"] != plugin_hashes():
        raise ValueError("admission fixture is bound to another candidate; rerun setup")
    if receipt["hermes_commit"] != HERMES_COMMIT or receipt["enabled"] is not True:
        raise ValueError("unsupported Hermes source or plugin not admitted")
    if receipt["candidate_tree"] != git_tree() or receipt["installed_tree"] != receipt["candidate_tree"]:
        raise ValueError("admission did not install the complete candidate tree")
    plugin = contained(root, receipt["plugin"])
    if plugin_hashes(plugin) != receipt["plugin_hashes"]:
        raise ValueError("installed candidate changed")
    for path, expected in receipt["state_hashes"].items():
        if file_hash(contained(root, path)) != expected:
            raise ValueError("native selection/recipe/lock changed")
    contained(root, receipt["python"])
    contained(root, receipt["source"])
    return receipt
