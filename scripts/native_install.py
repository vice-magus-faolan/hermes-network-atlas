#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Online SETUP ONLY: real native install/enable, unchanged admission and consent."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from acceptance_support import HERMES_COMMIT, contained, file_hash, git_head, git_tree, plugin_hashes
from caution_confirmation import ROOT, canonical, marker, scan_request, verify_approval, verify_core
from ci_admission import MODE, install_ci, select_mode


def confirmation_arguments(parser: argparse.ArgumentParser) -> None:
    """No defaults or environment-variable activation of security consent."""
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--approval-signature", type=Path)
    parser.add_argument("--allowed-signers", type=Path)
    parser.add_argument("--signer")
    parser.add_argument("--confirmation-scope")


def approval_values(args: argparse.Namespace) -> tuple | None:
    values = (args.approval, args.approval_signature, args.allowed_signers, args.signer, args.confirmation_scope)
    if not any(values):
        return None
    if not all(values):
        raise ValueError("all external approval/signature/anchor/signer/scope inputs required")
    return values


def readback(root: Path, source: Path, home: Path, action: str) -> dict:
    """Read actual native bytes and PM selection after installation or enable."""
    from hermes_cli.config import load_config_readonly
    from pm.environments import runtime_facts_path, selected_venv, venv_python

    config = load_config_readonly()
    enabled = "network-atlas" in config.get("plugins", {}).get("enabled", [])
    assert enabled == (action == "enable"), config.get("plugins")
    plugin = home / "plugins" / "network-atlas"
    assert (plugin / "plugin.yaml").is_file()
    result = {"action": action, "enabled": enabled, "plugin": str(plugin),
              "installed_commit": git_head(plugin), "installed_tree": git_tree(plugin)}
    if enabled:
        venv = contained(root, str(selected_venv(source)))
        facts = contained(root, str(runtime_facts_path(source)))
        assert (venv / "pyvenv.cfg").is_file()
        paths = [facts, home / "config.yaml", plugin / "plugin.yaml",
                 *(source / name for name in ("pyproject.toml", "uv.lock", "pm/pyproject.toml", "pm/uv.lock", "pm/lock.json"))]
        # Capture the actual member-union recipe and lock produced by native PM.
        paths.extend(sorted(facts.parent.rglob("uv.lock")))
        paths.extend(sorted(facts.parent.rglob("pyproject.toml")))
        paths.extend(sorted((facts.parent / "pm-runtime").rglob("selected.json")))
        paths.extend(sorted((facts.parent / "pm-runtime").rglob("pm-runtime.json")))
        result.update({"python": str(venv_python(venv)), "source": str(source),
                       "native_facts": str(facts), "native_generation": str(venv),
                       "hermes_commit": HERMES_COMMIT, "plugin_hashes": plugin_hashes(plugin),
                       "state_hashes": {str(path): file_hash(path) for path in paths}})
        (root / "native-enabled.json").write_text(json.dumps(result, indent=2))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("source", type=Path)
    parser.add_argument("action", choices=("scan", "install", "enable"))
    parser.add_argument("candidate", type=Path, nargs="?")
    parser.add_argument("ref", nargs="?")
    parser.add_argument("--origin-commit")
    parser.add_argument("--admission-mode", choices=("local", MODE), default="local")
    confirmation_arguments(parser)
    args = parser.parse_args()
    hosted = select_mode(args.admission_mode, os.environ)
    if hosted and (args.action != "install" or approval_values(args)):
        raise ValueError("hosted CI mode is install-only and cannot use signed consent")
    root = Path(os.environ["TMPDIR"]).resolve()
    if not (root / "synthetic-atlas-home").is_file():
        raise ValueError("synthetic scratch fixture marker required")
    home = contained(root, os.environ["HERMES_HOME"])
    # Scan-only reconnaissance may read the retained exact public core, but
    # installation still requires a source snapshot inside its marked fixture.
    source = args.source.resolve() if args.action == "scan" else contained(root, str(args.source))
    action = args.action
    candidate = None
    if action in {"scan", "install"}:
        candidate = contained(root, str(args.candidate))
        if git_head(candidate) != args.ref:
            raise ValueError("exact fixture ref mismatch")
        if action == "scan":
            request = scan_request(source, candidate, args.origin_commit, args.confirmation_scope)
            print(canonical(request).decode())
            return 0
        consent = approval_values(args)
        if consent:
            request = scan_request(source, candidate, args.origin_commit, args.confirmation_scope)
            verify_approval(request, consent[0], consent[1], consent[2], consent[3], (ROOT, root, source))
            print(marker(request).decode(), flush=True)
    if hosted:
        verify_core(source)
    sys.path.insert(0, str(source))
    from hermes_cli import plugins_cmd

    if action == "install":
        assert candidate is not None
        if hosted:
            report = install_ci(source, candidate, args.ref, args.origin_commit, root, os.environ, plugins_cmd.cmd_install)
            print(json.dumps({"admission_mode": MODE, "verdict": report["verdict"],
                              "findings": len(report["findings"]), "candidate_commit": report["candidate_commit"],
                              "candidate_tree": report["candidate_tree"]}), flush=True)
        else:
            plugins_cmd.cmd_install(candidate.as_uri(), enable=False, ref=args.ref)
    elif action == "enable":
        plugins_cmd.cmd_enable("network-atlas")
    else:
        raise ValueError("unknown fixture action")
    result = readback(root, source, home, action)
    print(json.dumps({key: result[key] for key in ("action", "enabled", "plugin")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
