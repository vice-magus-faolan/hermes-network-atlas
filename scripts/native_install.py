#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Online SETUP ONLY: real native install/enable, unchanged admission and consent."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

from acceptance_support import HERMES_COMMIT, contained, file_hash, git_head, git_tree, plugin_hashes


def main() -> int:
    root = Path(os.environ["TMPDIR"]).resolve()
    if not (root / "synthetic-atlas-home").is_file():
        raise ValueError("synthetic scratch fixture marker required")
    home = contained(root, os.environ["HERMES_HOME"])
    source = contained(root, sys.argv[1])
    sys.path.insert(0, str(source))
    from hermes_cli import plugins_cmd
    from hermes_cli.config import load_config_readonly
    from pm.environments import runtime_facts_path, selected_venv, venv_python

    action = sys.argv[2]
    if action == "install":
        candidate = contained(root, sys.argv[3])
        plugins_cmd.cmd_install(candidate.as_uri(), enable=False, ref=sys.argv[4])
    elif action == "enable":
        plugins_cmd.cmd_enable("network-atlas")
    else:
        raise ValueError("unknown fixture action")
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
    print(json.dumps({"action": action, "enabled": enabled, "plugin": str(plugin)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
