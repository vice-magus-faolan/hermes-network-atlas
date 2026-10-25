# SPDX-License-Identifier: GPL-3.0-or-later
"""Test-only imports and synthetic, scratch-scoped homes; never use live profile data."""
from __future__ import annotations

import importlib.util

from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRATCH_ROOT: Path | None = None


def load_package():
    """Import our native directory plugin with the same relative-import package shape."""
    name = "atlas_test_plugin"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, ROOT / "__init__.py",
                                                    submodule_search_locations=[str(ROOT)])
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def scratch_home():
    """Create disposable synthetic state under pytest's per-test tmp_path."""
    return tempfile.TemporaryDirectory(prefix="network-atlas-test-", dir=SCRATCH_ROOT)


def fixture_policy(home: Path):
    """Domain-test adapter for old synthetic YAML fixtures, not runtime loading.

    Native settings/profile behavior is exercised separately through actual
    PluginContext callbacks in runtime_smoke.py and native_endpoints.py.
    """
    import importlib
    load_package()
    config = importlib.import_module("atlas_test_plugin.config")
    conversion = importlib.import_module("atlas_test_plugin.conversion")
    return config.validate_policy(conversion.read_legacy(home), home)


def fixture_handlers(home: Path):
    """Inject a domain policy into real handlers without mocking native APIs."""
    import importlib
    load_package()
    tools = importlib.import_module("atlas_test_plugin.tools")
    return tools.Handlers(lambda: fixture_policy(home))


def fixture_command(args, home: Path):
    """Exercise CLI domain behavior against an explicit synthetic policy loader."""
    import importlib
    load_package()
    commands = importlib.import_module("atlas_test_plugin.commands")
    return commands.run_command(args, lambda: fixture_policy(home))


def copy_plugin(destination: Path) -> None:
    """Copy plugin source and metadata so native admission sees the shipped files."""
    import shutil
    destination.mkdir(parents=True)
    for pattern in ("*.py", "*.sql", "plugin.yaml", "ruff.toml"):
        for source in ROOT.glob(pattern):
            shutil.copy2(source, destination / source.name)
