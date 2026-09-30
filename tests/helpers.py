# SPDX-License-Identifier: GPL-3.0-or-later
"""Test-only imports and synthetic, scratch-scoped homes; never use live profile data."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


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
    """Require declared scratch rather than falling back to the system temp directory."""
    scratch = os.environ.get("TMPDIR")
    if not scratch or not Path(scratch).is_dir():
        raise RuntimeError("Set TMPDIR to an existing local scratch directory")
    return tempfile.TemporaryDirectory(prefix="network-atlas-test-", dir=scratch)
