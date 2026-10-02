# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression checks for the acceptance boundary and candidate evidence invalidation."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
from test_acceptance import support


class AcceptanceHarnessTests(unittest.TestCase):
    def test_socket_denial_is_inherited_through_exec(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / "network_denial_probe.py")],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("denied in parent and exec child", result.stdout)

    def test_marker_and_symlink_containment_fail_closed(self):
        with scratch_home() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                support.fixture_root(str(root))
            (root / "synthetic-atlas-home").touch()
            self.assertEqual(support.fixture_root(str(root)), root)
            (root / "escape").symlink_to(Path(os.environ["TMPDIR"]).resolve(), target_is_directory=True)
            with self.assertRaises(ValueError):
                support.contained(root, str(root / "escape" / "outside"))

    def test_code_and_native_selection_changes_invalidate_receipt(self):
        with scratch_home() as directory:
            root = Path(directory)
            # This intentionally invalid LOCAL unit fixture is not native admission
            # evidence. It only proves that byte/selection mismatch is refused.
            plugin = root / "plugin"
            plugin.mkdir()
            for name in support.PLUGIN_FILES:
                (plugin / name).write_bytes((ROOT / name).read_bytes())
            state = root / "state.json"
            state.write_text("native-selection-fixture")
            receipt = {"candidate_commit": support.git_head(), "plugin_hashes": support.plugin_hashes(),
                       "candidate_tree": support.git_tree(), "installed_tree": support.git_tree(),
                       "hermes_commit": support.HERMES_COMMIT, "enabled": True, "plugin": str(plugin),
                       "state_hashes": {str(state): support.file_hash(state)},
                       "python": str(root / "python"), "source": str(root / "source")}
            (root / "admission.json").write_text(json.dumps(receipt))
            (plugin / "tools.py").write_text("changed bytes")
            with self.assertRaisesRegex(ValueError, "installed candidate changed"):
                support.validate_receipt(root)
            (plugin / "tools.py").write_bytes((ROOT / "tools.py").read_bytes())
            state.write_text("changed selector")
            with self.assertRaisesRegex(ValueError, "selection/recipe/lock changed"):
                support.validate_receipt(root)
            with patch.object(support, "git_head", return_value="different-candidate"):
                with self.assertRaisesRegex(ValueError, "another candidate"):
                    support.validate_receipt(root)
