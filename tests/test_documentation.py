# SPDX-License-Identifier: GPL-3.0-or-later
"""Current operator/matrix contracts, not the retired bootstrap status assertion."""
import ast
from pathlib import Path
import re
import unittest

from helpers import ROOT


class DocumentationTests(unittest.TestCase):
    def test_matrix_paths_and_exact_test_symbols_exist(self):
        text = (ROOT / "docs" / "acceptance-matrix.md").read_text()
        rows = re.findall(r"^\| (A\d{2}) \| (.+)$", text, re.MULTILINE)
        self.assertEqual({identifier for identifier, _ in rows}, {f"A{number:02d}" for number in range(1, 15)})
        self.assertEqual(len(rows), 14)
        for identifier, evidence in rows:
            references = re.findall(r"`([^`]+)`", evidence)
            self.assertTrue(references, identifier)
            for reference in references:
                parts = reference.split("::")
                path = ROOT / parts[0]
                with self.subTest(identifier=identifier, reference=reference):
                    self.assertTrue(path.is_file(), reference)
                    if len(parts) == 3:
                        tree = ast.parse(path.read_text())
                        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == parts[1])
                        self.assertIn(parts[2], {node.name for node in cls.body if isinstance(node, ast.FunctionDef)})
                        self.assertTrue(parts[2].startswith("test_"))
        workflow = (ROOT / ".github" / "workflows" / "verify.yml").read_text()
        self.assertIn("scripts/prepare_acceptance.py", workflow)
        self.assertIn("python3 scripts/verify.py", workflow)

    def test_readme_distinguishes_implementation_from_live_delivery(self):
        readme = (ROOT / "README.md").read_text()
        for term in ("V1 phases 1–3 implemented", "cumulative synthetic acceptance", "separately gated",
                     "Missing Hermes is a failure", "applied=false/persisted=false", "require separate explicit authorization"):
            self.assertIn(term, readme)
        guide = (ROOT / "docs" / "operator-guide.md").read_text()
        for term in ("--no-enable", "plugins enable network-atlas", "NETWORK_ATLAS_ACCEPTANCE_FIXTURE",
                     "ONLINE PREREQUISITE SETUP", "SEPARATE NETWORK-DENIED ACCEPTANCE", "Same-UID",
                     "ProxyJump/ProxyCommand/Match exec", "store.shared_sqlite_path", "Missing Python dependencies",
                     "No LLM/provider response is fabricated", "socket", "unperformed"):
            self.assertIn(term, guide)
