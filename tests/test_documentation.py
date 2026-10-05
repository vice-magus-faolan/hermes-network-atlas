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
        host_rows = re.findall(r"^\| (H\d{2}) \| (.+)$", text, re.MULTILINE)
        self.assertEqual({identifier for identifier, _ in host_rows}, {f"H{number:02d}" for number in range(1, 13)})
        self.assertEqual(len(host_rows), 12)
        rows.extend(host_rows)
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

    def test_host_operator_contract_and_required_canonical_coverage(self):
        contract = (ROOT / "docs" / "host-discovery-policy.md").read_text()
        for term in ("Future live validation recipe", "separate authorization required",
                     "preinstalled ping helper", "not a wire-packet receipt", "4403",
                     "responding_address_count", "address_outcome_counts.success", "2222", "22000",
                     "no optional real helper"):
            # The optional-helper claim is maintained in the acceptance matrix.
            text = contract + (ROOT / "docs" / "acceptance-matrix.md").read_text()
            self.assertIn(term, text)
        trees = [ast.parse((ROOT / "scripts" / name).read_text())
                 for name in ("verify.py", "acceptance_support.py")]
        for tree in trees:
            node = next(node for node in tree.body if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == "PLUGIN_FILES" for target in node.targets))
            self.assertTrue({"host_discovery.py", "host_transport.py", "host_schedule.py"} <= set(ast.literal_eval(node.value)))
        required = next(node for node in trees[0].body if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == "REQUIRED_HOST_DISCOVERY_TESTS" for target in node.targets))
        ids = ast.literal_eval(required.value)
        host_tree = ast.parse((ROOT / "tests" / "test_host_acceptance.py").read_text())
        cls = next(node for node in host_tree.body if isinstance(node, ast.ClassDef))
        for test in cls.body:
            if isinstance(test, ast.FunctionDef) and test.name.startswith("test_"):
                self.assertIn("test_host_acceptance.CumulativeHostTests." + test.name, ids)

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
