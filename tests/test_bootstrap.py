# SPDX-License-Identifier: GPL-3.0-or-later
"""Repository bootstrap contracts only; these do not test plugin behavior."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BootstrapContractTests(unittest.TestCase):
    def test_required_project_documents_exist(self) -> None:
        for name in ("README.md", "AGENTS.md", "CONTRIBUTING.md", "SECURITY.md",
                     "docs/project-specification.md", "docs/implementation-addendum.md",
                     "docs/delivery-plan.md", "docs/acceptance-matrix.md"):
            with self.subTest(path=name):
                self.assertTrue((ROOT / name).is_file())
                self.assertTrue((ROOT / name).read_text().strip())

    def test_scaffold_is_not_advertised_as_v1_acceptance(self) -> None:
        readme = (ROOT / "README.md").read_text()
        self.assertIn("V1 atlas is not implemented or released yet", readme)
        self.assertIn("applied=false and persisted=false", readme)
        self.assertIn("Missing Hermes is a failure", readme)

    def test_license_has_later_version_grant_and_full_text(self) -> None:
        self.assertIn("GPL-3.0-or-later", (ROOT / "README.md").read_text())
        license_text = (ROOT / "LICENSE").read_text()
        self.assertIn("Version 3, 29 June 2007", license_text)
        self.assertIn("END OF TERMS AND CONDITIONS", license_text)

    def test_addendum_names_non_negotiable_boundaries(self) -> None:
        addendum = (ROOT / "docs/implementation-addendum.md").read_text()
        for term in ("shell=False", "StrictHostKeyChecking=yes", "Phase 4",
                     "network_map.md", "network_map.mmd", "same-UID",
                     "Failed/partial", "source='user'", "256", "retirement"):
            with self.subTest(term=term):
                self.assertIn(term, addendum)


if __name__ == "__main__":
    unittest.main()
