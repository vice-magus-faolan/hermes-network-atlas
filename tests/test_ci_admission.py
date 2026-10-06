# SPDX-License-Identifier: GPL-3.0-or-later
"""Hosted policy/refusal tests only; never perform a force install on this host."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import unittest
from unittest.mock import Mock, patch

from helpers import ROOT, scratch_home

sys.path.insert(0, str(ROOT / "scripts"))
from acceptance_support import HERMES_COMMIT, fixture_environment, git_head, git_tree
from offline_guard import deny_network
import ci_admission


class HostedCIAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = scratch_home()
        cls.root = Path(cls.workspace.__enter__())
        cls.addClassCleanup(cls.workspace.__exit__, None, None, None)
        source = Path(os.environ["NETWORK_ATLAS_HERMES_ROOT"])
        if git_head(source) != HERMES_COMMIT:
            raise ValueError("exact public Hermes source required")
        cls.source = cls.root / "hermes-source"
        cls.source.mkdir()
        archive = subprocess.check_output(["git", "-C", str(source), "archive", HERMES_COMMIT], timeout=60)
        with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
            bundle.extractall(cls.source, filter="data")

    def setUp(self):
        self.case = self.root / self._testMethodName
        self.case.mkdir()
        (self.case / "synthetic-atlas-home").touch()
        (self.case / "user").mkdir()
        home = self.case / "hermes"
        home.mkdir()
        (home / "config.yaml").write_text(json.dumps({"plugins": {"enabled": [], "disabled": []}}))
        self.candidate = self.case / "candidate"
        self.candidate.mkdir()
        (self.candidate / "plugin.yaml").write_text("name: network-atlas\nversion: '1.0'\ndescription: Synthetic policy test\n")
        (self.candidate / "__init__.py").write_text("def register(ctx):\n    pass\n")
        (self.candidate / "README.md").write_text("Preinstalled setuid helpers are not permitted.\n")
        self.commit()
        self.env = fixture_environment(self.case)
        self.source = self.case / "hermes-source"
        shutil.copytree(type(self).source, self.source, symlinks=True)
        self.diagnostics = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                            "RUNNER_OS": "Linux", "GITHUB_REPOSITORY": ci_admission.REPOSITORY,
                            "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/feat/6-host-discovery",
                            "GITHUB_JOB": "offline-verification", "GITHUB_SHA": git_head(ROOT),
                            "GITHUB_WORKSPACE": str(ROOT), "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
        self.env.update(self.diagnostics)
        # These strings test rejection/selection, not actual hosted isolation or
        # approval. The native install boundary is ALWAYS a mock in these tests.
        self.installer = Mock()

    def commit(self):
        for args in (("init", "-q"), ("add", "."), ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                                                "commit", "-qm", "Synthetic policy fixture")):
            subprocess.run(["git", "-C", str(self.candidate), *args], check=True, capture_output=True, timeout=30)

    def install_policy(self):
        # Scanner verdict controls need clean synthetic safe/caution/dangerous
        # trees, not admission of the repository. Only the checkout-tree mapping
        # is mocked; every source byte and finding is scanned by the real native
        # scanner, and the native installation boundary remains a mock.
        with patch.object(ci_admission, "git_tree", return_value=git_tree(self.candidate)):
            return ci_admission.install_ci(self.source, self.candidate, git_head(self.candidate),
                                           git_head(ROOT), self.case, self.env, self.installer)

    def test_explicit_mode_and_matching_diagnostics_required(self):
        self.assertFalse(ci_admission.select_mode("local", {}))
        with self.assertRaises(ValueError):
            ci_admission.select_mode("force", self.diagnostics)
        with self.assertRaises(ValueError):
            ci_admission.select_mode(ci_admission.MODE, {})
        self.assertTrue(ci_admission.select_mode(ci_admission.MODE, self.diagnostics))
        for key in self.diagnostics:
            changed = dict(self.diagnostics, **{key: "mismatched"})
            with self.subTest(key=key), self.assertRaises(ValueError):
                ci_admission.select_mode(ci_admission.MODE, changed)
        pull_request = dict(self.diagnostics, GITHUB_EVENT_NAME="pull_request", GITHUB_REF="refs/pull/6/merge")
        self.assertTrue(ci_admission.select_mode(ci_admission.MODE, pull_request))
        for event in ("pull_request_target", "workflow_dispatch"):
            with self.assertRaises(ValueError):
                ci_admission.select_mode(ci_admission.MODE, dict(self.diagnostics, GITHUB_EVENT_NAME=event))

    def test_main_feature_push_and_pr_merge_refs_match_workflow(self):
        from ruamel.yaml import YAML
        workflow = YAML(typ="safe").load((ROOT / ".github" / "workflows" / "verify.yml").read_text())
        for event, ref in (("push", "refs/heads/main"), ("push", "refs/heads/feat/6-host-discovery"),
                           ("pull_request", "refs/pull/6/merge"), ("pull_request", "refs/pull/123/merge")):
            with self.subTest(event=event, ref=ref):
                self.assertTrue(ci_admission.select_mode(ci_admission.MODE,
                                                        dict(self.diagnostics, GITHUB_EVENT_NAME=event, GITHUB_REF=ref)))
        self.assertEqual(workflow["on"]["push"], {"branches": ["main", "feat/6-host-discovery"]})
        self.assertEqual(workflow["on"]["pull_request"], {"branches": ["main"]})

    def test_other_events_branches_tags_and_nonmerge_pr_refs_refuse(self):
        cases = (("push", "refs/heads/main-next"), ("push", "refs/heads/feat/6-host-discovery-next"),
                 ("push", "refs/heads/unrelated"), ("push", "refs/tags/main"),
                 ("push", "refs/pull/6/merge"), ("push", "refs/heads/main\n"),
                 ("pull_request", "refs/heads/main"), ("pull_request", "refs/pull/6/head"),
                 ("pull_request", "refs/pull/0/merge"), ("pull_request", "refs/pull/06/merge"),
                 ("pull_request", "refs/pull/6/merge/extra"), ("pull_request_target", "refs/pull/6/merge"),
                 ("workflow_dispatch", "refs/heads/main"), ("schedule", "refs/heads/main"))
        for event, ref in cases:
            with self.subTest(event=event, ref=ref), self.assertRaises(ValueError):
                ci_admission.select_mode(ci_admission.MODE,
                                         dict(self.diagnostics, GITHUB_EVENT_NAME=event, GITHUB_REF=ref))
        self.installer.assert_not_called()
        self.assertFalse((self.case / "admission.json").exists())

    def test_fresh_marked_contained_fixture_no_replacement(self):
        ci_admission.fresh_fixture(self.case, self.source, self.candidate, git_head(self.candidate), self.env)
        home = Path(self.env["HERMES_HOME"])
        for path in (home / "plugins" / "network-atlas", self.case / "admission.json", self.case / "native-enabled.json"):
            path.parent.mkdir(exist_ok=True)
            path.touch()
            with self.subTest(path=path), self.assertRaises(ValueError):
                ci_admission.fresh_fixture(self.case, self.source, self.candidate, git_head(self.candidate), self.env)
            path.unlink()
        for key in ("HERMES_HOME", "HOME", "TMPDIR"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                ci_admission.fresh_fixture(self.case, self.source, self.candidate, git_head(self.candidate),
                                          dict(self.env, **{key: str(ROOT)}))
        (self.case / "synthetic-atlas-home").unlink()
        with self.assertRaises(ValueError):
            ci_admission.fresh_fixture(self.case, self.source, self.candidate, git_head(self.candidate), self.env)

    def test_native_full_scan_caution_selects_supported_force_without_install(self):
        report = self.install_policy()
        self.assertEqual(report["verdict"], "caution")
        self.assertTrue(report["findings"])
        self.assertEqual(json.loads((self.case / "ci-scan.json").read_text()), report)
        self.installer.assert_called_once_with(self.candidate.as_uri(), force=True, enable=False,
                                               ref=git_head(self.candidate))
        self.assertFalse((Path(self.env["HERMES_HOME"]) / "plugins" / "network-atlas").exists())
        self.assertFalse((self.case / "admission.json").exists())
        sys.path.insert(0, str(self.source))
        from hermes_cli import plugins_cmd
        from tools.plugin_guard import should_allow_plugin_install
        with patch.dict(os.environ, self.env, clear=True):
            result = plugins_cmd._scan_plugin_tree(self.candidate, "synthetic", force=True)
        assert result is not None
        self.assertEqual(result.verdict, "caution")
        self.assertIs(should_allow_plugin_install(result, force=False)[0], None)
        self.assertIs(should_allow_plugin_install(result, force=True)[0], True)

    def test_native_dangerous_refuses_even_force_and_never_calls_installer(self):
        (self.candidate / "escape").symlink_to(self.root / "outside")
        self.commit()
        with self.assertRaisesRegex(ValueError, "dangerous"):
            self.install_policy()
        self.installer.assert_not_called()
        sys.path.insert(0, str(self.source))
        from hermes_cli import plugins_cmd
        with patch.dict(os.environ, self.env, clear=True), self.assertRaises(plugins_cmd.PluginScanBlocked):
            plugins_cmd._scan_plugin_tree(self.candidate, "synthetic", force=True)
        self.assertEqual(json.loads((self.case / "ci-scan.json").read_text())["verdict"], "dangerous")
        self.assertFalse((self.case / "admission.json").exists())

    def test_safe_does_not_select_force_and_candidate_or_core_drift_refuses(self):
        (self.candidate / "README.md").write_text("Synthetic clean fixture.\n")
        self.commit()
        report = self.install_policy()
        self.assertEqual(report["verdict"], "safe")
        self.assertFalse(self.installer.call_args.kwargs["force"])
        self.installer.reset_mock()
        (self.candidate / "untracked").touch()
        with self.assertRaisesRegex(ValueError, "clean candidate"):
            self.install_policy()
        self.installer.assert_not_called()
        (self.candidate / "untracked").unlink()
        scanner = self.source / "tools" / "plugin_guard.py"
        original = scanner.read_bytes()
        try:
            scanner.write_bytes(original + b"\n# synthetic drift\n")
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                self.install_policy()
            self.installer.assert_not_called()
        finally:
            scanner.write_bytes(original)

    def test_reviewed_workflow_hosted_readonly_pins_no_secrets_or_privileged_event(self):
        from ruamel.yaml import YAML
        workflow = YAML(typ="safe").load((ROOT / ".github" / "workflows" / "verify.yml").read_text())
        self.assertEqual(set(workflow["on"]), {"push", "pull_request"})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        job = workflow["jobs"]["offline-verification"]
        self.assertEqual(job["runs-on"], "ubuntu-latest")
        self.assertNotIn("permissions", job)
        text = (ROOT / ".github" / "workflows" / "verify.yml").read_text()
        for prohibited in ("secrets.", "pull_request_target", "self-hosted", "--allow-removed", "--approval"):
            self.assertNotIn(prohibited, text)
        self.assertIn("--admission-mode hosted-ci-caution", text)
        self.assertIn("git rev-parse HEAD HEAD^{tree}", text)
        self.assertIn("python3 scripts/verify.py", text)
        for step in job["steps"]:
            if "uses" in step:
                self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")
                if step["uses"].startswith("actions/checkout@"):
                    self.assertIs(step["with"]["persist-credentials"], False)

    def test_workflow_runner_context_scratch_initialized_at_step_then_persisted(self):
        from ruamel.yaml import YAML
        workflow = YAML(typ="safe").load((ROOT / ".github" / "workflows" / "verify.yml").read_text())
        job = workflow["jobs"]["offline-verification"]
        # GitHub evaluates job env before runner assignment; runner.* belongs
        # in step env/run. Full expression validation is a separate actionlint
        # preflight, not something a YAML parser or this narrow test replaces.
        for values in (workflow.get("env", {}), job.get("env", {})):
            for value in values.values():
                self.assertNotRegex(str(value), r"\brunner\.", "runner context is unavailable before step env")
        self.assertNotIn("TMPDIR", job["env"])
        steps = job["steps"]
        setup = next(step for step in steps if step.get("name") == "Prepare isolated verifier prerequisites")
        self.assertEqual(setup["env"], {"TMPDIR": "${{ runner.temp }}/atlas-test-scratch"})
        initialization, pip_command, remainder = setup["run"].partition("python3 -m pip")
        self.assertTrue(pip_command)
        self.assertIn("-r requirements-test.txt", remainder)
        # Exercise the actual initialization shell without dependency acquisition.
        # Space-containing paths also require correct quoting in GITHUB_ENV.
        scratch = self.case / "runner temp" / "atlas-test-scratch"
        github_env = self.case / "github env"
        env = dict(fixture_environment(self.case), TMPDIR=str(scratch), GITHUB_ENV=str(github_env))
        subprocess.run(["/bin/bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", initialization],
                       cwd=self.case, env=env, check=True, capture_output=True, timeout=10)
        self.assertTrue(scratch.is_dir())
        self.assertEqual(github_env.read_text(), f"TMPDIR={scratch}\n")
        for step in steps[steps.index(setup) + 1:]:
            self.assertNotIn("TMPDIR", step.get("env", {}))
        self.assertEqual(job["env"]["NETWORK_ATLAS_HERMES_ROOT"], "${{ github.workspace }}/.hermes-runtime-source")

    def test_real_entrypoints_refuse_local_ci_mode_mixed_consent_and_enable(self):
        native = [sys.executable, str(ROOT / "scripts" / "native_install.py"), str(self.source)]
        setup = [sys.executable, str(ROOT / "scripts" / "prepare_acceptance.py"), "--hermes-source", str(self.source)]
        install = [*native, "install", str(self.candidate), git_head(self.candidate)]
        cases = [(setup, dict(self.env, GITHUB_ACTIONS="false"), "diagnostics mismatch"),
                 (install, dict(self.env, RUNNER_ENVIRONMENT="self-hosted"), "diagnostics mismatch"),
                 ([*native, "enable"], self.env, "install-only"),
                 ([*install, "--approval", str(self.case / "missing"), "--approval-signature", str(self.case / "missing.sig"),
                   "--allowed-signers", str(self.case / "anchor"), "--signer", "synthetic", "--confirmation-scope", "synthetic"],
                  self.env, "cannot use signed consent")]
        for command, env, message in cases:
            with self.subTest(command=command):
                result = subprocess.run([*command, "--admission-mode", ci_admission.MODE], env=env,
                                        capture_output=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message.encode(), result.stderr)
                self.assertFalse((self.case / "admission.json").exists())
                self.assertFalse((Path(self.env["HERMES_HOME"]) / "plugins" / "network-atlas").exists())

    def test_install_boundary_rechecks_context_origin_ref_and_modified_scan_policy(self):
        self.env["GITHUB_ACTIONS"] = "false"
        with self.assertRaises(ValueError):
            self.install_policy()
        self.env["GITHUB_ACTIONS"] = "true"
        with self.assertRaisesRegex(ValueError, "checked-out CI SHA"):
            ci_admission.install_ci(self.source, self.candidate, git_head(self.candidate), "0" * 40,
                                    self.case, self.env, self.installer)
        with self.assertRaisesRegex(ValueError, "candidate/ref"):
            ci_admission.install_ci(self.source, self.candidate, "0" * 40, git_head(ROOT),
                                    self.case, self.env, self.installer)
        with self.assertRaisesRegex(ValueError, "complete candidate tree"):
            ci_admission.install_ci(self.source, self.candidate, git_head(self.candidate), git_head(ROOT),
                                    self.case, self.env, self.installer)
        config = Path(self.env["HERMES_HOME"]) / "config.yaml"
        config.write_text(json.dumps({"plugins": {"enabled": [], "disabled": [], "scan_on_install": False}}))
        with self.assertRaisesRegex(ValueError, "default native scan"):
            self.install_policy()
        self.installer.assert_not_called()


if __name__ == "__main__":
    deny_network()
    unittest.main()
