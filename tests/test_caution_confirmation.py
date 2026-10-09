# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic external approvals, unchanged native scanner/CLI, inherited packet denial."""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time
import unittest

from helpers import ROOT, scratch_home

sys.path.insert(0, str(ROOT / "scripts"))
import caution_confirmation as confirmation
from acceptance_support import HERMES_COMMIT, fixture_environment, git_head, git_tree
from native_install import approval_values, confirmation_arguments
from offline_guard import deny_network


class CautionConfirmationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # No keys/config/atlas from a profile. Only the exact public committed
        # Hermes archive is read; dependencies come from the selected interpreter.
        cls.workspace = scratch_home()
        cls.authority = scratch_home()
        cls.root = Path(cls.workspace.__enter__())
        cls.trust = Path(cls.authority.__enter__())
        cls.addClassCleanup(cls.workspace.__exit__, None, None, None)
        cls.addClassCleanup(cls.authority.__exit__, None, None, None)
        (cls.root / "synthetic-atlas-home").touch()
        source = Path(os.environ["NETWORK_ATLAS_HERMES_ROOT"])
        if git_head(source) != HERMES_COMMIT:
            raise ValueError("regressions require the exact public Hermes Git checkout")
        cls.source = cls.root / "hermes-source"
        cls.source.mkdir()
        archive = subprocess.check_output(["git", "-C", str(source), "archive", HERMES_COMMIT], timeout=60)
        with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
            bundle.extractall(cls.source, filter="data")
        cls.key = cls.trust / "synthetic-key"
        cls.checked(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(cls.key)])
        cls.signers = cls.trust / "allowed-signers"
        cls.signers.write_text("fixture-operator " + cls.key.with_suffix(".pub").read_text())

    @staticmethod
    def checked(command, **kwargs):
        result = subprocess.run(command, capture_output=True, timeout=30, **kwargs)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        return result

    def setUp(self):
        self.case = self.root / self._testMethodName
        self.case.mkdir()
        self.env = fixture_environment(self.root)
        home = self.case / "hermes"
        home.mkdir()
        (self.case / "user").mkdir()
        (home / "config.yaml").write_text(json.dumps({"plugins": {"enabled": [], "disabled": []}}))
        self.env.update(HERMES_HOME=str(home), HOME=str(self.case / "user"))
        self.candidate = self.case / "candidate"
        self.candidate.mkdir()
        (self.candidate / "plugin.yaml").write_text("name: network-atlas\nversion: '1.0'\ndescription: Synthetic admission test\n")
        (self.candidate / "__init__.py").write_text("def register(ctx):\n    pass\n")
        (self.candidate / "README.md").write_text("Preinstalled setuid helpers are not permitted.\n")
        self.commit_candidate()
        self.origin = git_head(self.candidate)
        self.scope = "synthetic-local-test-only"
        self.command = [sys.executable, str(ROOT / "scripts" / "native_install.py"), str(self.source)]

    def commit_candidate(self):
        for args in (("init", "-q"), ("add", "."), ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                                                "commit", "-qm", "Synthetic admission fixture")):
            self.checked(["git", "-C", str(self.candidate), *args], env=self.env)

    def request(self):
        result = self.checked([*self.command, "scan", str(self.candidate), git_head(self.candidate),
                               "--origin-commit", self.origin, "--confirmation-scope", self.scope], env=self.env)
        return json.loads(result.stdout)

    def signed(self, request):
        approval = self.trust / (self._testMethodName + ".json")
        approval.write_bytes(confirmation.canonical(request))
        self.checked(["/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(self.key), "-n", confirmation.NAMESPACE, str(approval)])
        return approval, Path(str(approval) + ".sig")

    def verify(self, request, approval, signature, signers=None):
        confirmation.verify_approval(request, approval, signature, signers or self.signers,
                                     "fixture-operator", (ROOT, self.root))

    def install_command(self, approval=None, signature=None):
        command = [*self.command, "install", str(self.candidate), git_head(self.candidate)]
        if approval:
            command.extend(["--approval", str(approval), "--approval-signature", str(signature),
                            "--allowed-signers", str(self.signers), "--signer", "fixture-operator",
                            "--confirmation-scope", self.scope, "--origin-commit", self.origin])
        return command

    def test_native_caution_in_ci_non_tty_refuses_without_approval(self):
        request = self.request()
        self.assertEqual(request["verdict"], "caution")
        self.assertIsNone(request["ordinary_decision"])
        self.assertTrue(request["findings"])
        result = subprocess.run(self.install_command(), env=self.env, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Security scan flagged", result.stdout)
        self.assertFalse((Path(self.env["HERMES_HOME"]) / "plugins" / "network-atlas").exists())
        parser = argparse.ArgumentParser()
        confirmation_arguments(parser)
        self.assertIsNone(approval_values(parser.parse_args([])))
        with self.assertRaises(ValueError):
            approval_values(parser.parse_args(["--confirmation-scope", self.scope]))

    def test_missing_or_candidate_controlled_authority_refuses(self):
        request = self.request()
        approval, signature = self.signed(request)
        with self.assertRaises(FileNotFoundError):
            self.verify(request, self.trust / "missing", signature)
        with self.assertRaises(FileNotFoundError):
            self.verify(request, approval, self.trust / "missing-signature")
        result = subprocess.run(self.install_command(self.trust / "missing", signature), env=self.env,
                                capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(confirmation.marker(request), result.stdout)
        self.assertFalse((Path(self.env["HERMES_HOME"]) / "plugins" / "network-atlas").exists())
        for path in (self.candidate / "approval", self.case / "anchor"):
            path.write_bytes(approval.read_bytes())
            with self.assertRaisesRegex(ValueError, "outside candidate"):
                self.verify(request, path, signature)
        link = self.trust / "candidate-link"
        link.symlink_to(self.candidate / "approval")
        with self.assertRaisesRegex(ValueError, "outside candidate"):
            self.verify(request, link, signature)

    def test_exact_commit_tree_scope_scanner_findings_and_signature_mismatches_refuse(self):
        request = self.request()
        approval, signature = self.signed(request)
        self.verify(request, approval, signature)
        with self.assertRaisesRegex(ValueError, "signature refused"):
            confirmation.verify_approval(request, approval, signature, self.signers, "another-operator", (ROOT, self.root))
        other_key = self.trust / "untrusted-synthetic-key"
        self.checked(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(other_key)])
        wrong_anchor = self.trust / "wrong-anchor"
        wrong_anchor.write_text("fixture-operator " + other_key.with_suffix(".pub").read_text())
        with self.assertRaisesRegex(ValueError, "signature refused"):
            self.verify(request, approval, signature, wrong_anchor)
        for key in ("candidate_commit", "candidate_tree", "scope", "hermes_commit", "hermes_tree",
                    "hermes_source_digest", "scanner_version", "scanner_files", "findings"):
            changed = dict(request)
            changed[key] = "mismatched"
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "does not bind exact"):
                self.verify(changed, approval, signature)
        payload = approval.read_bytes()
        approval.write_bytes(payload + b"\n")
        with self.assertRaises(ValueError):
            self.verify(request, approval, signature)
        approval.write_bytes(payload)
        signature.write_text("invalid detached signature")
        with self.assertRaisesRegex(ValueError, "signature refused"):
            self.verify(request, approval, signature)
        result = subprocess.run(self.install_command(approval, signature), env=self.env, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(confirmation.marker(request), result.stdout)

    def test_genuinely_dangerous_full_tree_refuses_even_signed_approval(self):
        (self.candidate / "escape").symlink_to(self.trust / "allowed-signers")
        self.commit_candidate()
        self.origin = git_head(self.candidate)
        request = self.request()
        self.assertEqual(request["verdict"], "dangerous")
        self.assertIs(request["ordinary_decision"], False)
        approval, signature = self.signed(request)
        with self.assertRaisesRegex(ValueError, "dangerous always refuses"):
            self.verify(request, approval, signature)
        result = subprocess.run(self.install_command(approval, signature), env=self.env, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(confirmation.marker(request), result.stdout)
        self.assertFalse((Path(self.env["HERMES_HOME"]) / "plugins" / "network-atlas").exists())

    def test_synthetic_signed_caution_reaches_ordinary_native_prompt_with_network_denied_pm(self):
        request = self.request()
        approval, signature = self.signed(request)
        self.verify(request, approval, signature)
        # The ordinary scanner/prompt is exercised. Downstream native PM lacks
        # an admitted toolchain in this empty synthetic home and cannot download
        # under inherited socket denial. Do not disguise this as native acceptance.
        with self.assertRaises(RuntimeError) as failure:
            confirmation.install_confirmed(self.install_command(approval, signature), self.root, self.env, request, timeout=30)
        output = str(failure.exception)
        self.assertIn("Security scan flagged", output)
        self.assertIn(confirmation.PROMPT.decode() + " y", output)
        self.assertIn("was not published", output)
        installed = Path(self.env["HERMES_HOME"]) / "plugins" / "network-atlas"
        self.assertFalse(installed.exists())
        config = json.loads((Path(self.env["HERMES_HOME"]) / "config.yaml").read_text())
        self.assertNotIn("network-atlas", config["plugins"]["enabled"])
        self.assertFalse((self.root / "admission.json").exists())

    def test_synthetic_verified_child_prompt_transport_answers_once_and_exits(self):
        request = self.request()
        script = self.case / "verified-prompt.py"
        script.write_text("import sys\nprint(" + repr(confirmation.marker(request).decode()) + ", flush=True)\n"
                          "print(" + repr(confirmation.PROMPT.decode()) + ", flush=True)\n"
                          "answer = sys.stdin.readline()\nassert answer == 'y\\n'\nprint('synthetic prompt consumed once', flush=True)\n")
        output = confirmation.install_confirmed([sys.executable, str(script)], self.root, self.env, request, timeout=2)
        self.assertIn("synthetic prompt consumed once", output)

    def test_signed_request_cannot_confirm_changed_candidate_or_core(self):
        request = self.request()
        approval, signature = self.signed(request)
        (self.candidate / "untracked.txt").write_text("entire tree matters")
        result = subprocess.run(self.install_command(approval, signature), env=self.env, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"clean candidate", result.stderr)
        self.commit_candidate()
        result = subprocess.run(self.install_command(approval, signature), env=self.env, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"does not bind exact", result.stderr)
        scanner = self.source / "tools" / "plugin_guard.py"
        original = scanner.read_bytes()
        try:
            scanner.write_bytes(original + b"\n# changed scanner\n")
            result = subprocess.run([*self.command, "scan", str(self.candidate), git_head(self.candidate),
                                     "--origin-commit", self.origin, "--confirmation-scope", self.scope], env=self.env,
                                    capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"identity mismatch", result.stderr)
        finally:
            scanner.write_bytes(original)

    def test_prompt_transport_without_matching_marker_or_with_bounds_never_confirms(self):
        request = self.request()
        script = self.case / "prompt.py"
        script.write_text("import sys\nprint('Install anyway? Only continue if you trust the source. [y/N]:', flush=True)\nprint(sys.stdin.readline(), flush=True)\n")
        with self.assertRaises((RuntimeError, subprocess.TimeoutExpired)):
            confirmation.install_confirmed([sys.executable, str(script)], self.root, self.env, request, timeout=0.2)
        script.write_text("print('x' * 4096, flush=True)\n")
        with self.assertRaisesRegex(RuntimeError, "output bound"):
            confirmation.install_confirmed([sys.executable, str(script)], self.root, self.env, request, timeout=2, output_limit=1024)
        sleeper = self.case / "sleeper.py"
        sleeper.write_text("import time\ntime.sleep(30)\n")
        pid_file = self.case / "owned-pid"
        script.write_text("import subprocess, sys\nfrom pathlib import Path\n"
                          "child = subprocess.Popen([sys.executable, " + repr(str(sleeper)) + "])\n"
                          "Path(" + repr(str(pid_file)) + ").write_text(str(child.pid))\n"
                          "print(" + repr(confirmation.marker(request).decode()) + ", flush=True)\n"
                          "print(" + repr(confirmation.PROMPT.decode()) + ", flush=True)\n"
                          "assert sys.stdin.readline() == 'y\\n'\n")
        unrelated = subprocess.Popen([sys.executable, str(sleeper)], env=self.env, start_new_session=True,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            with self.assertRaisesRegex(RuntimeError, "deadline exceeded"):
                confirmation.install_confirmed([sys.executable, str(script)], self.root, self.env, request, timeout=0.5)
            self.assertIsNone(unrelated.poll())
            owned = Path("/proc") / pid_file.read_text() / "stat"
            deadline = time.monotonic() + 2
            while owned.exists() and owned.read_text().split()[2] != "Z" and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(not owned.exists() or owned.read_text().split()[2] == "Z")
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=5)


if __name__ == "__main__":
    deny_network()
    unittest.main()
