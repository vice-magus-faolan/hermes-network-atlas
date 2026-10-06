# SPDX-License-Identifier: GPL-3.0-or-later
"""Packet-free Docker contract tests; these are not real Docker/native acceptance."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home

sys.path.insert(0, str(ROOT / "scripts"))
import docker_contract as contract
import docker_acceptance as harness
import native_install


class DockerContractTests(unittest.TestCase):
    def identity(self):
        return contract.Identity("a" * 40, "b" * 40, "sha256:" + "c" * 64, "daemon-fixture")

    def test_identity_labels_endpoint_and_optimized_refusal(self):
        identity = self.identity()
        self.assertEqual(identity.labels()[contract.OWNER], contract.OWNER_VALUE)
        for args in (("short", identity.tree, identity.image, identity.daemon),
                     (identity.commit, "B" * 40, identity.image, identity.daemon),
                     (identity.commit, identity.tree, "latest", identity.daemon),
                     (identity.commit, identity.tree, identity.image, "")):
            with self.assertRaises(ValueError):
                contract.Identity(*args)
        for env in ({"DOCKER_HOST": "tcp://remote:2375"}, {"DOCKER_CONTEXT": "remote"},
                    {"DOCKER_TLS_VERIFY": "1"}):
            with self.assertRaises(ValueError):
                contract.check_endpoint(env, {"ID": identity.daemon, "OSType": "linux", "Architecture": "x86_64"}, identity)
        contract.check_endpoint({}, {"ID": identity.daemon, "OSType": "linux", "Architecture": "x86_64"}, identity)
        with self.assertRaises(ValueError):
            contract.check_endpoint({}, {"ID": "other", "OSType": "linux", "Architecture": "x86_64"}, identity)

    def test_readonly_mounts_no_network_privileges_ports_or_ambient_env(self):
        with scratch_home() as directory:
            candidate = Path(directory) / "candidate"
            candidate.mkdir()
            (Path(directory) / "incoming").mkdir()
            argv = contract.create_command(self.identity(), candidate, "smoke")
            self.assertIn("--read-only", argv)
            self.assertEqual(argv[argv.index("--network") + 1], "none")
            self.assertEqual(argv[argv.index("--user") + 1], "1000:1000")
            self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
            self.assertIn("no-new-privileges=true", argv)
            self.assertEqual(argv.count("--mount"), 2)
            self.assertIn("readonly", argv[argv.index("--mount") + 1])
            self.assertFalse(set(argv) & {"--privileged", "--publish", "-p", "--device", "--volume", "--pid", "--force"})
            self.assertNotIn("docker.sock", " ".join(argv))
            self.assertNotIn("GITHUB_ACTIONS", " ".join(argv))
            for mode in ("hosted-ci-caution", "arbitrary"):
                with self.assertRaises(ValueError):
                    contract.create_command(self.identity(), candidate, mode)
            link = Path(directory) / "link"
            link.symlink_to(candidate)
            with self.assertRaises(ValueError):
                contract.create_command(self.identity(), link, "smoke")

    def inspection(self, candidate):
        identity = self.identity()
        return {"Id": "d" * 64, "Name": "/" + contract.NAME, "Image": identity.image,
                "Config": {"Labels": identity.labels(), "User": "1000:1000", "Env": [],
                           "Cmd": ["python3", "/candidate/scripts/docker_inside.py", "smoke"],
                           "Entrypoint": None, "Volumes": None},
                "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True,
                               "CapDrop": ["ALL"], "CapAdd": None, "Privileged": False,
                               "SecurityOpt": ["no-new-privileges=true"], "Init": True,
                               "PidMode": "", "IpcMode": "private", "Devices": [],
                               "Binds": None, "PortBindings": {}, "Memory": contract.MEMORY,
                               "MemorySwap": contract.MEMORY, "NanoCpus": 2000000000,
                               "PidsLimit": 256, "LogConfig": {"Type": "local", "Config": {"max-size": "4m", "max-file": "1", "compress": "false"}},
                               "Tmpfs": contract.TMPFS},
                "Mounts": [{"Type": "bind", "Source": str(candidate), "Destination": "/candidate", "RW": False},
                           {"Type": "bind", "Source": str(candidate.parent / "incoming"), "Destination": "/export", "RW": True}],
                "NetworkSettings": {"Networks": {"none": {}}}, "State": {"Running": False}}

    def test_inspection_drift_rejects_wrong_labels_image_mounts_flags_network(self):
        with scratch_home() as directory:
            candidate = Path(directory)
            inspected = self.inspection(candidate)
            self.assertEqual(contract.validate_container(inspected, self.identity(), candidate, "smoke"), "d" * 64)
            mutations = [("Image", "sha256:" + "e" * 64), ("Name", "/unrelated")]
            for key, value in mutations:
                changed = json.loads(json.dumps(inspected))
                changed[key] = value
                with self.assertRaises(ValueError):
                    contract.validate_container(changed, self.identity(), candidate, "smoke")
            for key, value in (("Privileged", True), ("NetworkMode", "bridge"), ("ReadonlyRootfs", False),
                               ("CapAdd", ["NET_RAW"]), ("PidMode", "host"), ("Memory", 0),
                               ("PortBindings", {"80/tcp": []}), ("SecurityOpt", ["seccomp=unconfined"])):
                changed = json.loads(json.dumps(inspected))
                changed["HostConfig"][key] = value
                with self.assertRaises(ValueError):
                    contract.validate_container(changed, self.identity(), candidate, "smoke")
            changed = json.loads(json.dumps(inspected))
            changed["Config"]["Labels"][contract.OWNER] = "unrelated"
            with self.assertRaises(ValueError):
                contract.validate_container(changed, self.identity(), candidate, "smoke")
            inspected["Mounts"][0]["RW"] = True
            with self.assertRaises(ValueError):
                contract.validate_container(inspected, self.identity(), candidate, "smoke")

    def test_acceptance_command_requires_exact_uncompressed_bounded_local_logs(self):
        with scratch_home() as directory:
            root = Path(directory)
            for mode in contract.MODES:
                hosted = {"GITHUB_WORKSPACE": "/candidate"} if mode == "hosted-accept" else None
                argv = contract.create_command(self.identity(), root, mode, root, hosted=hosted)
                options = [argv[index + 1] for index, value in enumerate(argv) if value == "--log-opt"]
                self.assertEqual(argv.count("--log-driver"), 1)
                self.assertEqual(argv[argv.index("--log-driver") + 1], "local")
                self.assertCountEqual(options, ["max-size=4m", "max-file=1", "compress=false"])

    def test_acceptance_inspection_refuses_missing_compressed_extra_or_expanded_logs(self):
        with scratch_home() as directory:
            candidate = Path(directory)
            data = self.inspection(candidate)
            contract.validate_container(data, self.identity(), candidate, "smoke")
            for change in ({"compress": None}, {"compress": "true"}, {"compress": False},
                           {"max-size": "8m"}, {"max-size": None}, {"max-file": "2"},
                           {"max-file": None}, {"extra": "false"}):
                mutated = json.loads(json.dumps(data))
                config = mutated["HostConfig"]["LogConfig"]["Config"]
                config.update(change)
                config = {key: value for key, value in config.items() if value is not None}
                mutated["HostConfig"]["LogConfig"]["Config"] = config
                with self.subTest(change=change), self.assertRaises(ValueError):
                    contract.validate_container(mutated, self.identity(), candidate, "smoke")
            data["HostConfig"]["LogConfig"]["Type"] = "json-file"
            with self.assertRaises(ValueError):
                contract.validate_container(data, self.identity(), candidate, "smoke")

    def test_actual_counts_exit_zero_skips_missing_and_mismatch_refuse(self):
        log = "Canonical verification: 3 tests discovered; synthetic\nRan 3 tests in 1.0s\n\nOK\n"
        self.assertEqual(contract.verification_result(log, 0), {"tests": 3, "exit_code": 0, "passed": True})
        for text, code in ((log, 1), (log.replace("Ran 3", "Ran 2"), 0),
                           (log.replace("3 tests", "0 tests"), 0), (log + "skipped=1", 0),
                           ("OK\n", 0), (log + "FAILED (failures=1)", 0)):
            with self.assertRaises(ValueError):
                contract.verification_result(text, code)

    def archive(self, name="scan.json", size=2, kind=tarfile.REGTYPE):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as bundle:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = size if kind == tarfile.REGTYPE else 0
            member.linkname = "../../outside"
            bundle.addfile(member, io.BytesIO(b"{}") if member.size else None)
        return buffer.getvalue()

    def test_evidence_bounds_traversal_symlinks_export_failure_and_hashes(self):
        with scratch_home() as directory:
            root = Path(directory)
            exported = root / "evidence"
            manifest = contract.export_archive(self.archive(), exported)
            self.assertIn("scan.json", manifest)
            self.assertEqual(len(manifest["scan.json"]), 64)
            for name, kind in (("../../outside", tarfile.REGTYPE), ("/etc/escape", tarfile.REGTYPE),
                               ("link", tarfile.SYMTYPE), ("link", tarfile.LNKTYPE)):
                with self.assertRaises(ValueError):
                    contract.export_archive(self.archive(name, kind=kind), root / "bad")
            with self.assertRaises(ValueError):
                contract.export_archive(b"x" * (contract.EVIDENCE_LIMIT + 1), root / "large")
            with self.assertRaises(FileExistsError):
                contract.export_archive(self.archive(), exported)

    def test_cleanup_identity_duplicate_residue_and_unrelated_preservation(self):
        identity = self.identity()
        self.assertFalse(contract.cleanup_allowed(None, identity))
        inspected = {"Id": "d" * 64, "Image": identity.image, "Name": "/" + contract.NAME,
                     "Config": {"Labels": identity.labels()}}
        self.assertTrue(contract.cleanup_allowed(inspected, identity))
        inspected["Config"]["Labels"][contract.OWNER] = "other"
        with self.assertRaises(ValueError):
            contract.cleanup_allowed(inspected, identity)


class DockerLifecycleTests(unittest.TestCase):
    identity = DockerContractTests.identity
    inspection = DockerContractTests.inspection
    def test_actual_bounded_command_pass_fail_deadline_output_and_owned_cleanup(self):
        self.assertEqual(harness.command(["/usr/bin/true"]), b"")
        with self.assertRaises(subprocess.CalledProcessError):
            harness.command(["/usr/bin/false"])
        with scratch_home() as directory:
            program = Path(directory) / "child.py"
            program.write_text("import time\ntime.sleep(10)\n")
            with self.assertRaises(TimeoutError):
                harness.command([sys.executable, str(program)], timeout=0.1)
            program.write_text("print('x' * 10000)\n")
            with self.assertRaisesRegex(RuntimeError, "output"):
                harness.command([sys.executable, str(program)], limit=100)

    def test_active_lease_refuses_and_releases_without_suffix_retry(self):
        with scratch_home() as directory:
            root = Path(directory)
            with harness.lease(root):
                with self.assertRaises(BlockingIOError):
                    with harness.lease(root):
                        self.fail("second lease entered")
            with harness.lease(root):
                self.assertEqual({path.name for path in root.iterdir()}, {"lease"})

    def test_complete_shallow_snapshot_exact_public_commit_tree_no_host_git(self):
        with scratch_home() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "public.txt").write_text("synthetic public source\n")
            for args in (("init", "-q"), ("add", "."), ("-c", "user.name=Synthetic", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")):
                harness.command(["git", "-C", str(source), *args])
            commit = harness.git_head(source)
            snapshot = root / "candidate"
            harness.snapshot(source, commit, snapshot)
            self.assertEqual(harness.git_head(snapshot), commit)
            self.assertEqual(harness.git_tree(snapshot), harness.git_tree(source))
            self.assertEqual((snapshot / "public.txt").read_bytes(), (source / "public.txt").read_bytes())
            self.assertFalse((snapshot / ".git").is_symlink())
            self.assertNotEqual((snapshot / ".git").stat().st_ino, (source / ".git").stat().st_ino)

    def test_teardown_duplicate_residue_wrong_identity_no_unrelated_remove(self):
        class Fake:
            def __init__(self, data):
                self.data, self.calls, self.residue = data, [], False
            def inspect(self, _identifier):
                return self.data
            def run(self, args, **_kwargs):
                self.calls.append(args)
                if args[0] == "stop":
                    self.data["State"]["Running"] = False
                if args[0] == "rm" and not self.residue:
                    self.data = None
                return b""
        with scratch_home() as directory:
            fake = Fake(self.inspection(Path(directory)))
            harness.teardown(fake, self.identity())
            calls = list(fake.calls)
            harness.teardown(fake, self.identity())
            self.assertEqual(fake.calls, calls)
            fake.data = self.inspection(Path(directory))
            fake.residue = True
            with self.assertRaisesRegex(RuntimeError, "residue"):
                harness.teardown(fake, self.identity())
            fake.data["Config"]["Labels"][contract.OWNER] = "unrelated"
            calls = list(fake.calls)
            with self.assertRaises(ValueError):
                harness.teardown(fake, self.identity())
            self.assertEqual(fake.calls, calls)

    def test_failed_export_keeps_original_failure_and_still_tears_down(self):
        with scratch_home() as directory:
            root = Path(directory)
            outcome = {"error": "original failure", "mode": "fail"}
            fake = SimpleNamespace(inspect=lambda _name: None)
            with patch.object(harness, "collect_export", side_effect=OSError("export failed")), patch.object(harness, "teardown") as cleanup:
                harness.finish_attempt(fake, root, root, self.identity(), outcome)
            self.assertEqual(outcome["error"], "original failure")
            self.assertIn("export failed", outcome["export_error"])
            cleanup.assert_called_once()
            self.assertTrue(outcome["cleanup_verified"])

    def test_acceptance_stopped_error_survives_log_failure_and_owned_teardown(self):
        with scratch_home() as directory:
            root = Path(directory)
            data = self.inspection(root)
            error = "failed to initialize logging driver: compression cannot be enabled when max file count is 1"
            data["State"].update(Status="created", ExitCode=128, Error=error)
            calls = []
            def run(argv, **_kwargs):
                calls.append(argv)
                if argv[0] == "logs":
                    raise OSError("synthetic failed log export")
                if argv[0] == "rm":
                    data.clear()
                return b""
            fake = SimpleNamespace(inspect=lambda *_args: data or None, run=run)
            outcome = {"error": "original start failed", "mode": "smoke"}
            harness.finish_attempt(fake, root, root, self.identity(), outcome)
            stopped = json.loads((root / "metadata" / "stopped.json").read_text())
            self.assertEqual(stopped["State"]["Error"], error)
            self.assertEqual(stopped["State"]["Status"], "created")
            self.assertEqual(outcome["error"], "original start failed")
            self.assertIn("failed log export", outcome["export_error"])
            self.assertTrue(outcome["cleanup_verified"])
            self.assertEqual([argv[0] for argv in calls], ["logs", "rm"])
            self.assertNotIn("native_acceptance", outcome)

    def test_unattended_accept_refuses_before_any_daemon_effect(self):
        fake = SimpleNamespace(json=lambda _args: self.fail("daemon read before consent refusal"))
        with patch.object(sys.stdin, "isatty", return_value=False):
            with self.assertRaisesRegex(ValueError, "unattended"):
                harness.attempt_preflight(fake, Path("/unused"), self.identity().image, "accept")

    def test_containerd_and_unknown_build_backend_refuse_before_mutation(self):
        for info in ({"Driver": "overlayfs", "DriverStatus": [["driver-type", "io.containerd.snapshotter.v1"]]},
                     {}, {"Driver": "unexpected"}):
            with self.subTest(info=info):
                fake = SimpleNamespace(info=info, run=lambda *_args: self.fail("mutation or resource query before refusal"))
                with self.assertRaisesRegex(ValueError, "before effects"):
                    harness.build_base(fake, Path("/unused"), Path("/unused"))
        harness.require_supported_builder({"Driver": "overlay2", "DriverStatus": []})

    def test_optimized_native_readback_mismatch_manifest_and_generation_refuse(self):
        with scratch_home() as directory:
            root = Path(directory)
            source, home = root / "source", root / "home"
            config = SimpleNamespace(load_config_readonly=lambda: {"plugins": {"enabled": []}})
            pm = SimpleNamespace(runtime_facts_path=lambda _source: root / "facts",
                                 selected_venv=lambda _source: root / "generation",
                                 venv_python=lambda path: path / "bin" / "python")
            with patch.dict(sys.modules, {"hermes_cli.config": config, "pm.environments": pm}):
                with self.assertRaisesRegex(ValueError, "selection"):
                    native_install.readback(root, source, home, "enable")
                with self.assertRaisesRegex(ValueError, "manifest"):
                    native_install.readback(root, source, home, "install")
                plugin = home / "plugins" / "network-atlas"
                plugin.mkdir(parents=True)
                (plugin / "plugin.yaml").touch()
                config.load_config_readonly = lambda: {"plugins": {"enabled": ["network-atlas"]}}
                with patch.object(native_install, "git_head", return_value="a" * 40), patch.object(native_install, "git_tree", return_value="b" * 40):
                    with self.assertRaisesRegex(ValueError, "generation"):
                        native_install.readback(root, source, home, "enable")


if __name__ == "__main__":
    unittest.main()
