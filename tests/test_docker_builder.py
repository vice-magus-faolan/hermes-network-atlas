# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic builder/export contracts; never connect to a Docker daemon."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tarfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from helpers import ROOT, scratch_home
sys.path.insert(0, str(ROOT / "scripts"))
import docker_builder as builder
import docker_evidence as evidence
import docker_acceptance as harness
import docker_cold as cold
import docker_inside as inside
import test_result_report
sys.path.insert(0, str(ROOT / "docker"))
import acquisition_support as acquisition


def invented_plan():
    categories = ("upstream-layer", "apt-index", "apt-package", "pm-tool", "verifier-wheel", "union-wheel", "core-archive")
    return {"schema": 1, "status": "resolved", "core_commit": builder.HERMES_COMMIT,
            "core_tree": builder.CORE_TREE, "platform": "linux/amd64", "upstream": builder.UPSTREAM_DIGEST,
            "upstream_image": "sha256:" + "a" * 64, "rootfs_layers": ["sha256:" + "b" * 64],
            "inputs": {name: "c" * 64 for name in builder.INPUT_FILES},
            "closures": {name: True for name in ("apt", "pm", "verifier", "union")},
            "artifacts": [{"category": name, "name": name, "version": "1", "filename": name + ".tar",
                           "url": "https://files.pythonhosted.org/" + name, "sha256": "d" * 64,
                           "compressed_bytes": 100, "unpacked_bytes": 1000, "members": 10}
                          for name in categories], "unknowns": []}


from docker_plan_fixture import linked_plan


def plan():
    return linked_plan(builder)


def identity():
    return builder.BootstrapIdentity("e" * 64, "daemon-fixture", "sha256:" + "a" * 64, "f" * 64)


def inspected(context, running=False):
    value = identity()
    return {"Id": "1" * 64, "Name": "/" + builder.BOOTSTRAP_NAME, "Image": value.image,
            "Config": {"User": "0:0", "Labels": value.labels(), "Entrypoint": None, "Volumes": None,
                       "Env": [], "Cmd": ["python3", "/opt/inputs/base_setup.py"]},
            "HostConfig": builder.bootstrap_host_config(),
            "Mounts": [{"Type": "bind", "Source": str(context), "Destination": "/opt/inputs", "RW": False}],
            "NetworkSettings": {"Networks": {"bridge": {}}},
            "State": {"Running": running, "Status": "running" if running else "exited", "ExitCode": 0}}


class BuilderContractTests(unittest.TestCase):
    def setUp(self):
        # Synthetic OCI anchor only for pure/mock tests, never public acquisition.
        pin = patch.object(builder, "UPSTREAM_DIGEST", plan()["upstream"])
        pin.start()
        self.addCleanup(pin.stop)
        runtime_pin = patch.object(harness, "UPSTREAM_DIGEST", plan()["upstream"])
        runtime_pin.start()
        self.addCleanup(runtime_pin.stop)

    def test_invented_plan_without_source_closure_refuses_before_effects(self):
        calls = []
        fake = SimpleNamespace(run=lambda *_args, **_kw: calls.append("effect"))
        with self.assertRaises(ValueError):
            builder.validate_plan(invented_plan())
        with self.assertRaises(ValueError):
            builder.build_owned(fake, Path("/unused"), Path("/unused"), invented_plan(), Path("/unused"), foreground=True)
        self.assertEqual(calls, [])

    def test_suffix_registry_wrong_home_profile_and_temporary_parent_refuse(self):
        scratch = Path(os.environ["TMPDIR"])
        for parent in (Path("/unrelated"), scratch, Path("/unrelated/.hermes/profiles/other")):
            wrong = parent / ".hermes/network-atlas/docker-acceptance"
            with self.subTest(parent=parent), self.assertRaises(ValueError):
                builder.registry_path(wrong, scratch / "different-pruning-boundary")

    def test_public_input_context_exact_hashes_readable_for_capless_setup_without_broad_chmod(self):
        with scratch_home() as directory:
            root = Path(directory)
            root.chmod(0o700)
            source = root / "public-core"
            source.mkdir()
            value = plan()
            payloads = {name: ("synthetic public " + name).encode() for name in builder.INPUT_FILES}
            value["inputs"] = {name: hashlib.sha256(data).hexdigest() for name, data in payloads.items()}
            next(item for item in value["artifacts"] if item["category"] == "core-archive")["compressed_bytes"] = len(payloads["hermes.tar"])
            def command(args, **_kwargs):
                if args[-1] == "--show-toplevel":
                    return str(source).encode()
                if "status" in args:
                    return b""
                if "show" in args:
                    return payloads[Path(args[-1]).name]
                return payloads["hermes.tar" if "archive" in args else "hermes.commit"]
            destination = root / "context"
            with patch.object(harness, "command", side_effect=command), patch.object(harness, "git_head", return_value=builder.HERMES_COMMIT), \
                    patch.object(harness, "validate_plan"), patch.object(harness, "validate_pinned_sources"):
                key = harness.base_context(source, destination, value)
            self.assertEqual(len(key), 64)
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o755)
            self.assertEqual(set(path.name for path in destination.iterdir()), set(builder.INPUT_FILES) | {"acquisition.json"})
            self.assertTrue(all(path.stat().st_mode & 0o777 == 0o644 for path in destination.iterdir()))
            self.assertFalse((destination / ".git").exists())

    def test_complete_plan_identity_unknown_lengths_hashes_and_peak_reserve(self):
        value = plan()
        result = builder.validate_plan(value)
        self.assertGreater(result["peak_bytes"], 700)
        builder.require_space(value, result["peak_bytes"] + builder.RESERVE)
        with self.assertRaisesRegex(ValueError, "additional"):
            builder.require_space(value, result["peak_bytes"] + builder.RESERVE - 1)
        for path, bad in (("status", "partial_metadata_not_an_acquisition_lock"), ("core_commit", "x" * 40),
                          ("unknowns", ["unpacked size"]), ("closures", {"apt": True}),
                          ("upstream_image", "latest"), ("platform", "linux/arm64")):
            mutated = copy.deepcopy(value)
            mutated[path] = bad
            with self.subTest(path=path), self.assertRaises(ValueError):
                builder.validate_plan(mutated)
        for key, bad in (("compressed_bytes", None), ("compressed_bytes", True), ("unpacked_bytes", 0),
                         ("members", -1), ("sha256", "guess"), ("url", "http://127.0.0.1/x"),
                         ("filename", "../outside")):
            mutated = copy.deepcopy(value)
            mutated["artifacts"][0][key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                builder.validate_plan(mutated)

    def test_bootstrap_root_is_private_bounded_public_readonly_not_candidate(self):
        with scratch_home() as directory:
            root = Path(directory)
            argv = builder.bootstrap_command(identity(), root)
            self.assertEqual(argv[argv.index("--user") + 1], "0:0")
            self.assertEqual(argv[argv.index("--network") + 1], "bridge")
            self.assertIn("--cap-drop", argv)
            self.assertIn("no-new-privileges=true", argv)
            self.assertIn("readonly", argv[argv.index("--mount") + 1])
            self.assertFalse(set(argv) & {"--privileged", "--device", "--publish", "--pid", "--volume", "--force"})
            self.assertNotIn("candidate", " ".join(argv))
            self.assertNotIn("docker.sock", " ".join(argv))
            builder.validate_bootstrap(inspected(root), identity(), root)
            for section, key, bad in (("HostConfig", "CapAdd", ["CHOWN"]), ("HostConfig", "NetworkMode", "host"),
                                      ("HostConfig", "RestartPolicy", {"Name": "always"}),
                                      ("Config", "User", "1000:1000"), ("Config", "Env", ["GITHUB_ACTIONS=true"])):
                value = inspected(root)
                value[section][key] = bad
                with self.subTest(key=key), self.assertRaises(ValueError):
                    builder.validate_bootstrap(value, identity(), root)
            value = inspected(root)
            value["Mounts"][0]["RW"] = True
            with self.assertRaises(ValueError):
                builder.validate_bootstrap(value, identity(), root)

    def test_commit_requires_stopped_exact_owned_rootfs_and_final_nonroot_labels(self):
        with scratch_home() as directory:
            root = Path(directory)
            command = builder.commit_command(inspected(root), identity(), root)
            self.assertEqual(command[-2], "1" * 64)
            self.assertIn("USER 1000:1000", command)
            self.assertIn("CMD []", command)
            self.assertNotIn("--pause=false", command)
            for field, bad in (("Image", "sha256:" + "2" * 64), ("Id", "short"), ("Name", "/unrelated")):
                value = inspected(root)
                value[field] = bad
                with self.assertRaises(ValueError):
                    builder.commit_command(value, identity(), root)
            with self.assertRaisesRegex(ValueError, "stopped"):
                builder.commit_command(inspected(root, running=True), identity(), root)

    def test_durable_registry_contract_not_scratch_symlink_or_ambient_profile(self):
        with scratch_home() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                builder.registry_path(root / "registry", root)
            durable = root / ".hermes" / "network-atlas" / "docker-acceptance"
            # Tests use a separate synthetic pruning boundary, never a live registry.
            self.assertEqual(builder._registry_identity(durable, root / "scratch", durable), durable)
            durable.mkdir(parents=True)
            durable.chmod(0o700)
            link = root / "link"
            link.symlink_to(durable)
            with self.assertRaises(ValueError):
                builder.registry_path(link, root / "scratch")

    def test_unapproved_or_incomplete_plan_never_reaches_daemon_or_native(self):
        calls = []
        fake = type("Fake", (), {"run": lambda *_args, **_kw: calls.append("effect")})()
        with self.assertRaisesRegex(ValueError, "foreground"):
            builder.build_owned(fake, Path("/unused"), Path("/unused"), plan(), Path("/unused"), foreground=False)
        with self.assertRaises(ValueError):
            builder.build_owned(fake, Path("/unused"), Path("/unused"), {"status": "partial"}, Path("/unused"), foreground=True)
        self.assertEqual(calls, [])

    def test_owned_cleanup_duplicate_wrong_labels_and_residue_preserve_unrelated(self):
        with scratch_home() as directory:
            root = Path(directory)
            class Fake:
                def __init__(self):
                    self.data = inspected(root, running=True)
                    self.calls = []
                    self.residue = False
                def inspect(self, *_args, **_kw):
                    return self.data
                def run(self, args, **_kw):
                    self.calls.append(args)
                    if args[0] == "stop":
                        self.data["State"].update(Running=False, Status="exited")
                    if args[0] == "rm" and not self.residue:
                        self.data = None
                    return b""
            fake = Fake()
            builder.teardown_bootstrap(fake, identity())
            self.assertEqual([row[0] for row in fake.calls], ["stop", "rm"])
            builder.teardown_bootstrap(fake, identity())
            self.assertEqual(len(fake.calls), 2)
            fake.data = inspected(root)
            fake.residue = True
            with self.assertRaisesRegex(RuntimeError, "residue"):
                builder.teardown_bootstrap(fake, identity())
            fake.data["Config"]["Labels"][builder.OWNER] = "unrelated"
            calls = list(fake.calls)
            with self.assertRaises(ValueError):
                builder.teardown_bootstrap(fake, identity())
            self.assertEqual(fake.calls, calls)

    def test_finish_preserves_original_error_and_reports_export_cleanup_residue(self):
        with scratch_home() as directory:
            outcome = {"error": "original build failed"}
            with patch.object(builder, "export_bootstrap", side_effect=OSError("export")), \
                    patch.object(builder, "teardown_bootstrap", side_effect=RuntimeError("residue")):
                builder.finish_build(object(), Path(directory), identity(), outcome)
            self.assertEqual(outcome["error"], "original build failed")
            self.assertIn("export", outcome["export_error"])
            self.assertIn("residue", outcome["cleanup_error"])
            self.assertFalse(outcome.get("cleanup_verified", False))

    def test_actual_synthetic_bootstrap_sequence_success_failure_interrupt_and_durable_identity(self):
        for failure in (None, "start", "interrupt", "commit"):
            with self.subTest(failure=failure), scratch_home() as directory:
                parent = Path(directory)
                root = parent / "scratch" / "atlas-docker"
                root.mkdir(parents=True)
                registry = parent / ".hermes" / "network-atlas" / "docker-acceptance"
                value = plan()
                fake = FakeBuilderDocker(root / "context", value, failure)
                with patch.object(harness, "base_context", side_effect=lambda *_args: make_context(root / "context")), \
                        patch.object(builder.shutil, "disk_usage", return_value=SimpleNamespace(free=4 * 1024 ** 3)), \
                        patch.object(builder, "registry_path", side_effect=lambda p, s: builder._registry_identity(p, s, registry)), \
                        patch.object(builder, "require_execution_ready"):
                    result = builder.build_owned(fake, root, parent / "source", value, registry, foreground=True)
                self.assertTrue(result["cleanup_verified"], result)
                self.assertTrue(result["unrelated_preserved"], result)
                self.assertIsNone(fake.data)
                self.assertTrue((registry / "bootstrap.json").is_file())
                self.assertFalse(any(row[0] in {"build", "rmi", "prune", "exec", "run"} for row in fake.calls))
                if failure is None:
                    self.assertNotIn("error", result)
                    record = json.loads((registry / "base.json").read_text())
                    self.assertEqual(record["image"], "sha256:" + "2" * 64)
                    self.assertEqual(record["consumers"], [])
                    self.assertEqual(record["dependency_inventory"]["plan_sha256"], fake.identity.plan_hash)
                    operations = [row[0] for row in fake.calls]
                    self.assertLess(operations.index("start"), operations.index("commit"))
                    self.assertLess(operations.index("cp"), operations.index("commit"))
                    self.assertLess(operations.index("commit"), operations.index("rm"))
                else:
                    self.assertIn("error", result)
                    self.assertFalse((registry / "base.json").exists())

    def test_daemon_drift_before_every_mutation_and_clean_environment_no_buildkit(self):
        identity_value = identity()
        fake = harness.Docker.__new__(harness.Docker)
        fake.prefix = ["docker", "--host", "unix:///var/run/docker.sock"]
        fake.daemon = identity_value.daemon
        for operation in ("pull", "create", "start", "stop", "commit", "rm"):
            with patch.object(harness, "command", return_value=json.dumps({"ID": "other"}).encode()) as command:
                with self.assertRaises(ValueError):
                    fake.run([operation, "synthetic"])
                self.assertEqual(command.call_count, 1)
        self.assertEqual(set(harness.docker_environment()), {"PATH", "LANG"})

    def test_base_drift_wrong_user_rootfs_daemon_and_unrelated_resources_never_remove(self):
        ident = identity()
        data = {"Id": "sha256:" + "2" * 64, "Size": 123,
                "Config": {"Labels": dict(ident.labels(), **{"org.network-atlas.acceptance.kind": "base"}),
                           "User": "1000:1000", "WorkingDir": "/work", "Cmd": [], "Entrypoint": [], "Volumes": None},
                "RootFS": {"Layers": ["sha256:" + "b" * 64, "sha256:" + "3" * 64]}}
        record = builder.verify_final_image(data, ident)
        harness.validate_base(data, record, ident.daemon)
        for key, bad in (("User", "0:0"), ("Volumes", {"/state": {}}), ("Entrypoint", ["unsafe"]),
                         ("Labels", {})):
            mutated = copy.deepcopy(data)
            mutated["Config"][key] = bad
            with self.assertRaises(ValueError):
                builder.verify_final_image(mutated, ident)
        with self.assertRaises(ValueError):
            harness.validate_base(data, record, "other-daemon")

    def test_durable_consumers_retained_and_cap_exhaustion_no_auto_deletion(self):
        with scratch_home() as directory:
            root = Path(directory)
            ident = harness.Identity("a" * 40, "b" * 40, "sha256:" + "c" * 64, "daemon-fixture")
            evidence.BoundedDirectory(root).json("base.json", {"image": ident.image, "daemon": ident.daemon, "consumers": []})
            for number in range(8):
                builder.register_consumer(root, ident, root / str(number), "active")
            builder.register_consumer(root, ident, root / "0", "retained-awaiting-review")
            before = (root / "base.json").read_bytes()
            with self.assertRaises(ValueError):
                builder.register_consumer(root, ident, root / "ninth", "active")
            self.assertEqual((root / "base.json").read_bytes(), before)
            self.assertEqual(len(json.loads(before)["consumers"]), 8)


def make_context(path):
    path.mkdir(mode=0o700)
    return "e" * 64


class FakeBuilderDocker:
    """Synthetic in-memory daemon; no socket/subprocess/native admission path."""
    daemon = "daemon-fixture"
    def __init__(self, context, value, failure):
        self.context, self.plan, self.failure = context, value, failure
        self.data, self.identity, self.calls = None, None, []
        self.images = {"sha256:" + "9" * 64}

    def inspect(self, *_args, **_kw):
        return self.data

    def json(self, args):
        if args[-1] == self.plan["upstream_image"]:
            return [{"Id": self.plan["upstream_image"], "Architecture": "amd64", "Os": "linux", "Config": {},
                     "RootFS": {"Layers": self.plan["rootfs_layers"]}, "RepoDigests": ["python@" + builder.UPSTREAM_DIGEST]}]
        return [{"Id": "sha256:" + "2" * 64, "Size": 123,
                 "Config": {"User": "1000:1000", "WorkingDir": "/work", "Cmd": [], "Entrypoint": [],
                            "Labels": dict(self.identity.labels(), **{"org.network-atlas.acceptance.kind": "base"})},
                 "RootFS": {"Layers": [*self.plan["rootfs_layers"], "sha256:" + "3" * 64]}}]

    def run(self, args, **_kw):
        self.calls.append(args)
        operation = args[0]
        if operation == self.failure:
            raise TimeoutError("intentional synthetic " + operation)
        if operation == "pull":
            self.images.add(self.plan["upstream_image"])
        if operation == "image" and args[1] == "ls" and "--filter" not in args:
            return ("\n".join(sorted(self.images)) + "\n").encode()
        if operation == "create":
            labels = dict(value.split("=", 1) for index, value in enumerate(args) if index and args[index - 1] == "--label")
            self.identity = builder.BootstrapIdentity(labels[builder.BASE_LABEL], self.daemon,
                self.plan["upstream_image"], labels["org.network-atlas.acceptance.plan"])
            self.data = inspected(self.context)
            self.data["Image"] = self.identity.image
            self.data["Config"]["Labels"] = self.identity.labels()
        if operation == "start":
            if self.failure == "interrupt":
                self.data["State"].update(Running=True, Status="running")
                raise KeyboardInterrupt("synthetic cancellation")
            self.data["State"].update(Running=False, Status="exited")
        if operation == "stop":
            self.data["State"].update(Running=False, Status="exited")
        if operation == "rm":
            self.data = None
        if operation == "commit":
            self.images.add("sha256:" + "2" * 64)
            return ("sha256:" + "2" * 64 + "\n").encode()
        if operation == "cp":
            payload = evidence.json_bytes({"plan_sha256": self.identity.plan_hash, "inputs": {}})
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as bundle:
                member = tarfile.TarInfo("inventory.json")
                member.size = len(payload)
                bundle.addfile(member, io.BytesIO(payload))
            return buffer.getvalue()
        return b""


class EvidenceWriteTests(unittest.TestCase):
    def test_exact_serialization_overwrite_transient_count_and_aggregate_before_write(self):
        with scratch_home() as directory:
            root = Path(directory)
            budget = evidence.BoundedDirectory(root, total=100, per_file=80, count=2)
            budget.json("receipt.json", {"a": "b"})
            self.assertEqual((root / "receipt.json").read_bytes(), evidence.json_bytes({"a": "b"}))
            budget.write("log", b"x" * 50)
            before = (root / "receipt.json").read_bytes()
            with self.assertRaises(ValueError):
                budget.write("receipt.json", b"x" * 60)
            self.assertEqual((root / "receipt.json").read_bytes(), before)
            with self.assertRaises(ValueError):
                budget.write("third", b"x")
            self.assertFalse((root / "third").exists())
            for name in ("../escape", "/absolute", "sub/file"):
                with self.assertRaises(ValueError):
                    budget.write(name, b"x")

    def test_copy_symlink_member_file_bounds_and_archive_padding_before_allocation(self):
        with scratch_home() as directory:
            root = Path(directory)
            export = root / "export"
            export.mkdir()
            source = root / "source"
            source.write_bytes(b"x" * 81)
            budget = evidence.BoundedDirectory(export, total=100, per_file=80, count=2)
            with self.assertRaises(ValueError):
                budget.copy(source, "receipt")
            self.assertEqual(list(export.iterdir()), [])
            source.write_bytes(b"{}")
            link = root / "link"
            link.symlink_to(source)
            with self.assertRaises((ValueError, OSError)):
                budget.copy(link, "receipt")
            budget.copy(source, "receipt")
            with self.assertRaisesRegex(ValueError, "archive"):
                evidence.archive_directory(export, limit=100)
            data = evidence.archive_directory(export)
            with tarfile.open(fileobj=io.BytesIO(data)) as bundle:
                self.assertEqual(bundle.getnames(), ["receipt"])

    def test_sqlite_consistent_backup_preflight_limit_and_no_partial_export(self):
        with scratch_home() as directory:
            root = Path(directory)
            source = root / "source.sqlite3"
            with sqlite3.connect(source) as db:
                db.execute("CREATE TABLE facts(value TEXT)")
                db.execute("INSERT INTO facts VALUES ('synthetic')")
            export = root / "export"
            export.mkdir()
            small = evidence.BoundedDirectory(export, total=100, per_file=80)
            with self.assertRaises(ValueError):
                small.sqlite_backup(source, "atlas.sqlite3")
            self.assertEqual(list(export.iterdir()), [])
            budget = evidence.BoundedDirectory(export)
            budget.sqlite_backup(source, "atlas.sqlite3")
            with sqlite3.connect(export / "atlas.sqlite3") as db:
                self.assertEqual(db.execute("SELECT value FROM facts").fetchall(), [("synthetic",)])

    def test_usage_rejects_unexpected_directory_symlink_and_preserves_original_on_error(self):
        with scratch_home() as directory:
            root = Path(directory)
            budget = evidence.BoundedDirectory(root)
            (root / "link").symlink_to(root / "absent")
            with self.assertRaises(ValueError):
                budget.write("result.json", b"{}")
            self.assertFalse((root / "result.json").exists())


class AcquisitionAndColdTests(unittest.TestCase):
    def test_public_core_git_reconstruction_complete_tree_commit_no_host_git_or_native_setup(self):
        with scratch_home() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "public.txt").write_text("public fixture\n")
            harness.command(["git", "-C", str(source), "init", "--quiet"])
            harness.command(["git", "-C", str(source), "add", "--all"])
            tree = harness.command(["git", "-C", str(source), "write-tree"]).decode().strip()
            commit = root / "public.commit"
            commit.write_text(f"tree {tree}\nauthor Fixture <fixture@example.invalid> 0 +0000\n"
                              "committer Fixture <fixture@example.invalid> 0 +0000\n\npublic fixture\n")
            sha = harness.command(["git", "-C", str(source), "hash-object", "-t", "commit", "-w", str(commit)]).decode().strip()
            archive = harness.command(["git", "-C", str(source), "archive", sha])
            destination = root / "core"
            destination.mkdir()
            with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
                bundle.extractall(destination, filter="data")
            self.assertFalse((destination / ".git").exists())
            git_clean_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
            with patch.dict(os.environ, git_clean_env, clear=True):
                acquisition.reconstruct_public_core(destination, commit, sha, tree)
            self.assertEqual(harness.command(["git", "-C", str(destination), "rev-parse", "HEAD"]).decode().strip(), sha)
            self.assertEqual((destination / ".git" / "shallow").read_text(), sha + "\n")
            with self.assertRaises(ValueError):
                acquisition.reconstruct_public_core(destination, commit, sha, tree)
            wrong = root / "wrong"
            wrong.mkdir()
            (wrong / "different.txt").write_text("mismatch\n")
            with patch.dict(os.environ, git_clean_env, clear=True), self.assertRaisesRegex(ValueError, "tree mismatch"):
                acquisition.reconstruct_public_core(wrong, commit, sha, tree)

    def test_exact_download_prewrite_length_hash_deadline_and_redirect_no_network(self):
        payload = b"synthetic-public"
        item = {"url": "https://files.pythonhosted.org/fixture.whl", "filename": "fixture.whl",
                "compressed_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        class Response(io.BytesIO):
            status = 200
            headers = {"Content-Length": str(len(payload))}
            def geturl(self):
                return item["url"]
        with scratch_home() as directory:
            root = Path(directory)
            fake = SimpleNamespace(open=lambda *_args, **_kw: Response(payload))
            value = acquisition.finite_download(item, root, opener=fake, deadline=float("inf"))
            self.assertEqual(value.read_bytes(), payload)
            for content, change, deadline in ((payload, {"sha256": "0" * 64}, float("inf")),
                                              (payload + b"x", {}, float("inf")), (payload, {}, 0)):
                value.unlink(missing_ok=True)
                mutated = dict(item, **change)
                fake.open = lambda *_args, **_kw: Response(content)
                with self.assertRaises((ValueError, TimeoutError)):
                    acquisition.finite_download(mutated, root, opener=fake, deadline=deadline)
                self.assertFalse(value.exists())
            for url in ("http://files.pythonhosted.org/x", "https://127.0.0.1/x", "https://user:password@github.com/x"):
                with self.assertRaises(ValueError):
                    acquisition.public_url(url)

    def test_archive_expansion_members_traversal_and_unknown_format_refuse_before_unpack(self):
        with scratch_home() as directory:
            root = Path(directory)
            path = root / "fixture.tar"
            limits = {"unpacked_bytes": 100, "members": 2, "category": "pm-tool"}
            with tarfile.open(path, mode="w") as bundle:
                member = tarfile.TarInfo("public.txt")
                member.size = 3
                bundle.addfile(member, io.BytesIO(b"abc"))
            self.assertEqual(acquisition.archive_bounds(path, limits), {"members": 1, "bytes": 3})
            with self.assertRaises(ValueError):
                acquisition.archive_bounds(path, dict(limits, unpacked_bytes=2))
            with tarfile.open(path, mode="w") as bundle:
                member = tarfile.TarInfo("link")
                member.type = tarfile.SYMTYPE
                member.linkname = "../../escape"
                bundle.addfile(member)
            with self.assertRaises(ValueError):
                acquisition.archive_bounds(path, limits)
            path.write_bytes(b"not-an-archive")
            with self.assertRaises(ValueError):
                acquisition.archive_bounds(path, limits)

    def test_debian_archive_control_data_counts_and_index_expansion_are_bounded(self):
        import lzma
        with scratch_home() as directory:
            root = Path(directory)
            contents = []
            for name in ("control.tar", "data.tar"):
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode="w") as bundle:
                    member = tarfile.TarInfo("file")
                    member.size = 3
                    bundle.addfile(member, io.BytesIO(b"abc"))
                data = buffer.getvalue()
                header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n".encode()
                contents.append(header + data + (b"\n" if len(data) % 2 else b""))
            path = root / "fixture.deb"
            payload = b"!<arch>\n" + b"".join(contents)
            path.write_bytes(payload)
            item = {"compressed_bytes": len(payload), "unpacked_bytes": 6, "members": 2, "category": "apt-package"}
            self.assertEqual(acquisition.archive_bounds(path, item)["bytes"], 6)
            with self.assertRaises(ValueError):
                acquisition.archive_bounds(path, dict(item, unpacked_bytes=5))
            path = root / "Packages.xz"
            path.write_bytes(lzma.compress(b"abcd"))
            with self.assertRaises(ValueError):
                acquisition.archive_bounds(path, {"category": "apt-index", "unpacked_bytes": 3})

    def test_actual_setup_child_bounded_output_failure_deadline_and_owned_reaping(self):
        self.assertEqual(acquisition.bounded_run(["/usr/bin/true"], ROOT), "")
        with self.assertRaises(RuntimeError):
            acquisition.bounded_run(["/usr/bin/false"], ROOT)
        with scratch_home() as directory:
            child = Path(directory) / "child.py"
            child.write_text("print('x' * 1000)\n")
            with self.assertRaises(ValueError):
                acquisition.bounded_run([sys.executable, str(child)], ROOT, limit=10)
            child.write_text("import time\ntime.sleep(10)\n")
            with self.assertRaises(TimeoutError):
                acquisition.bounded_run([sys.executable, str(child)], ROOT, timeout=0.1)

    def test_cold_selection_generation_prefix_config_and_installed_tree_refuse_in_optimized_mode(self):
        with scratch_home() as directory:
            root = Path(directory)
            generation = root / "environments" / "fresh" / "venv"
            generation.mkdir(parents=True)
            source = root / "source"
            source.mkdir()
            facts = root / "facts.json"
            receipt = {"native_generation": str(generation), "native_facts": str(facts), "plugin": str(root / "plugin"),
                       "installed_commit": "a" * 40, "candidate_tree": "b" * 40}
            pm = SimpleNamespace(committed_venv=lambda _source: generation, runtime_facts_path=lambda _source: facts,
                                 venv_python=lambda _path: generation / "bin" / "python")
            config = SimpleNamespace(load_config_readonly=lambda: {"plugins": {"enabled": ["network-atlas"]}})
            with patch.dict(sys.modules, {"pm.environments": pm, "hermes_cli.config": config}), \
                    patch.object(sys, "prefix", str(generation)), patch.object(sys, "executable", str(generation / "bin" / "python")), \
                    patch.object(cold, "git_head", return_value="a" * 40), patch.object(cold, "git_tree", return_value="b" * 40):
                cold.check_selection(root, receipt, source)
                with patch.object(sys, "prefix", str(root / "old-generation")), self.assertRaises(ValueError):
                    cold.check_selection(root, receipt, source)
                config.load_config_readonly = lambda: {"plugins": {"enabled": []}}
                with self.assertRaises(ValueError):
                    cold.check_selection(root, receipt, source)
            with self.assertRaises(ValueError):
                cold.consume(root, "latest")

    def test_cold_proof_missing_image_or_generation_fails_host_outcome_validation(self):
        with scratch_home() as directory:
            root = Path(directory)
            export = root / "export"
            export.mkdir()
            ident = harness.Identity("a" * 40, "b" * 40, "sha256:" + "c" * 64, "daemon-fixture")
            budget = evidence.BoundedDirectory(export)
            budget.json("result.json", {"native_acceptance": True, "tests": 1})
            budget.json("admission.json", {"candidate_commit": ident.commit, "candidate_tree": ident.tree,
                                         "installed_tree": ident.tree, "enabled": True, "native_generation": "fresh"})
            budget.json("cold.json", {"candidate_commit": ident.commit, "candidate_tree": ident.tree,
                                    "native_generation": "fresh", "image": "sha256:" + "d" * 64,
                                    "cold_native_selection": True, "collected": False})
            with self.assertRaisesRegex(ValueError, "cold"):
                harness.exported_outcome(root, "accept", ident, 0)

    def test_native_export_failure_preserves_original_without_fabricated_evidence(self):
        with patch.object(sys, "argv", ["docker_inside.py", "smoke"]), \
                patch.object(inside, "write_json"), patch.object(inside, "git_head", return_value="a" * 40), \
                patch.object(inside, "git_tree", return_value="b" * 40), \
                patch.object(inside, "prepare", side_effect=RuntimeError("original native failure")), \
                patch.object(inside, "export_native", side_effect=OSError("export failure")):
            with self.assertRaisesRegex(RuntimeError, "original native failure") as value:
                inside.main()
            self.assertIn("native evidence export failed: OSError", value.exception.__notes__)

    def test_real_count_parser_includes_standalone_native_statuses_not_constants(self):
        text = ("Canonical verification: 2 tests discovered; synthetic\n"
                "test_one (suite.One.test_one) ... native stdout\nok\n"
                "test_two (suite.Two.test_two) ... FAIL\nRan 2 tests in 0.5s\nFAILED (failures=1)\n")
        result = test_result_report.report(text, 1)
        self.assertEqual(result["tests"], 2)
        self.assertEqual(result["status_counts"], {"ok": 1, "FAIL": 1})
        for log, code in ((text, 0), (text.replace("Ran 2", "Ran 3"), 1), (text.replace("\nok\n", "\n"), 1)):
            with self.assertRaises(ValueError):
                test_result_report.report(log, code)


if __name__ == "__main__":
    unittest.main()
