# SPDX-License-Identifier: GPL-3.0-or-later
"""Metadata linkage and authority refusal, with tiny non-forwarding fixtures."""
import copy
import hashlib
import json
import os
from pathlib import Path
import pwd
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from helpers import ROOT, scratch_home
sys.path.insert(0, str(ROOT / "scripts"))
import docker_builder as builder
import docker_acceptance as harness
import acquisition_plan as linkage
import acquisition_support as acquisition
from docker_plan_fixture import doc, linked_plan


class PlanLinkageTests(unittest.TestCase):
    def setUp(self):
        self.value = linked_plan(builder)
        anchor = patch.object(builder, "UPSTREAM_DIGEST", self.value["upstream"])
        anchor.start()
        self.addCleanup(anchor.stop)

    def test_strict_nested_schema_missing_extra_duplicate_and_category_source_refuse(self):
        builder.validate_plan(self.value)
        changes = [("unexpected", True), ("closures", {"apt": True}), ("sources", {})]
        for key, bad in changes:
            value = copy.deepcopy(self.value)
            value[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                builder.validate_plan(value)
        for key, bad in (("extra", True), ("source", "pm"), ("record", "absent"), ("members", True)):
            value = copy.deepcopy(self.value)
            value["artifacts"][0][key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                builder.validate_plan(value)
        for key in ("oci", "pm", "apt", "verifier", "union", "core"):
            value = copy.deepcopy(self.value)
            value["sources"][key] = None
            with self.subTest(source=key), self.assertRaises(ValueError):
                builder.validate_plan(value)
        for rows in (self.value["artifacts"][:-1], self.value["artifacts"] + [self.value["artifacts"][0]]):
            with self.assertRaises(ValueError):
                builder.validate_plan(dict(self.value, artifacts=rows))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            text = '{"x":1,"x":2}'
            linkage.document({"text": text, "sha256": hashlib.sha256(text.encode()).hexdigest()})

    def test_outer_duplicate_keys_and_declared_budgets_never_become_proven_fit(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            linkage.parse_plan('{"schema":2,"schema":1}')
        with self.assertRaises(ValueError):
            linkage.parse_plan(b"x" * (1024 ** 2 + 1))
        result = builder.require_space(self.value, 10 * 1024 ** 3)
        self.assertTrue(result["planning_only"])
        self.assertFalse(result["fit_proven"])
        with self.assertRaisesRegex(ValueError, "live build disabled"):
            linkage.require_execution_ready()

    def test_oci_manifest_config_compressed_layer_and_ordered_diffid_linkage(self):
        for key, bad in (("upstream_image", "sha256:" + "0" * 64), ("rootfs_layers", ["sha256:" + "1" * 64])):
            with self.subTest(key=key), self.assertRaises(ValueError):
                builder.validate_plan(dict(self.value, **{key: bad}))
        for field in ("sha256", "compressed_bytes", "url", "category"):
            value = copy.deepcopy(self.value)
            item = next(row for row in value["artifacts"] if row["source"] == "oci")
            item[field] = {"sha256": "0" * 64, "compressed_bytes": 101, "url": "https://registry-1.docker.io/unrelated", "category": "pm-tool"}[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                builder.validate_plan(value)
        value = copy.deepcopy(self.value)
        value["sources"]["oci"]["config"]["text"] += " "
        with self.assertRaises(ValueError):
            builder.validate_plan(value)

    def test_each_closure_pin_edges_roots_and_exact_member_identity_refuse(self):
        for group in ("apt", "verifier", "union"):
            original = json.loads(self.value["sources"][group]["text"])
            for kind in ("pin", "root", "missing-edge", "extra-member", "identity"):
                value = copy.deepcopy(self.value)
                source = copy.deepcopy(original)
                first = source["roots"][0]
                if kind == "pin":
                    source["pin"] = "wrong"
                elif kind == "root":
                    source["roots"] = []
                elif kind == "missing-edge":
                    source["records"][first]["requires"] = ["missing"]
                elif kind == "extra-member":
                    source["records"]["unrelated"] = copy.deepcopy(source["records"][first])
                else:
                    source["records"][first]["sha256"] = "0" * 64
                value["sources"][group] = doc(source)
                with self.subTest(group=group, kind=kind), self.assertRaises(ValueError):
                    builder.validate_plan(value)
        for group in ("pm", "core"):
            value = copy.deepcopy(self.value)
            value["sources"][group]["commit"] = "0" * 40
            with self.assertRaises(ValueError):
                builder.validate_plan(value)
        bad = {"member": {"version": "2"}}
        with self.assertRaises(ValueError):
            linkage.check_requirements(bad, ["member>=1,<2"])

    def test_native_and_recipe_literal_metadata_bound_before_context_write(self):
        source = Path("/public-synthetic-core")
        records = self.value["sources"]
        payloads = [records["pm"]["lock"]["text"].encode(), b"synthetic uv.lock", records["dependencies"]["text"].encode()]
        records["uv_lock_sha256"] = hashlib.sha256(payloads[1]).hexdigest()
        with patch.object(harness, "command", side_effect=payloads):
            harness.validate_pinned_sources(source, self.value)
        for index in range(3):
            changed = list(payloads)
            changed[index] += b"changed"
            with patch.object(harness, "command", side_effect=changed), self.assertRaises(ValueError):
                harness.validate_pinned_sources(source, self.value)
        item = next(row for row in self.value["artifacts"] if row["source"] == "pm")
        item["version"] = "invented"
        with self.assertRaises(ValueError):
            builder.validate_plan(self.value)

    def test_live_build_and_acquire_remain_disabled_even_linked_metadata_no_effect(self):
        calls = []
        fake = SimpleNamespace(run=lambda *_args, **_kw: calls.append("daemon"))
        registry = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".hermes/network-atlas/docker-acceptance"
        with patch.object(builder.shutil, "disk_usage", return_value=SimpleNamespace(free=10 * 1024 ** 3)), \
                self.assertRaisesRegex(ValueError, "live build disabled"):
            builder.build_owned(fake, Path("/unused"), Path("/unused"), self.value, registry, foreground=True)
        with patch.object(acquisition, "finite_download") as download, self.assertRaisesRegex(ValueError, "live build disabled"):
            acquisition.acquire(Path("/unused"), Path("/unused"), self.value)
        download.assert_not_called()
        with patch.object(sys, "argv", ["docker_acceptance.py", "build", "--daemon", "synthetic", "--registry", str(registry)]), \
                patch.object(harness, "private_root") as root, patch.object(harness, "Docker") as docker, \
                self.assertRaisesRegex(ValueError, "live build disabled"):
            harness.main()
        root.assert_not_called()
        docker.assert_not_called()
        self.assertEqual(calls, [])

    def test_cli_bad_plan_or_wrong_registry_refuses_before_resource_and_daemon(self):
        expected = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".hermes/network-atlas/docker-acceptance"
        for registry in (expected, Path("/unrelated/.hermes/network-atlas/docker-acceptance")):
            with patch.object(sys, "argv", ["docker_acceptance.py", "preflight", "--daemon", "synthetic", "--registry", str(registry), "--plan", "/unused"]), \
                    patch.object(harness, "clean_checkout"), patch.object(harness, "regular_read", return_value=b'{"schema":1,"status":"resolved"}'), \
                    patch.object(harness, "private_root") as root, patch.object(harness, "Docker") as docker, self.assertRaises(ValueError):
                harness.main()
            root.assert_not_called()
            docker.assert_not_called()

    def test_registry_account_identity_ignores_ambient_home_no_writes(self):
        expected = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".hermes/network-atlas/docker-acceptance"
        with patch.dict(os.environ, {"HOME": "/unrelated", "HERMES_HOME": "/unrelated-profile"}):
            self.assertEqual(builder.registry_path(expected, Path(os.environ["TMPDIR"])), expected)
        with scratch_home() as directory:
            temporary = Path(directory) / ".hermes/network-atlas/docker-acceptance"
            with self.assertRaises(ValueError):
                builder.registry_path(temporary, Path(directory) / "other")
            self.assertFalse(temporary.exists())

    def test_native_hash_cache_uses_literal_lock_and_tiny_verified_seed_without_install(self):
        # Exercise the actual pinned Store with a mocked downloader, not a copied
        # implementation or native installation. Tiny bytes are not public tools.
        core = Path(os.environ["NETWORK_ATLAS_HERMES_ROOT"])
        sys.path.insert(0, str(core))
        from pm.store import Store
        from pm import downloader, artifact_mirror
        with scratch_home() as directory:
            root = Path(directory)
            payload = b"tiny synthetic archive"
            digest = hashlib.sha256(payload).hexdigest()
            cache = root / "store" / ("fetch-" + digest)
            cache.mkdir(parents=True)
            archive = cache / "literal.tar.gz"
            archive.write_bytes(payload)
            scratch = root / "staging"
            scratch.mkdir()
            captured = []
            def pin(url, dest, sha256):
                captured.append((url, dest, sha256))
                return SimpleNamespace(url=url, dest=dest, sha256=sha256)
            class VerifyOnly:
                def __init__(self, sources, **_kw):
                    self.sources = sources
                def run(self, **_kw):
                    for value in self.sources:
                        if hashlib.sha256(value.dest.read_bytes()).hexdigest() != value.sha256:
                            raise ValueError("tiny cache hash mismatch")
            url = "https://github.com/fixture/releases/download/literal-version/literal.tar.gz"
            with patch.object(artifact_mirror, "pinned_source", side_effect=pin), patch.object(downloader, "Download", VerifyOnly):
                result = Store(root / "store").fetch_many([{"url": url, "sha256": digest}], scratch)
                self.assertEqual(result, [archive])
                self.assertEqual(captured, [(url, archive, digest)])
                archive.write_bytes(b"wrong")
                with self.assertRaises(ValueError):
                    Store(root / "store").fetch_many([{"url": url, "sha256": digest}], scratch)
        raw = (core / "pm/lock.json").read_bytes()
        self.assertNotIn(b"*", raw)
        native = json.loads(raw)
        resolved = linkage.pm_sources({"commit": builder.HERMES_COMMIT,
            "lock": {"text": raw.decode(), "sha256": hashlib.sha256(raw).hexdigest()}}, builder.HERMES_COMMIT)
        for name in ("python", "uv"):
            literal = native["packages"][name]["artifacts"]["linux-x64"]
            self.assertEqual(resolved[name]["version"], native["packages"][name]["version"])
            self.assertEqual(resolved[name]["url"], literal["url"])
            self.assertEqual(resolved[name]["sha256"], literal["sha256"])
            with scratch_home() as directory:
                root = Path(directory)
                target = root / "store" / ("fetch-" + literal["sha256"])
                target.mkdir(parents=True)
                archive = target / resolved[name]["filename"]
                archive.write_bytes(b"tiny deliberately WRONG native cache")
                staging = root / "staging"
                staging.mkdir()
                captured.clear()
                with patch.object(artifact_mirror, "pinned_source", side_effect=pin), patch.object(downloader, "Download", VerifyOnly), self.assertRaises(ValueError):
                    Store(root / "store").fetch_many([literal], staging)
                self.assertEqual(captured, [(literal["url"], archive, literal["sha256"])])
