#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run bootstrap, implemented behavior/review regressions, and native-runtime smoke.

Requires a compatible Hermes runtime, an existing TMPDIR, and a candidate-bound
NETWORK_ATLAS_ACCEPTANCE_FIXTURE prepared OUTSIDE this network-denied process.
Missing prerequisites are failures, not skipped integration coverage.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
import unittest

from offline_guard import deny_network

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_FILES = ("__init__.py", "config.py", "schemas.py", "updates.py", "tools.py", "commands.py",
                "storage.py", "facts.py", "identity.py", "core.py", "query.py", "batches.py", "render.py",
                "probes.py", "discovery_parse.py", "discovery.py", "reconcile.py", "inspection.py",
                "inspection_parse.py", "inspection_evidence.py", "ssh_identity.py", "unresolved.py", "host_discovery.py",
                "host_transport.py", "host_schedule.py")

REQUIRED_CHUNK_TESTS = {
    "test_discovery_chunks.ChunkDiscoveryTests.test_sparse_24_startup_budget_reaches_last_address_and_reconciles_exact_batch",
    "test_discovery_chunks.ChunkDiscoveryTests.test_mid_chunk_deadline_keeps_earlier_positive_and_marks_tail_not_started",
    "test_discovery_chunks.ChunkParserTests.test_hostile_duplicate_out_of_chunk_stats_and_output_bounds",
    "test_status_remediation.StatusBatchBoundsTests.test_legacy_per_address_24_and_25_totals_remain_readable_after_restart",
    "test_unresolved.UnresolvedEvidenceTests.test_chunk_evidence_partial_not_started_and_complete_bounded_pages",
    "test_unresolved.UnresolvedEvidenceTests.test_partial_chunk_original_later_lineage_and_foreign_visibility",
    "test_unresolved.UnresolvedEvidenceTests.test_malformed_stored_receipt_entries_fail_in_public_error_envelope",
}

REQUIRED_HOST_DISCOVERY_TESTS = {
    "test_documentation.DocumentationTests.test_host_operator_contract_and_required_canonical_coverage",
    "test_host_acceptance.CumulativeHostTests.test_every_method_uses_combined_budget_at_each_concurrency",
    "test_host_acceptance.CumulativeHostTests.test_sparse_late_range_each_method_and_all_filtered_control",
    "test_host_acceptance.CumulativeHostTests.test_sensitive_destinations_excluded_without_socket_or_helper",
    "test_host_acceptance.CumulativeHostTests.test_hostile_echo_fields_and_bytes_never_qualify_response",
    "test_host_acceptance.CumulativeHostTests.test_shared_receive_exhaustion_retains_other_method_evidence",
    "test_host_acceptance.CumulativeHostTests.test_deadline_after_open_before_send_and_unregister_failure_cleanup",
    "test_host_acceptance.CumulativeHostTests.test_legacy_and_new_exact_lineage_shared_read_without_apply_authority",
    "test_host_transport.HostTransportTests.test_icmp_golden_header_and_hostile_reply_validation",
    "test_host_transport.HostTransportTests.test_combined_probe_bound_before_capability_or_transport",
    "test_host_transport.HostTransportTests.test_native_fixture_assertions_through_ordinary_local_public_handlers",
    "test_acceptance.CumulativeAcceptanceTests.test_supported_admission_three_aliases_and_fresh_process_without_collection",
    "test_commands.OperatorStatusTests.test_cli_invalid_policy_refusal_has_explicit_no_effects_receipt",
    "test_host_discovery_policy.HostDiscoveryPolicyTests.test_legacy_defaults_and_explicit_defaults_preserve_exact_transport",
    "test_host_discovery_policy.HostDiscoveryPolicyTests.test_strict_enablement_port_types_bounds_duplicates_cap_and_exclusion",
    "test_host_discovery_policy.HostDiscoveryPolicyTests.test_method_dependencies_ipv6_scope_and_unknown_authority_fail_closed",
    "test_host_discovery_policy.HostDiscoveryPolicyTests.test_combined_bounds_refuse_before_any_effect_and_report_on_public_routes",
    "test_host_discovery_policy.ICMPCapabilityTests.test_disabled_expired_unsupported_are_packet_free_no_open",
    "test_host_discovery_policy.ICMPCapabilityTests.test_open_success_only_unverified_and_socket_closed_no_packet_operations",
    "test_host_discovery_policy.ICMPCapabilityTests.test_permission_protocol_resource_failures_are_bounded_no_retry_or_helper",
    "test_host_transport.HostTransportTests.test_icmp_only_positive_survives_filtered_web_and_retains_times",
    "test_host_transport.HostTransportTests.test_tcp_2222_and_optional_22000_only_positives",
    "test_host_transport.HostTransportTests.test_mixed_duplicates_retained_address_counts_deduplicated_after_restart",
    "test_host_transport.HostTransportTests.test_denied_missing_icmp_does_not_suppress_tcp_and_no_fallback",
    "test_host_transport.HostTransportTests.test_all_filtered_timeouts_not_offline_or_packets_for_unstarted",
    "test_host_transport.HostTransportTests.test_scope_and_4403_caller_forgery_refuse_before_transport",
    "test_host_transport.HostTransportTests.test_round_robin_late_range_rate_concurrency_and_single_host_deadline",
    "test_host_transport.HostTransportTests.test_output_limit_is_shared_across_methods_owned_sockets_close",
    "test_host_transport.HostTransportTests.test_interruption_selector_failure_and_expired_before_send_close_only_owned",
    "test_host_transport.HostTransportTests.test_persistence_failure_retains_history_and_output_receipt_rolls_back",
    "test_host_transport.HostTransportTests.test_original_later_lineage_and_foreign_methods_do_not_transfer_authority",
    "test_host_transport.HostTransportTests.test_runtime_method_failure_preserves_other_method_positive",
    "test_host_transport.HostTransportTests.test_host_budget_is_not_renewed_per_method_or_port",
    "test_host_transport.HostTransportTests.test_completed_scheduler_returns_without_idle_operation_wait",
    "test_host_transport.HostTransportTests.test_tcp_refusal_is_response_only_after_connect_not_socket_setup",
}

REQUIRED_CONFIRMATION_TESTS = {
    "test_caution_confirmation.CautionConfirmationTests.test_native_caution_in_ci_non_tty_refuses_without_approval",
    "test_caution_confirmation.CautionConfirmationTests.test_missing_or_candidate_controlled_authority_refuses",
    "test_caution_confirmation.CautionConfirmationTests.test_exact_commit_tree_scope_scanner_findings_and_signature_mismatches_refuse",
    "test_caution_confirmation.CautionConfirmationTests.test_genuinely_dangerous_full_tree_refuses_even_signed_approval",
    "test_caution_confirmation.CautionConfirmationTests.test_signed_request_cannot_confirm_changed_candidate_or_core",
    "test_caution_confirmation.CautionConfirmationTests.test_synthetic_signed_caution_reaches_ordinary_native_prompt_with_network_denied_pm",
    "test_caution_confirmation.CautionConfirmationTests.test_synthetic_verified_child_prompt_transport_answers_once_and_exits",
    "test_caution_confirmation.CautionConfirmationTests.test_prompt_transport_without_matching_marker_or_with_bounds_never_confirms",
}

REQUIRED_CI_ADMISSION_TESTS = {
    "test_ci_admission.HostedCIAdmissionTests.test_explicit_mode_and_matching_diagnostics_required",
    "test_ci_admission.HostedCIAdmissionTests.test_main_feature_push_and_pr_merge_refs_match_workflow",
    "test_ci_admission.HostedCIAdmissionTests.test_other_events_branches_tags_and_nonmerge_pr_refs_refuse",
    "test_ci_admission.HostedCIAdmissionTests.test_fresh_marked_contained_fixture_no_replacement",
    "test_ci_admission.HostedCIAdmissionTests.test_native_full_scan_caution_selects_supported_force_without_install",
    "test_ci_admission.HostedCIAdmissionTests.test_native_dangerous_refuses_even_force_and_never_calls_installer",
    "test_ci_admission.HostedCIAdmissionTests.test_safe_does_not_select_force_and_candidate_or_core_drift_refuses",
    "test_ci_admission.HostedCIAdmissionTests.test_reviewed_workflow_hosted_readonly_pins_no_secrets_or_privileged_event",
    "test_ci_admission.HostedCIAdmissionTests.test_workflow_runner_context_scratch_initialized_at_step_then_persisted",
    "test_ci_admission.HostedCIAdmissionTests.test_real_entrypoints_refuse_local_ci_mode_mixed_consent_and_enable",
    "test_ci_admission.HostedCIAdmissionTests.test_install_boundary_rechecks_context_origin_ref_and_modified_scan_policy",
}


REQUIRED_DOCKER_TESTS = {
    "test_docker_acceptance.DockerContractTests.test_identity_labels_endpoint_and_optimized_refusal",
    "test_docker_acceptance.DockerContractTests.test_readonly_mounts_no_network_privileges_ports_or_ambient_env",
    "test_docker_acceptance.DockerContractTests.test_inspection_drift_rejects_wrong_labels_image_mounts_flags_network",
    "test_docker_acceptance.DockerContractTests.test_actual_counts_exit_zero_skips_missing_and_mismatch_refuse",
    "test_docker_acceptance.DockerContractTests.test_evidence_bounds_traversal_symlinks_export_failure_and_hashes",
    "test_docker_acceptance.DockerLifecycleTests.test_actual_bounded_command_pass_fail_deadline_output_and_owned_cleanup",
    "test_docker_acceptance.DockerLifecycleTests.test_active_lease_refuses_and_releases_without_suffix_retry",
    "test_docker_acceptance.DockerLifecycleTests.test_complete_shallow_snapshot_exact_public_commit_tree_no_host_git",
    "test_docker_acceptance.DockerLifecycleTests.test_teardown_duplicate_residue_wrong_identity_no_unrelated_remove",
    "test_docker_acceptance.DockerLifecycleTests.test_failed_export_keeps_original_failure_and_still_tears_down",
    "test_docker_acceptance.DockerLifecycleTests.test_unattended_accept_refuses_before_any_daemon_effect",
    "test_docker_acceptance.DockerLifecycleTests.test_containerd_and_unknown_build_backend_refuse_before_mutation",
    "test_docker_acceptance.DockerLifecycleTests.test_optimized_native_readback_mismatch_manifest_and_generation_refuse",
}
DOCKER_SOURCES = ("scripts/docker_acceptance.py", "scripts/docker_contract.py", "scripts/docker_inside.py", "docker/base_setup.py")


def check_docker_source() -> bool:
    valid = True
    for filename in DOCKER_SOURCES:
        tree = ast.parse((ROOT / filename).read_text(), filename=filename)
        compile(tree, filename, "exec")
        for function in (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)):
            score = 1
            for node in ast.walk(function):
                if isinstance(node, (ast.If, ast.For, ast.While, ast.IfExp, ast.ExceptHandler, ast.comprehension)):
                    score += 1
                if isinstance(node, ast.BoolOp):
                    score += len(node.values) - 1
            if score > 10:
                print(f"Complexity review: {filename}:{function.lineno} {function.name} estimate={score}")
            if score > 15:
                valid = False
    return valid


def test_ids(suite: unittest.TestSuite) -> set[str]:
    """Require critical issue regressions in discovery, not just a nonzero count."""
    result = set()
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            result.update(test_ids(item))
        else:
            result.add(item.id())
    return result


def check_source() -> bool:
    """Compile plugin sources and report a conservative AST branch estimate.

    This is a local review signal, not an exact McCabe metric. Count conditions,
    handlers, boolean alternatives, and comprehensions; require refactoring
    above 15 rather than quietly waiving the repository's review threshold.
    """
    valid = True
    maximum = 0
    actual = {path.name for path in ROOT.glob("*.py")}
    if actual != set(PLUGIN_FILES):
        print(f"ERROR: undeclared/absent plugin modules: {actual ^ set(PLUGIN_FILES)}")
        valid = False
    for path in (ROOT / "scripts").glob("*.py"):
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
    for filename in PLUGIN_FILES:
        path = ROOT / filename
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=filename)
        compile(tree, filename, "exec")
        for function in (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)):
            score = 1
            for node in ast.walk(function):
                if isinstance(node, (ast.If, ast.For, ast.While, ast.IfExp, ast.ExceptHandler, ast.comprehension)):
                    score += 1
                if isinstance(node, ast.BoolOp):
                    score += len(node.values) - 1
            maximum = max(maximum, score)
            if score > 10:
                print(f"Complexity review: {filename}:{function.lineno} {function.name} estimate={score}")
            if score > 15:
                valid = False
    print(f"Plugin source check: maximum conservative branch estimate={maximum}", flush=True)
    return valid


def main() -> int:
    """Run discovered tests and refuse a misleading zero-test success."""
    os.chdir(ROOT)
    deny_network()
    if not check_source() or not check_docker_source():
        print("ERROR: refactor function(s) estimated above 15 before review")
        return 1
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    count = suite.countTestCases()
    if count == 0:
        print("ERROR: no tests discovered")
        return 1
    missing = (REQUIRED_CHUNK_TESTS | REQUIRED_HOST_DISCOVERY_TESTS | REQUIRED_CONFIRMATION_TESTS
               | REQUIRED_CI_ADMISSION_TESTS | REQUIRED_DOCKER_TESTS) - test_ids(suite)
    if missing:
        print(f"ERROR: required discovery regression coverage absent: {sorted(missing)}")
        return 1
    print(f"Canonical verification: {count} tests discovered; cumulative synthetic V1, NOT live validation", flush=True)
    print(f"Required discovery regressions: {len(REQUIRED_CHUNK_TESTS)} chunk/legacy and "
          f"{len(REQUIRED_HOST_DISCOVERY_TESTS)} host/native and "
          f"{len(REQUIRED_CONFIRMATION_TESTS)} inert confirmation and "
          f"{len(REQUIRED_CI_ADMISSION_TESTS)} hosted CI policy and "
          f"{len(REQUIRED_DOCKER_TESTS)} Docker contract IDs present", flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
