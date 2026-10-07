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
    "test_docker_image_readback.ImageReadbackTests.test_each_safety_mismatch_names_precise_field_without_relaxation",
    "test_docker_image_readback.ImageReadbackTests.test_empty_commit_command_merge_is_source_hypothesis_not_hosted_proof",
    "test_docker_image_readback.ImageReadbackTests.test_actual_readback_journal_mismatch_and_compact_export_survive_refusal",
    "test_docker_image_readback.ImageReadbackTests.test_returned_identity_and_exact_upstream_layers_must_match",
    "test_docker_image_readback.ImageReadbackTests.test_readback_command_shape_bound_and_export_errors_never_fabricate_success",
    "test_docker_image_readback.ImageReadbackTests.test_unverified_image_cleanup_refuses_and_preserves_primary_on_export_failure",
    "test_docker_image_readback.ImageReadbackTests.test_hosted_failed_image_retains_proofs_and_never_registers_or_deletes_base",
    "test_docker_reconstruction.ReconstructionLogTests.test_budget_refuses_before_git_or_log_effects",
    "test_docker_reconstruction.ReconstructionLogTests.test_each_failed_git_stage_retains_real_child_evidence_in_export",
    "test_docker_reconstruction.ReconstructionLogTests.test_success_outputs_and_hosted_phases_share_existing_budget",
    "test_docker_reconstruction.ReconstructionLogTests.test_terminal_write_failure_preserves_real_primary_exit",
    "test_docker_reconstruction.ReconstructionLogTests.test_deadline_reaps_owned_child_and_preserves_terminal_audit",
    "test_docker_command_logs.CommandLogTests.test_near_limit_failed_child_traceback_and_actual_export_preserve_primary",
    "test_docker_command_logs.CommandLogTests.test_repeated_hostile_rows_reserve_terminal_before_spawn_under_aggregate_cap",
    "test_docker_command_logs.CommandLogTests.test_command_metadata_and_count_refuse_before_child_or_log_effects",
    "test_docker_command_logs.CommandLogTests.test_real_nonzero_command_survives_terminal_emission_error_without_output_chain",
    "test_docker_pm.NativePMContractTests.test_candidate_argv_passes_actual_parser_and_flag_predicate",
    "test_docker_pm.NativePMContractTests.test_predecessor_tools_only_names_refuse_before_dispatch",
    "test_docker_pm.NativePMContractTests.test_named_dispatch_keeps_exact_tools_and_never_syncs_or_defaults",
    "test_docker_pm.NativePMContractTests.test_bare_tools_only_closure_is_not_the_authenticated_seed",
    "test_docker_pm.NativePMContractTests.test_verifier_argv_matches_actual_build_parser_and_public_api",
    "test_docker_pm.NativePMContractTests.test_hosted_pm_api_signatures_and_member_encoding",
    "test_docker_pm.NativePMContractTests.test_real_command_success_failure_and_bounded_output_diagnostics",
    "test_docker_pm.NativePMContractTests.test_command_diagnostic_failure_never_replaces_primary_error",
    "test_docker_apt.AptProofTests.test_native_tool_hashes_captured_before_publication_removes_fetch_cache",
    "test_docker_apt.AptProofTests.test_native_fetch_tools_local_guard_precedes_import_and_files",
    "test_docker_apt.AptProofTests.test_normal_cache_cleanup_keeps_genuine_preinstall_hashes_and_base_versions",
    "test_docker_apt.AptProofTests.test_empty_index_and_archive_refuse_with_distinct_incremental_counts",
    "test_docker_apt.AptProofTests.test_index_archive_control_and_installed_drift_refuse_not_success",
    "test_docker_apt.AptProofTests.test_each_command_failure_retains_stage_output_exit_and_primary",
    "test_docker_apt.AptProofTests.test_already_installed_base_is_explicit_not_fabricated_archive_success",
    "test_docker_apt.AptProofTests.test_malformed_nonregular_empty_or_overbound_proof_refuses",
    "test_docker_apt.AptProofTests.test_actual_owned_command_failure_output_deadline_limit_and_resource_audit",
    "test_docker_apt.AptProofTests.test_diagnostic_write_failure_is_secondary_to_command_failure",
    "test_docker_apt.AptProofTests.test_failed_bootstrap_exports_diagnostics_without_success_inventory_and_compact_pack",
    "test_docker_bootstrap_repair.BootstrapRepairTests.test_hosted_build_success_crosschecks_process_proof_before_commit_and_owned_cleanup",
    "test_docker_bootstrap_repair.BootstrapRepairTests.test_standard_docker_capabilities_and_process_containment_golden_and_drift",
    "test_docker_bootstrap_repair.BootstrapRepairTests.test_real_setup_guard_requires_root_container_and_actual_status_before_effects",
    "test_docker_bootstrap_repair.BootstrapRepairTests.test_hosted_apt_permits_normal_authenticated_provisioning_not_script_bypass",
    "test_docker_bootstrap_repair.BootstrapRepairTests.test_complete_package_contract_refuses_before_controller_effects",
    "test_docker_bootstrap_repair.BootstrapRepairTests.test_setup_and_apt_refuse_before_filesystem_acquisition_or_pm",
    "test_docker_bootstrap_repair.BootstrapRepairTests.test_actual_controller_entrypoint_contract_gate_precedes_scratch_and_daemon",
    "test_docker_bootstrap_repair.BootstrapRepairTests.test_final_diagnostic_error_is_secondary_unless_no_primary",
    "test_docker_bootstrap_repair.BootstrapRepairTests.test_failed_export_preserves_stopped_logs_and_all_missing_members",
    "test_docker_bootstrap_repair.BootstrapRepairTests.test_success_requires_every_inventory_and_provenance_member",
    "test_docker_bootstrap_repair.BootstrapRepairTests.test_permission_archive_and_output_failures_are_not_missing",
    "test_docker_bootstrap_repair.BootstrapRepairTests.test_reinspection_ownership_drift_never_reads_logs_or_members",
    "test_docker_bootstrap_repair.BootstrapRepairTests.test_stopped_failure_is_primary_before_success_only_exports_or_commit",
    "test_docker_bootstrap_repair.BootstrapRepairTests.test_primary_failure_survives_secondary_cleanup_evidence_write",
    "test_docker_bootstrap_repair.BootstrapRepairTests.test_all_stopped_failure_kinds_refuse_before_rootfs_commit",
    "test_docker_builder.BuilderContractTests.test_bootstrap_command_requires_exact_uncompressed_bounded_local_logs",
    "test_docker_builder.BuilderContractTests.test_bootstrap_inspection_refuses_missing_compressed_extra_or_expanded_logs",
    "test_docker_builder.BuilderContractTests.test_bootstrap_stopped_error_survives_log_failure_and_owned_teardown",
    "test_docker_acceptance.DockerContractTests.test_acceptance_command_requires_exact_uncompressed_bounded_local_logs",
    "test_docker_acceptance.DockerContractTests.test_acceptance_inspection_refuses_missing_compressed_extra_or_expanded_logs",
    "test_docker_acceptance.DockerLifecycleTests.test_acceptance_stopped_error_survives_log_failure_and_owned_teardown",
    "test_hosted_docker.HostedDockerTests.test_real_legacy_prewarm_dispatch_refuses_before_pm_import_or_call",
    "test_hosted_docker.HostedDockerTests.test_explicit_hosted_initial_feature_context_and_local_refusal",
    "test_hosted_docker.HostedDockerTests.test_real_hosted_setup_dispatch_and_warm_refuse_before_pm",
    "test_hosted_docker.HostedDockerTests.test_real_prewarm_refusal_normal_and_optimized_children",
    "test_hosted_docker.HostedDockerTests.test_hosted_native_mode_scope_and_force_still_use_original_boundary",
    "test_hosted_docker.HostedDockerTests.test_hosted_runtime_exact_diagnostics_and_isolation_readback",
    "test_hosted_docker.HostedDockerTests.test_hosted_bootstrap_readback_and_commit_clear_attempt_diagnostics",
    "test_hosted_docker.HostedDockerTests.test_verified_public_wheel_index_hash_size_type_and_native_tools",
    "test_hosted_docker.HostedDockerTests.test_mocked_hosted_sequence_preserves_failure_no_retry_and_owned_cleanup",
    "test_hosted_docker.HostedDockerTests.test_compact_export_hashes_refuses_missing_symlink_and_no_context",
    "test_hosted_docker.HostedDockerTests.test_workflow_single_initial_vm_job_pins_permissions_and_step_context",
    "test_docker_plan.PlanLinkageTests.test_cli_bad_plan_or_wrong_registry_refuses_before_resource_and_daemon",
    "test_docker_plan.PlanLinkageTests.test_outer_duplicate_keys_and_declared_budgets_never_become_proven_fit",
    "test_docker_builder.BuilderContractTests.test_invented_plan_without_source_closure_refuses_before_effects",
    "test_docker_builder.BuilderContractTests.test_suffix_registry_wrong_home_profile_and_temporary_parent_refuse",
    "test_docker_plan.PlanLinkageTests.test_strict_nested_schema_missing_extra_duplicate_and_category_source_refuse",
    "test_docker_plan.PlanLinkageTests.test_oci_manifest_config_compressed_layer_and_ordered_diffid_linkage",
    "test_docker_plan.PlanLinkageTests.test_each_closure_pin_edges_roots_and_exact_member_identity_refuse",
    "test_docker_plan.PlanLinkageTests.test_native_and_recipe_literal_metadata_bound_before_context_write",
    "test_docker_plan.PlanLinkageTests.test_live_build_and_acquire_remain_disabled_even_linked_metadata_no_effect",
    "test_docker_plan.PlanLinkageTests.test_registry_account_identity_ignores_ambient_home_no_writes",
    "test_docker_plan.PlanLinkageTests.test_native_hash_cache_uses_literal_lock_and_tiny_verified_seed_without_install",
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
    "test_docker_builder.BuilderContractTests.test_complete_plan_identity_unknown_lengths_hashes_and_peak_reserve",
    "test_docker_builder.BuilderContractTests.test_bootstrap_root_is_private_bounded_public_readonly_not_candidate",
    "test_docker_builder.BuilderContractTests.test_commit_requires_stopped_exact_owned_rootfs_and_final_nonroot_labels",
    "test_docker_builder.BuilderContractTests.test_durable_registry_contract_not_scratch_symlink_or_ambient_profile",
    "test_docker_builder.BuilderContractTests.test_unapproved_or_incomplete_plan_never_reaches_daemon_or_native",
    "test_docker_builder.BuilderContractTests.test_owned_cleanup_duplicate_wrong_labels_and_residue_preserve_unrelated",
    "test_docker_builder.BuilderContractTests.test_finish_preserves_original_error_and_reports_export_cleanup_residue",
    "test_docker_builder.BuilderContractTests.test_actual_synthetic_bootstrap_sequence_success_failure_interrupt_and_durable_identity",
    "test_docker_builder.BuilderContractTests.test_daemon_drift_before_every_mutation_and_clean_environment_no_buildkit",
    "test_docker_builder.BuilderContractTests.test_base_drift_wrong_user_rootfs_daemon_and_unrelated_resources_never_remove",
    "test_docker_builder.BuilderContractTests.test_durable_consumers_retained_and_cap_exhaustion_no_auto_deletion",
    "test_docker_builder.EvidenceWriteTests.test_exact_serialization_overwrite_transient_count_and_aggregate_before_write",
    "test_docker_builder.EvidenceWriteTests.test_copy_symlink_member_file_bounds_and_archive_padding_before_allocation",
    "test_docker_builder.EvidenceWriteTests.test_sqlite_consistent_backup_preflight_limit_and_no_partial_export",
    "test_docker_builder.EvidenceWriteTests.test_usage_rejects_unexpected_directory_symlink_and_preserves_original_on_error",
    "test_docker_builder.AcquisitionAndColdTests.test_exact_download_prewrite_length_hash_deadline_and_redirect_no_network",
    "test_docker_builder.AcquisitionAndColdTests.test_archive_expansion_members_traversal_and_unknown_format_refuse_before_unpack",
    "test_docker_builder.AcquisitionAndColdTests.test_debian_archive_control_data_counts_and_index_expansion_are_bounded",
    "test_docker_builder.AcquisitionAndColdTests.test_actual_setup_child_bounded_output_failure_deadline_and_owned_reaping",
    "test_docker_builder.AcquisitionAndColdTests.test_cold_selection_generation_prefix_config_and_installed_tree_refuse_in_optimized_mode",
    "test_docker_builder.AcquisitionAndColdTests.test_cold_proof_missing_image_or_generation_fails_host_outcome_validation",
    "test_docker_builder.AcquisitionAndColdTests.test_native_export_failure_preserves_original_without_fabricated_evidence",
    "test_docker_builder.AcquisitionAndColdTests.test_real_count_parser_includes_standalone_native_statuses_not_constants",
    "test_docker_builder.AcquisitionAndColdTests.test_public_core_git_reconstruction_complete_tree_commit_no_host_git_or_native_setup",
    "test_docker_builder.BuilderContractTests.test_public_input_context_exact_hashes_readable_for_capless_setup_without_broad_chmod",
}
DOCKER_SOURCES = ("scripts/docker_acceptance.py", "scripts/docker_contract.py", "scripts/docker_inside.py", "docker/base_setup.py",
                  "scripts/docker_builder.py", "scripts/docker_evidence.py", "scripts/docker_cold.py",
                  "docker/acquisition_support.py", "docker/acquisition_plan.py",
                  "scripts/test_result_report.py", "scripts/check_docker.py", "scripts/hosted_contract.py",
                  "scripts/hosted_docker.py", "scripts/hosted_evidence.py", "docker/hosted_setup.py", "docker/hosted_apt.py")


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
