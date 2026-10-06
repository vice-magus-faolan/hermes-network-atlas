# Acceptance matrix

The requirements below are backed by cumulative synthetic offline tests, not
live validation or self approval. Run `python3 scripts/verify.py` after supported
isolated setup in [operator-guide.md](operator-guide.md). Missing native admission
evidence fails; it is never skipped. All production modules are declared/compiled
and all test modules discovered by the same verifier and CI workflow.

## Executable evidence index

Each named test is discovered by the canonical verifier. The matrix/reference
contract is checked by `tests/test_documentation.py::DocumentationTests`.

| ID | Exact executable evidence | Operator/contract documentation |
| --- | --- | --- |
| A01 | `tests/test_acceptance.py::CumulativeAcceptanceTests::test_supported_admission_three_aliases_and_fresh_process_without_collection`; `tests/test_runtime.py::NativeRuntimeTests::test_actual_native_discovery_schemas_tools_commands_and_operator_split` | `docs/operator-guide.md`; `plugin.yaml`; `scripts/prepare_acceptance.py`; `scripts/native_install.py` |
| A02 | `tests/test_core.py::PersistenceTests::test_fresh_process_reopen_preserves_manual_seed_query_history_access_and_map`; `tests/test_acceptance.py::CumulativeAcceptanceTests::test_supported_admission_three_aliases_and_fresh_process_without_collection` | `docs/atlas-core.md`; `docs/operator-guide.md` |
| A03 | `tests/test_boundaries.py::PolicyTests::test_cidr_scope_and_ipv6_active_boundaries`; `tests/test_boundaries.py::PolicyTests::test_each_limit_rejects_zero_negative_bool_fraction_nan_and_over_ceiling`; `tests/test_inspection.py::InspectionTests::test_exact_schema_and_request_boundary_before_any_effect` | `docs/contract-decisions.md`; `docs/local-discovery.md`; `docs/authorized-ssh-inspection.md` |
| A04 | `tests/test_core.py::IdentityAndProvenanceTests::test_ip_hostname_never_merge_and_mac_anchors_interface_only`; `tests/test_discovery_remediation.py::LocalCollisionTests::test_duplicate_mac_local_rows_both_orders_are_unresolved`; `tests/test_inspection_extra.py::ExtraInspectionTests::test_duplicate_remote_macs_and_foreign_interface_preserved` | `docs/contract-decisions.md`; `docs/local-discovery.md`; `docs/authorized-ssh-inspection.md` |
| A05 | `tests/test_core.py::IdentityAndProvenanceTests::test_field_precedence_assertions_preserved_and_same_source_supersession`; `tests/test_core.py::IdentityAndProvenanceTests::test_equal_rank_cross_source_disagreement_has_no_arbitrary_winner`; `tests/test_boundaries.py::BoundaryTests::test_runtime_kwargs_do_not_attest_operator_origin` | `docs/atlas-core.md`; `docs/contract-decisions.md` |
| A06 | `tests/test_core.py::QueryUpdateMapTests::test_query_filters_pagination_and_literal_sql_like_injection`; `tests/test_core.py::QueryUpdateMapTests::test_cli_create_operator_update_and_validated_interface_relations`; `tests/test_boundaries.py::BoundaryTests::test_alias_association_cannot_grant_permission`; `tests/test_commands.py::OperatorStatusTests::test_slash_exact_arities_and_usage_no_origin_promotion`; `tests/test_unresolved.py::UnresolvedEvidenceTests::test_zero_devices_multiple_responses_and_stored_reasons`; `tests/test_unresolved.py::UnresolvedEvidenceTests::test_exact_address_batch_validation_and_empty_unknown`; `tests/test_unresolved.py::UnresolvedEvidenceTests::test_tie_safe_pagination_duplicate_history_and_lowered_caps`; `tests/test_unresolved.py::UnresolvedEvidenceTests::test_reconciled_unresolved_later_resolved_same_interface_anchor`; `tests/test_unresolved.py::UnresolvedEvidenceTests::test_running_sql_interrupted_and_snapshot_closed` | `docs/atlas-core.md`; `docs/operator-guide.md`; `docs/unresolved-evidence.md` |
| A07 | `tests/test_discovery.py::ReconciliationTests::test_new_changed_unchanged_ip_movement_multi_address_idempotent_reopen`; `tests/test_discovery.py::ReconciliationTests::test_missing_not_offline_stale_threshold_never_seen_reappearance_retired`; `tests/test_discovery_extra.py::AdditionalDiscoveryTests::test_active_partial_keeps_positive_but_never_asserts_scope_absence` | `docs/local-discovery.md`; `docs/operator-guide.md` |
| A08 | `tests/test_discovery.py::RunnerTests::test_actual_stream_combined_output_limit_and_success`; `tests/test_discovery_extra.py::AdditionalRunnerTests::test_successful_leader_exit_cleans_descendant_not_unrelated_process`; `tests/test_inspection_extra.py::ActualInspectionBoundsTests::test_host_wide_deadline_real_owned_child_only_once_and_persisted_failures` | `docs/local-discovery.md`; `docs/authorized-ssh-inspection.md` |
| A09 | `tests/test_inspection.py::InspectionTests::test_fixed_transport_strict_keys_and_no_config_side_channels`; `tests/test_inspection.py::InspectionParserTests::test_os_release_is_parsed_as_data_not_sourced_and_negative_formats`; `tests/test_inspection_remediation.py::InspectionReachabilityTests::test_up_down_and_link_local_inventory_preserves_alias_success_and_history` | `docs/authorized-ssh-inspection.md`; `SECURITY.md` |
| A10 | `tests/test_core.py::PersistenceTests::test_interrupt_rolls_back_and_busy_writer_is_bounded`; `tests/test_discovery.py::DiscoveryTests::test_passive_fixed_argv_scope_atomic_no_canonical_mutation`; `tests/test_discovery_remediation.py::ReconcileBudgetTests::test_sql_progress_interrupts_running_statement_and_rolls_back`; `tests/test_inspection_extra.py::ExtraInspectionTests::test_reconcile_deadline_after_access_write_rolls_back_and_retry_is_exact` | `docs/atlas-core.md`; `docs/local-discovery.md` |
| A11 | `tests/test_core.py::QueryUpdateMapTests::test_golden_text_markdown_mermaid_and_negative_label_cases`; `tests/test_core.py::QueryUpdateMapTests::test_render_deterministic_escaped_isolated_stale_and_inferred_edges`; `tests/test_core.py::QueryUpdateMapTests::test_map_rejects_arbitrary_export_path_symlink_and_oversized_output` | `docs/atlas-core.md`; `docs/operator-guide.md`; `tests/fixtures/render-golden.json` |
| A12 | `tests/test_core.py::QueryUpdateMapTests::test_shared_knowledge_never_transfers_inspection_authority`; `tests/test_inspection.py::InspectionTests::test_disabled_revoked_shared_profile_and_ambiguous_mappings_fail_closed`; `tests/test_commands.py::OperatorStatusTests::test_shared_foreign_batches_do_not_claim_local_last_discovery`; `tests/test_unresolved.py::UnresolvedEvidenceTests::test_shared_foreign_knowledge_visible_without_authority_separate_store_empty`; `tests/test_unresolved.py::UnresolvedEvidenceTests::test_foreign_same_mac_does_not_resolve_local_lineage` | `docs/atlas-core.md`; `docs/operator-guide.md`; `docs/unresolved-evidence.md`; `SECURITY.md` |
| A13 | `tests/test_acceptance.py::CumulativeAcceptanceTests::test_supported_admission_three_aliases_and_fresh_process_without_collection`; `tests/test_harness.py::AcceptanceHarnessTests::test_socket_denial_is_inherited_through_exec`; `tests/test_harness.py::AcceptanceHarnessTests::test_code_and_native_selection_changes_invalidate_receipt` | `docs/operator-guide.md`; `scripts/cumulative_acceptance.py`; `scripts/cumulative_transport.py`; `scripts/offline_guard.py` |
| A14 | `tests/test_documentation.py::DocumentationTests::test_matrix_paths_and_exact_test_symbols_exist`; `tests/test_documentation.py::DocumentationTests::test_readme_distinguishes_implementation_from_live_delivery`; `tests/test_commands.py::OperatorStatusTests::test_empty_status_has_consistent_counts_scopes_and_no_file_effects`; `tests/test_commands.py::OperatorStatusTests::test_discovery_and_inspection_are_distinct_local_qualified_summaries`; `tests/test_status_remediation.py::StatusBatchBoundsTests::test_full_size_ping_complete_partial_failed_and_small_control_after_restart`; `tests/test_status_remediation.py::StatusBatchBoundsTests::test_full_size_ping_lowered_detail_limits_do_not_change_whole_batch_evidence`; `tests/test_status_remediation.py::StatusBatchBoundsTests::test_lowered_limit_passive_and_ssh_status_keep_distinct_complete_evidence`; `tests/test_status_remediation.py::StatusBatchBoundsTests::test_lowered_limit_passive_and_ssh_complete_and_failed_after_restart`; `tests/test_status_remediation.py::StatusBatchBoundsTests::test_status_output_cap_still_refuses_without_store_changes` | `README.md`; `docs/operator-guide.md`; `docs/atlas-core.md`; `SECURITY.md`; `CONTRIBUTING.md` |

## Docker harness evidence boundaries

Docker contract regressions are required by the same canonical verifier. They
exercise synthetic inspection/ownership/export refusals and actual owned local
CLI child cleanup, not Docker daemon/native admission substitutes:

| Gate | Evidence and interpretation |
| --- | --- |
| Contract | `tests/test_docker_acceptance.py::DockerContractTests::test_inspection_drift_rejects_wrong_labels_image_mounts_flags_network`; `tests/test_docker_acceptance.py::DockerContractTests::test_actual_counts_exit_zero_skips_missing_and_mismatch_refuse`; `tests/test_docker_acceptance.py::DockerLifecycleTests::test_active_lease_refuses_and_releases_without_suffix_retry`; `tests/test_docker_acceptance.py::DockerLifecycleTests::test_optimized_native_readback_mismatch_manifest_and_generation_refuse` |
| Actual owned child/lifecycle | `tests/test_docker_acceptance.py::DockerLifecycleTests::test_actual_bounded_command_pass_fail_deadline_output_and_owned_cleanup`; `tests/test_docker_acceptance.py::DockerLifecycleTests::test_failed_export_keeps_original_failure_and_still_tears_down`; real Docker passing/failing/interrupted cleanup still requires external run evidence |
| Code-only owned bootstrap/plan | `tests/test_docker_builder.py::BuilderContractTests::test_actual_synthetic_bootstrap_sequence_success_failure_interrupt_and_durable_identity`; `tests/test_docker_builder.py::BuilderContractTests::test_complete_plan_identity_unknown_lengths_hashes_and_peak_reserve`; `tests/test_docker_builder.py::BuilderContractTests::test_unapproved_or_incomplete_plan_never_reaches_daemon_or_native`; no actual first setup or peak proof is inferred |
| Write-side export/retention | `tests/test_docker_builder.py::EvidenceWriteTests::test_exact_serialization_overwrite_transient_count_and_aggregate_before_write`; `tests/test_docker_builder.py::EvidenceWriteTests::test_sqlite_consistent_backup_preflight_limit_and_no_partial_export`; `tests/test_docker_builder.py::BuilderContractTests::test_durable_consumers_retained_and_cap_exhaustion_no_auto_deletion`; cooperative bounds are not a bind quota |
| Cold-selection contract | `tests/test_docker_builder.py::AcquisitionAndColdTests::test_cold_selection_generation_prefix_config_and_installed_tree_refuse_in_optimized_mode`; `tests/test_docker_builder.py::AcquisitionAndColdTests::test_cold_proof_missing_image_or_generation_fails_host_outcome_validation`; real changed-artifact enable/cold consumer remains mandatory |
| Plan/registry review remediation | `tests/test_docker_builder.py::BuilderContractTests::test_invented_plan_without_source_closure_refuses_before_effects`; `tests/test_docker_builder.py::BuilderContractTests::test_suffix_registry_wrong_home_profile_and_temporary_parent_refuse`; `tests/test_docker_plan.py::PlanLinkageTests::test_oci_manifest_config_compressed_layer_and_ordered_diffid_linkage`; `tests/test_docker_plan.py::PlanLinkageTests::test_each_closure_pin_edges_roots_and_exact_member_identity_refuse`; `tests/test_docker_plan.py::PlanLinkageTests::test_live_build_and_acquire_remain_disabled_even_linked_metadata_no_effect`; linkage/mock refusal is not authenticated resolution or proven fit |
| Genuine container native acceptance | Fresh real native scan/install/enable/PM-selected generation, contained receipt, full canonical logs and cold/restart evidence on exact commit/tree/image; missing proof fails acceptance, never a smoke-to-native promotion |
| Minimal host evidence | Required packet-free host/kernel permission diagnostics remain explicit; container fixtures do not prove host ICMP capabilities or live readiness |
| Final/hosted/publication | Independent cumulative exact-SHA review and publisher-owned actual hosted CI/PR review remain separate; local Docker is not hosted-CI authority |

See `docs/docker-acceptance.md` for exact layout, resource/retention constraints,
ordinary local consent and the pre-canary exact-byte safety gate. New Docker
runtime/native proof remains pending until exercised; no full success is inferred
from the Dockerfile or packet-free unit regressions.

## Acceptance requirements

### Complete issue-6 criterion audit

The controlling amendment is host-only/datagram-only, with no helper execution or
privilege changes. These exact tests cover each public issue criterion cumulatively;
the final independent review must cold-read the entire change, not this stage alone.
Green fixtures are not live validation, publication approval or target integration.

| ID | Public criterion and exact executable evidence |
| --- | --- |
| H01 | Minimal network-local policy/compatibility and prior amendment: `tests/test_host_discovery_policy.py::HostDiscoveryPolicyTests::test_legacy_defaults_and_explicit_defaults_preserve_exact_transport`; `docs/implementation-addendum.md`; `docs/host-discovery-policy.md` |
| H02 | Strict policy/scope/ports, no caller destinations/flags: `tests/test_host_discovery_policy.py::HostDiscoveryPolicyTests::test_strict_enablement_port_types_bounds_duplicates_cap_and_exclusion`; `tests/test_host_transport.py::HostTransportTests::test_scope_and_4403_caller_forgery_refuse_before_transport` |
| H03 | Ordinary permitted datagrams, no helper/raw/elevation: `tests/test_host_discovery_policy.py::ICMPCapabilityTests::test_permission_protocol_resource_failures_are_bounded_no_retry_or_helper`; `tests/test_host_acceptance.py::CumulativeHostTests::test_sensitive_destinations_excluded_without_socket_or_helper`; `SECURITY.md` |
| H04 | Real permission/protocol failures, no flag/executable capability fiction: `tests/test_host_discovery_policy.py::ICMPCapabilityTests::test_open_success_only_unverified_and_socket_closed_no_packet_operations`; `tests/test_host_transport.py::HostTransportTests::test_denied_missing_icmp_does_not_suppress_tcp_and_no_fallback`; `tests/test_host_discovery_policy.py::HostDiscoveryPolicyTests::test_missing_nmap_remains_explicit_failure_without_icmp_fallback` |
| H05 | One combined budget, every enabled method, persistence reserve/cancellation: `tests/test_host_acceptance.py::CumulativeHostTests::test_every_method_uses_combined_budget_at_each_concurrency`; `tests/test_host_acceptance.py::CumulativeHostTests::test_shared_receive_exhaustion_retains_other_method_evidence`; `tests/test_host_acceptance.py::CumulativeHostTests::test_deadline_after_open_before_send_and_unregister_failure_cleanup`; `tests/test_host_transport.py::HostTransportTests::test_persistence_failure_retains_history_and_output_receipt_rolls_back` |
| H06 | Checks/responses/attempts/coverage kept separate: `tests/test_host_transport.py::HostTransportTests::test_mixed_duplicates_retained_address_counts_deduplicated_after_restart`; `tests/test_host_transport.py::HostTransportTests::test_all_filtered_timeouts_not_offline_or_packets_for_unstarted`; `docs/operator-guide.md` |
| H07 | Method/port/time positives retained, no identity/service/access inference: `tests/test_host_transport.py::HostTransportTests::test_icmp_only_positive_survives_filtered_web_and_retains_times`; `tests/test_host_acceptance.py::CumulativeHostTests::test_hostile_echo_fields_and_bytes_never_qualify_response`; `tests/test_host_acceptance.py::CumulativeHostTests::test_legacy_and_new_exact_lineage_shared_read_without_apply_authority` |
| H08 | Sensitive exclusion, no application payload and honest connection effects: `tests/test_host_transport.py::HostTransportTests::test_scope_and_4403_caller_forgery_refuse_before_transport`; `tests/test_host_transport.py::HostTransportTests::test_icmp_golden_header_and_hostile_reply_validation`; `scripts/synthetic_sockets.py`; `SECURITY.md` |
| H09 | Profile-local authority over shared foreign knowledge: `tests/test_host_discovery_policy.py::HostDiscoveryPolicyTests::test_network_local_immutable_snapshots_and_shared_data_do_not_grant_methods`; `tests/test_host_acceptance.py::CumulativeHostTests::test_legacy_and_new_exact_lineage_shared_read_without_apply_authority`; `tests/test_inspection.py::InspectionTests::test_disabled_revoked_shared_profile_and_ambiguous_mappings_fail_closed` |
| H10 | Deterministic socket-denied method/bounds/tail/native acceptance: `tests/test_host_acceptance.py::CumulativeHostTests::test_sparse_late_range_each_method_and_all_filtered_control`; `tests/test_host_transport.py::HostTransportTests::test_tcp_2222_and_optional_22000_only_positives`; `tests/test_acceptance.py::CumulativeAcceptanceTests::test_supported_admission_three_aliases_and_fresh_process_without_collection`; `scripts/native_host_acceptance.py` |
| H11 | No-response uncertainty, historical evidence/identity conservatism: `tests/test_host_transport.py::HostTransportTests::test_all_filtered_timeouts_not_offline_or_packets_for_unstarted`; `tests/test_host_acceptance.py::CumulativeHostTests::test_legacy_and_new_exact_lineage_shared_read_without_apply_authority`; `tests/test_unresolved.py::UnresolvedEvidenceTests::test_malformed_stored_receipt_entries_fail_in_public_error_envelope` |
| H12 | Independent exact-artifact review before separate publication; no automatic enable/live scans: `tests/test_harness.py::AcceptanceHarnessTests::test_socket_denial_is_inherited_through_exec`; `tests/test_host_discovery_policy.py::HostDiscoveryPolicyTests::test_legacy_defaults_and_explicit_defaults_preserve_exact_transport`; `docs/delivery-plan.md`; `docs/host-discovery-policy.md` |

H12's independent verdict is a delivery gate, not something a builder can certify
with a unit test. Native candidate-bound setup/dispatch/restart is mandatory on
the final committed artifact. Other platforms and genuinely denied ICMP remain
honest unavailable outcomes; no optional real helper is claimed tested/enabled.

Issue #6 stage-1 regressions are mandatory alongside the original chunk tests:
`tests/test_host_discovery_policy.py::HostDiscoveryPolicyTests` covers strict
booleans/types/bounds/duplicates/four-port cap/4403 exclusion, dependency/scope
rejection, immutable network-local grants, YAML unknown/duplicate keys, unchanged
legacy fixed argv/missing-Nmap behavior and staged effect-free public tool/slash/
CLI refusal at stage 1, now combined-count pre-effect refusal at stage 2.
`tests/test_host_discovery_policy.py::ICMPCapabilityTests` mocks every
socket: disabled/deadline/platform no-open, permission/protocol/resource errors,
unverified open/close, interruption and uncached recheck. No packets or helpers.
Contract and stage-2 combined budgets/provenance are in host-discovery-policy.md.
`tests/test_host_transport.py::HostTransportTests` covers ICMP-only positives with
filtered web TCP, configured 2222/22000, mixed duplicates, denied/missing ICMP,
all-filtered outcomes, forged grants/4403 exclusions, full-range rate/concurrency,
shared receive/host/operation budgets, interruption/socket cleanup and rollback.
The native cumulative harness exercises nine method scenarios through installed tool,
slash and CLI dispatch with non-forwarding sockets, then reads exact evidence
after process restart. No real helper, packet or production migration is tested.
`tests/test_commands.py::OperatorStatusTests::test_cli_invalid_policy_refusal_has_explicit_no_effects_receipt`
requires explicit applied=false/persisted=false on invalid-policy CLI refusal,
before read/write dispatch, with absent and existing stores preserved byte-for-byte.

Combined discovery/evidence regressions are mandatory in the canonical verifier:
`tests/test_unresolved.py::UnresolvedEvidenceTests::test_chunk_evidence_partial_not_started_and_complete_bounded_pages`
checks complete/partial /24 address accounting including not_started under a
one-row evidence bound;
`tests/test_unresolved.py::UnresolvedEvidenceTests::test_partial_chunk_original_later_lineage_and_foreign_visibility`
preserves original/later identity and foreign read visibility without authority;
`tests/test_unresolved.py::UnresolvedEvidenceTests::test_malformed_stored_receipt_entries_fail_in_public_error_envelope`
proves malformed identity receipts refuse read-only in the public error envelope.

Issue #2 bounded-coverage regressions are discovered by the same verifier; it
explicitly refuses to run if the critical chunk/legacy regression IDs are absent:

- A07: `tests/test_discovery_chunks.py::ChunkDiscoveryTests::test_sparse_24_startup_budget_reaches_last_address_and_reconciles_exact_batch`
  proves startup-cost RED/GREEN, complete sparse /24 tail coverage and exact-batch retry.
- A08: `tests/test_discovery_chunks.py::ChunkDiscoveryTests::test_mid_chunk_deadline_keeps_earlier_positive_and_marks_tail_not_started`,
  `tests/test_discovery_chunks.py::ChunkDiscoveryTests::test_completed_at_transport_boundary_retained_no_late_chunk`,
  `tests/test_discovery_chunks.py::ChunkDiscoveryTests::test_last_completed_chunk_at_boundary_keeps_complete_coverage`,
  `tests/test_discovery_chunks.py::ChunkDiscoveryTests::test_deadline_rechecked_immediately_before_owned_spawn`,
  `tests/test_discovery_chunks.py::ChunkDiscoveryTests::test_fixed_argv_serial_process_internal_concurrency_rate_and_lowered_bounds`,
  `tests/test_discovery_chunks.py::ChunkParserTests::test_multi_host_accounting_down_records_and_boundaries`, and
  `tests/test_discovery_chunks.py::ChunkParserTests::test_hostile_duplicate_out_of_chunk_stats_and_output_bounds`
  cover scheduling, parser trust boundaries, lowered intensity, time/output/observation bounds.
- A10: `tests/test_discovery_chunks.py::ChunkDiscoveryTests::test_failed_chunk_output_parser_and_persistence_do_not_damage_history`
  proves failed chunks disqualify absence and persistence failure leaves old history intact.
- A14: `tests/test_status_remediation.py::StatusBatchBoundsTests::test_legacy_per_address_24_and_25_totals_remain_readable_after_restart`
  retains immutable legacy accounting; new address_count/address_outcome_counts
  exclude synthetic coverage. New not_started is never success/absence eligibility.
- The common runner seam also has
  `tests/test_inspection_extra.py::ActualInspectionBoundsTests::test_shared_runner_completion_and_not_started_are_not_relabelled_after_parsing`;
  no SSH capability or permissions changed. Exact fixed-argv/collector-contract
  amendment and real-world timing caveats are in local-discovery.md and addendum §6.

- **A01 Native plugin**: supported install/enable, discovery, schemas, actual
  tool invocation, and operator commands under a temporary Hermes home.
- **A02 Persistence**: reopen/fresh process retains IDs, facts, relations,
  observation history, access evidence, and map output without discovery.
- **A03 Config/authorization**: malformed/out-of-policy CIDRs, excessive ranges,
  disabled modes, unknown options, and unauthorized SSH aliases fail closed.
- **A04 Identity**: MAC survives address change; interface/device distinction;
  IP/name collisions do not force merges; alias identity and ambiguous matches.
- **A05 Provenance**: field-specific precedence; conflicts retained; operator
  attestation cannot be forged through tools; inference explanation preserved.
- **A06 Update/query**: authorized operator changes versus inference; parameterized
  bounded queries do no collection; alias association cannot grant SSH permission.
  Original discovery-evidence pages distinguish never-applied, unresolved,
  conflicting and subsequently resolved history with exact-anchor lineage,
  qualification/freshness, origin and legacy V1 batch/probe coverage. Exact
  address/batch filters, tie-safe limit+1 pagination, full page ceilings, lowered
  bounds, receipt/candidate/output limits and SQL deadlines are executable.
- **A07 Reconciliation**: new/changed/unchanged/missing/conflicting, stale threshold,
  reappearance, retired persistence, failed/partial scans, idempotent event history.
- **A08 Bounds**: fixed argv, no command/option/SQL injection; time/output/operation
  limits, owned child cleanup, missing optional dependencies, IPv4 scan cap.
- **A09 SSH**: strict host keys, noninteractive, no forwarding/LocalCommand/multiplex
  reuse/sudo; only fixed read-only probes; invalid target and parser/command failures.
- **A10 Atomicity**: rollback, concurrent writers, restart, busy timeout, schema
  version handling, transaction/events consistency; subprocess outside write locks.
- **A11 Rendering**: deterministic Markdown/Mermaid, escaping hostile text, stale
  visibility, only supported edges, isolated nodes, fixed safe export destinations.
- **A12 Profiles**: profile-aware homes; explicit shared atlas reads; separate
  inspection policy; no implicit authority transfer and no other-profile mutation.
- **A13 End to end**: three synthetic aliases, bounded collection, inspection,
  reconciliation, change/conflict/absence answers, maps, then restart/re-query.
- **A14 Operator docs**: supported installation, config, dependency failures,
  source meaning, trust boundaries, direct user updates, safety, examples, and
  explicit distinction between isolated acceptance and unperformed live validation.
  Status retains whole-batch completion/outcome/coverage/failure/absence counts
  for valid /24 and /25 batches independently of inventory pagination; bounded
  failure-first details declare returned/omitted/omitted-failure counts. Lowered
  result limits, passive/SSH distinctions, public tool/slash/operator reads after
  fresh-process restart, small-scope controls and serialized output caps are tested.
- **A15 Repository delivery**: exact independent approval, passing canonical
  checks on target, final artifact ancestry, clean checkout, guarded cleanup,
  later external publication kept behind an operator approval gate.

## Residual and unperformed checks

The prospective ordinary CAUTION confirmation route is inactive. Canonical
`REQUIRED_CONFIRMATION_TESTS` includes eight exact IDs from
`tests/test_caution_confirmation.py::CautionConfirmationTests`: non-TTY real native
refusal, missing/candidate-controlled authority, exact-byte/scope/identity/finding
and signature mismatch, signed dangerous refusal, candidate/core drift, real
ordinary prompt with packet-denied PM failure, synthetic successful prompt transport
and marker/output/deadline refusal. These are also run before default CI setup.
No synthetic approval is candidate admission or real CI authority. The legacy
signed route remains inactive optional coverage, not a CI provisioning gate.
`REQUIRED_CI_ADMISSION_TESTS` mandates all eleven hosted-policy tests in
`tests/test_ci_admission.py::HostedCIAdmissionTests`: explicit matching diagnostics,
fresh contained nonreplacement fixture, real native CAUTION/force-policy selection
without installation, native DANGEROUS refusal even with force, SAFE/no-force and
candidate/core drift, parsed hosted/read-only/pinned/no-secret workflow, real local
entrypoint/mixed-consent/enable refusals and origin/ref/config revalidation,
main/feature push and PR merge refs matching parsed workflow branch filters,
and disallowed event/branch/tag/malformed/non-merge ref refusal. The runner-context
regression rejects runner expressions before step scope and executes scratch
initialization/export with
space-containing paths; the same scratch directory persists through GITHUB_ENV
for later admission and canonical steps. Full workflow expression/context
validation uses pinned actionlint before a changed candidate's local admission;
YAML parsing alone is not proof that GitHub accepts a workflow. Pushes are limited
to main/the issue-6 feature and PRs target main; a main test context is not authority
to push/merge main. PR evidence binds the checked-out merge artifact, not head tip.
The approved hosted workflow uses supported force only for CAUTION on fresh
GitHub-hosted Ubuntu VMs with full scanning, DANGEROUS refusal, no supplied secrets
or deployment access and unchanged native admission/enable/readback. Environment
strings are not hosted isolation proof; local/runtime force remains prohibited.
See `docs/native-caution-confirmation.md`. Fresh exact-byte ordinary local admission,
canonical acceptance and independent review remain mandatory. The publisher checks
actual exact-head hosted native/canonical execution after the reviewed branch push;
no controller/key/anchor provisioning or per-commit signed CI consent is required.

A01 setup is a real native CLI-entrypoint install/enable and PM publication in
marked disposable homes. A13 uses real discovery/registry/command/core APIs and
the admitted selected Python, but transport is deliberately synthetic. Neither
proves a live host key, real reachability or provider chat behavior. All subprocesses
in canonical acceptance inherit socket denial; setup runs separately online.

Other OS/OpenSSH/Hermes versions, GitHub CI execution, production installation,
private seeding, LAN scans, actual SSH and gateway restart remain unperformed.
SSH config/executables and same-UID code are trusted; time/SQLite cancellation is
cooperative, and local cleanup cannot guarantee remote descendant cancellation.
Two-file generated export replacement is not a cross-file atomic transaction.

A15 is NOT closed by this cumulative component. Exact independent Gilfoyle approval
is required on its final SHA; the existing delivery owner proves target ancestry,
canonical checks on main and guarded integration/cleanup. Publication/live effects
remain separately authorized. Reviewer completion is not integration/publication.
