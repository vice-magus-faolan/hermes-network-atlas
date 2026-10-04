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

## Acceptance requirements

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
