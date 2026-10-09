# Acceptance matrix

## Current product-first delivery contract

The active path is [disposable-validation.md](disposable-validation.md): ONE
conventional hosted Docker image, ONE ONLINE native install AND enable, then
full packet-denied canonical and cold/restart checks using that very selection
in its candidate-owned volume. All feature/main/PR events use this path.
H01–H12 below remain the complete public issue #6 acceptance checklist; A01–A14
and every product safety regression remain required. Native/full-canonical/cold
proof on the final exact artifact is pending actual hosted execution and review.

The retained-producer/measurement/controller sections below are SUPERSEDED
historical contracts, not active delivery requirements. Their tests, fixtures,
limits and failures remain preserved, not weakened or reclassified as success.
Only four directly affected workflow methods changed, as explicitly indexed in
disposable-validation.md; new disposable validation IDs are additive/mandatory.
No local full-core fixture/native admission/Docker is required or authorized for
the preliminary exact-SHA source/workflow review. Missing admission still fails
the full canonical verifier; source-only review is not final feature delivery.
Hosted run 37864339897's provider green is invalid: canonical failed with eight
PM import errors and cold lacked canonical success proof. The bounded correction
adds workflow-wide explicit bash pipefail and pre-discovery pinned package roots.
Three mandatory `tests/test_disposable_failure.py::DisposableFailureTests` IDs
prove actual producer/tee failure propagation, cold-interpreter actual pinned PM
import lifetime RED/GREEN with stale-origin refusal, and real failed canonical
execution preventing proof/cold admission. All inherited IDs/files/assertions,
product modules and historical fixtures remain unchanged by this correction.
Corrected exact-head hosted native/full-canonical/cold and final review remain pending.

## Historical harness contracts (superseded)

For the GitHub-hosted Docker delivery contract, see
[hosted-first-docker.md](hosted-first-docker.md). Local implementation tests are
not native admission; absent fresh current-artifact acceptance remains FAILED.
The pre-CI handoff needs independent exact-code/workflow review, not a claimed
guaranteed-fit/local-all-green precondition or another per-attempt human approval.
Final actual native/canonical/hosted/independent/publication gates are unchanged.

The public bootstrap now uses standard Docker defaults for genuine package
ownership and maintainer scripts. Candidate acceptance still drops ALL capabilities
and runs non-root/offline. Complete audit is in
[bootstrap-permission-contract.md](bootstrap-permission-contract.md). Local tests
and preliminary source review do not prove actual hosted/native acceptance.

Mandatory `tests/test_docker_apt.py::AptProofTests` covers preinstall genuine
archive hashes surviving normal post-install cache removal, unchanged base package
versions, distinct empty index/archive refusals, control/index/installed drift,
each APT command's failure-stage/output/exit retention, explicit all-preinstalled
zero-archive refusal, malformed/nonregular/size/count proof, real owned child
failure/deadline/output/resource audit, diagnostic-error precedence and independent
failed-bootstrap diagnostic export/compact manifest. Native tool hash retention
before PM publication and direct local fetch/APT guard refusals are covered too.
These eleven IDs are mandatory in `scripts/verify.py`; fixtures are tiny and
packet-denied, not real signed APT/native acceptance or a successful hosted retry.

Eight mandatory `tests/test_docker_pm.py::NativePMContractTests` IDs execute the
actual pinned parser/flag predicate on production argv, predecessor refusal,
corrected narrow named dispatch, default-closure scope, real build-env parser/API
binding, member encoding/all used PM signatures, actual bounded owned command
success/failure diagnostics and primary-error precedence. Both normal and -O
processes are required. See [native-pm-contract-audit.md](native-pm-contract-audit.md)
for every hosted PM call and exact pinned source coordinates. The tests never
install/acquire; signature/dispatch success is not native acceptance.

Four additional mandatory `tests/test_docker_command_logs.py::CommandLogTests`
IDs exercise real failed children through the production wrapper and the actual
4 MiB aggregate reader: near-limit output plus uncaught traceback and actual
exporter readback; repeated failed rows with non-ASCII/invalid UTF-8/control/JSON
escaping and pre-spawn cumulative-budget refusal; argv/count effect-free bounds;
and real nonzero failure surviving terminal-emission errors. Normal/-O are required.
The exception is a bounded exit summary; the audit retains actual count/hash and
32 KiB head/tail. Its 1 MiB encoded cumulative ceiling, 256 KiB terminal reservation
and 32-command cap do not widen existing child/log/export budgets. No Docker is
executed; synthetic daemon export seams are not real native/hosted acceptance.

Five mandatory `tests/test_docker_reconstruction.py::ReconstructionLogTests` IDs
extend that same audit to every fixed Git reconstruction stage: actual failed
children (including near-cap and hostile output) survive the aggregate reader
and production exporter; a tiny real Git tree/commit reconstruction still passes
its original predicates; six Git stages and five ordinary hosted phase commands
plus the disabled legacy wrapper use one unchanged budget; count/byte exhaustion
refuses before Git/log effects; terminal-write errors retain the actual primary
exit; and deadline evidence survives owned-child reaping without affecting an
unrelated child. Normal/-O are required. These are packet-denied source/fixture
regressions, not acquisition, package/native acceptance or real Docker cleanup.

Seven inherited mandatory
`tests/test_docker_image_readback.py::ImageReadbackTests` IDs cover all field
mismatch names, historical empty-command merge refusal, journal-before-inspect,
actual parsed readback and compact export, exact returned digest/upstream ancestry,
malformed/oversized/failed readback, diagnostic-error precedence, unverified-image
cleanup refusal and hosted-controller failed-image proof retention. These synthetic
daemon seams do not identify run `37700249768`'s unexported mismatch. The diagnostic
successor's actual hosted run `37704198046` identifies `Config.Cmd` alone; its
inherited setup command remains refused by the precise corrected default contract.

Five additional mandatory
`tests/test_docker_default_command.py::DefaultCommandTests` IDs cover both production
commit paths and explicitly modeled Moby command merge; hash-bound actual historical
image/stopped fixtures and their continued refusal; exact inert `/usr/bin/true` argv
and empty entrypoint in initial validation, recovery/reuse and cleanup; unchanged
explicit acceptance argv in all six modes; no-op file/owner/permission/privilege/
absence/output/exit refusals before success inventory; a real tiny packet-denied
no-op child through the shared audit; and original-error/cleanup refusal evidence.
Normal/-O are required. One historical empty-CMD assertion and four success fixtures
now encode the inert default, while the original realistic empty-merge failure and
all other refusals remain. See [committed-image-readback.md](committed-image-readback.md)
for the exact inherited test-body changes. Modeling a proposed config or executing
the host's public no-op is NOT actual corrected image/native/full/cold/cleanup proof.

The requirements below are backed by cumulative synthetic offline tests, not
live validation or self approval. Run `python3 scripts/verify.py` after supported
isolated setup in [operator-guide.md](operator-guide.md). Missing native admission
evidence fails; it is never skipped. All production modules are declared/compiled
and all test modules discovered by the same verifier and CI workflow.

Ten additional mandatory
`tests/test_docker_container_readback.py::ContainerReadbackTests` IDs retain the
actual verified run `37707667589` base image/identity projection and separately
model Moby label inheritance. They exercise exact full composition/preflight,
all six acceptance argv/isolation, coherent base provenance/config drift refusal,
every label/Name/Image/returned-Id mismatch with raw-before-predicate persistence
and production compact export, export/stop/reinspect/cleanup drift, bounded
malformed/oversized/absent/daemon diagnostics and primary-error precedence,
failed/malformed create residue without deletion, independent durable consumers
despite outcome-export failure, and the production synthetic smoke lifecycle.
All inherited test bodies/IDs remain; normal/-O are required. No actual historical
container inspect exists and no real Docker/native success is inferred. See
[container identity readback](container-identity-readback.md) for source semantics,
exact authority, unchanged limits and the remaining actual hosted/final review gates.

## Executable evidence index

Fourteen additive mandatory `tests/test_docker_representation.py::RepresentationTests`
IDs cover actual tiny complete Git-only publication, literal commit/tree/shallow,
unreachable objects and absent parents, native CRLF/executable/symlink archive,
complete source/object/metadata readbacks, actual self-inclusive physical/logical/
verifier totals, owned spool/source peak overlap, old/mixed/partial/count/config/
hook/alternate/attribute/path/type/tamper refusals, real owned child deadline/
size/nonzero/reaping, simulated ENOSPC/primary-error/cleanup/export/no-reuse,
producer retirement failure and independent controller complete proof refusal.
Normal and actual -O are required. All inherited IDs/fixtures/assertions remain;
two structural AST expectations follow `seal_inventory` and two old minimal daemon
fixtures add only NEW representation-boundary decorators, with unchanged bodies.
Exact hashes/diffs are retained, not falsely called byte-identical. Full tracked
source/test/doc native-default scope remains unchanged. Source implementation and
tiny Git are NOT corrected hosted fit/fresh union/native/canonical/cold/restart/
cleanup/final acceptance. See [CORE retained representation](core-retained-representation.md).

Ten additive mandatory `tests/test_docker_measurement.py::MeasurementTests` IDs
cover real predecessor feature-routing RED, mutually exclusive measurement/native
jobs, unchanged main/PR/ordinary feature controls, actual tiny Git marker/hash/
parent/whole-diff validation and mixed/malformed/dirty/link refusal, pre-effect
local guard, two fixed genuine serial native variants preserving complete source/
objects/shallow/unreachable data with owned disposal, actual failure/audit/cleanup
precedence, projection equality/refusal/reserve/nonacceptance and resource/export
bounds. Normal/-O required. Two minimal inherited expectation seams change: the
hosted job condition adds validated acceptance output with original event/ref
predicates, and the core-checkout loop excludes only the source-routing gate;
all actual core consumers keep every original pin assertion. All inherited IDs,
remaining body assertions and historical JSON
bytes remain. No full core fixture/acquisition/native admission runs locally.
Full source measurement is hosted only after exact independent source/workflow
review. A sufficient projection or successful measurement is never native/full
canonical/final approval. Production packing/cache/tools/pins/budgets are unchanged.
See [hosted packing measurement](hosted-packing-measurement.md).

Eight additive mandatory `tests/test_docker_retention_observer.py::ObserverTests`
IDs exercise the actual live observer/owned child enumerate-stat race with a
deterministic barrier and genuine Git, full tiny source/object/shallow preservation
and unchanged lowered retention budget, exact loose-leaf/empty-fanout ENOENT scope,
strict final failure/proof refusal, permission/read/link/special/ancestor/escape
refusals, entry/time/transient byte bounds and postfailure/non-prune tolerance reset.
Normal/-O required. Every prune-phase sample is explicitly incomplete, not a final
total; final before/after/object/source/seed/verifier accounting remains strict.
All 450 inherited IDs/bodies/assertions, 264 required IDs, 50 test paths and six
historical JSONs are preserved. The authenticated real hosted observer failure is
not object loss, overflow or corrected acceptance. See [producer retention](producer-retention.md).

Thirteen additive mandatory `tests/test_docker_retention.py::RetentionTests` IDs
cover actual producer ordering, real tiny shallow packing with every reachable/
unreachable object and original absent parents preserved, full source/modes/links,
effect-free local/layout/ambient/alternate refusals, corrupt/changed object and
source refusal, actual-file same-budget RED then real-pack GREEN, component byte/
file totals and unchanged limits, bounded malformed/special/deadline reporting,
real owned-child failure/output/deadline and unrelated survival, primary-error
precedence, and independently ownership-first bounded export. Normal/-O required.
All 437 inherited IDs/method bodies/assertions and 49 tests-tree paths remain;
only two old minimal daemon seams gain documented new-export-boundary decorators.
These synthetic budgets and real tiny Git objects are not the actual hosted seed
or native acceptance. See [producer retention](producer-retention.md).

Ten additive mandatory `tests/test_docker_git_preparation.py::GitPreparationTests`
IDs cover actual producer command ordering RED/GREEN; exact original declaration/
lock drift refusal; actual pinned uv help/parser and nonrealizing PM selection;
substituted narrow online/independent offline commands and owned target disposal;
actual-file PEP 610 name/version/source/commit/malformed/additional-distribution
refusals; tiny real Git object hashing/missing/forged-object refusal; direct local,
missing-tool and preexisting-root pre-effect refusal; actual owned-child deadline/
output/reaping/resource caps and primary-error precedence; failed preparation
preventing warm; and independently guarded/bounded complete provenance export.
Normal/-O are required. All inherited IDs/assertions/fixtures remain; two old
controller methods add only documented new-boundary decorators, with unchanged
bodies. Local installs are substituted, not genuine Misaki/native acceptance.
See [producer-only Git preparation and limits](producer-git-preparation.md).

Nine additive mandatory `tests/test_docker_offline.py::OfflineConsumerTests` IDs
exercise literal predecessor parser/caller RED and successor explicit offline
enable GREEN, effect-free non-enable flag refusal, unchanged online default,
both network-none caller consent boundaries, actual native activation/Selection/
worker request and unchanged refusal, fresh member engine lock/sync offline argv,
authenticated current pins/fork workflow, and old-base/image current-policy
refusal. Normal/-O are required. Actual uv/publication/install/readback effects
are intercepted, NOT genuine cache/native acceptance. Five inherited test/helper
files have only documented pin literals/URL or scoped historical replay decorators
changed; all original historical JSON bytes and test IDs remain. Exact hashes/diffs
are retained, not falsely described as all-byte-identical. See
[authenticated offline consumer](native-offline-consumer.md).

Eleven additive mandatory `tests/test_docker_union_diagnostics.py::UnionDiagnosticsTests`
IDs cover real failed-enable export RED/GREEN, actual PTY audit/primary identity,
near-cap output and deadline/owned reaping, cache metadata/opaque hashes/symlink/
count/report/malformed refusals, read-only source/lock/member projection, actual
pinned PM argv/sanitizers/API and tiny workspace quarantine, producer failure
persistence and independent ownership-guarded/bounded export, plus primary-error
precedence. Normal/-O are required; all inherited test bodies/fixtures/IDs remain.
This is an explicitly diagnostics-only successor: actual run `37729012087` completed
native install but not enable, and its exact cache freshness/key deficiency remains
unknown. Intercepted pinned-engine calls and tiny fixtures are not resolution or
corrected hosted/native/full/cold acceptance. See
[member-union cache diagnostics](native-union-cache-diagnostics.md).

Eight additive mandatory `tests/test_docker_work_execution.py::WorkExecutionTests`
IDs cover exec only on the exact private `/work` create/inspect contract across
all modes; option/resource/UID/mount/source/export mutations; authenticated actual
run `37724779987` noexec/EACCES refusal; synthetic effective kernel flags/protection/
coverage, fixed current-version/containment/denial checks; incremental contract
export and primary error; actual entrypoint wiring; and install failure/success
with diagnostic failure refusing enable/canonical. Normal/-O are required. All
inherited IDs and bodies remain except the precisely authorized `/work` literal
gaining `exec,` at `tests/test_docker_tool_execution.py:256`; the rest of that body
is unchanged, with exact before/after hashes and diff retained. The actual failed
report is immutable; synthetic prospective reports are not corrected hosted/native
acceptance. See [native tool execution evidence](native-tool-execution.md).

Eight additional mandatory `tests/test_docker_tool_execution.py::ToolExecutionTests`
IDs cover actual pinned selection without PM healing/acquisition, current identity
drift, real tiny contained ELF/link/hash/mode/EACCES, escape/loop/missing/FIFO/size/
loader refusals, actual kernel mountinfo/statvfs versus intended HostConfig,
incremental pre-probe report and generic bounded exporter retention, real failed/
output/deadline owned children, and installer-primary/diagnostic-secondary behavior.
Normal/-O are required; all inherited tests/fixtures remain unchanged. The exact
historical permission cause in run `37720941089` remains UNKNOWN; this successor
changes diagnostics only, not mount/permission/PM/admission/isolation contracts.
These tiny production seams are not corrected hosted/native/full/cold acceptance.
See [native tool execution evidence](native-tool-execution.md).

Six additional mandatory `tests/test_docker_core_identity.py::CoreIdentityTests`
IDs exercise actual pinned named dispatch/project-local launcher writes with
acquisition and external PATH exposure replaced, full producer reconstruction
from a tiny real Git archive before replacing owned PM work material, complete
mutation/addition/removal/executable/symlink drift, seed/copied-core manifests
retained before refusal, source/member/manifest/special-type bounds and original
error precedence, and streamed exact public archive digest without extraction.
Normal/-O are required; all inherited bodies/fixtures remain unchanged. The
normal-path source mechanism is proved, but run `37716278161`'s unexported exact
member drift is unknown. These are not native install/admission or corrected
hosted/full/cold/all-mode cleanup. See [complete core identity](complete-core-identity.md).

Seven additional mandatory `tests/test_docker_startup.py::StartupTests` IDs cover
real tiny Git reconstruction and different-owner refusal/success, exact literal
path/record/config and commit/tree/blob/dirty/symlink/escape refusal, sanitized
native child trust for only the fixed snapshot with other repos still refused,
private hosted layout/owner/mode/nonempty/symlink refusals and actual bounded
writes, early real Git exit128 plus secondary-export precedence without unproven
identity claims, and all six unchanged isolation argv. Normal/-O are required.
Git's owner test seam and POSIX cross-UID mode analysis are not actual container
UID/native/hosted proof. All inherited test bodies/fixtures remain unchanged.
See [snapshot startup/layout contract](snapshot-startup-contract.md) for actual
run `37712086262`, the narrow process-local trust and ephemeral export leaf, and
the remaining actual hosted/native/full-canonical/cold/all-mode-cleanup gates.

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
| Hosted provisioning / pre-effect local refusal | `tests/test_docker_bootstrap_repair.py::BootstrapRepairTests::test_complete_package_contract_refuses_before_controller_effects`; `tests/test_docker_bootstrap_repair.py::BootstrapRepairTests::test_setup_and_apt_refuse_before_filesystem_acquisition_or_pm`; `tests/test_docker_bootstrap_repair.py::BootstrapRepairTests::test_actual_controller_entrypoint_contract_gate_precedes_scratch_and_daemon`; `tests/test_docker_bootstrap_repair.py::BootstrapRepairTests::test_standard_docker_capabilities_and_process_containment_golden_and_drift`; `tests/test_docker_bootstrap_repair.py::BootstrapRepairTests::test_real_setup_guard_requires_root_container_and_actual_status_before_effects`; `tests/test_docker_bootstrap_repair.py::BootstrapRepairTests::test_hosted_apt_permits_normal_authenticated_provisioning_not_script_bypass`; `tests/test_docker_bootstrap_repair.py::BootstrapRepairTests::test_hosted_build_success_crosschecks_process_proof_before_commit_and_owned_cleanup`; standard defaults only for public provisioning; local refusal and authentication remain, mocks are not actual package install |
| Primary failure / missing success evidence | `tests/test_docker_bootstrap_repair.py::BootstrapRepairTests::test_failed_export_preserves_stopped_logs_and_all_missing_members`; `tests/test_docker_bootstrap_repair.py::BootstrapRepairTests::test_success_requires_every_inventory_and_provenance_member`; `tests/test_docker_bootstrap_repair.py::BootstrapRepairTests::test_permission_archive_and_output_failures_are_not_missing`; `tests/test_docker_bootstrap_repair.py::BootstrapRepairTests::test_stopped_failure_is_primary_before_success_only_exports_or_commit`; actual production exporter with tiny synthetic regular tar bytes, not real Docker/native acceptance |
| Secondary errors / identity | `tests/test_docker_bootstrap_repair.py::BootstrapRepairTests::test_reinspection_ownership_drift_never_reads_logs_or_members`; `tests/test_docker_bootstrap_repair.py::BootstrapRepairTests::test_primary_failure_survives_secondary_cleanup_evidence_write`; `tests/test_docker_bootstrap_repair.py::BootstrapRepairTests::test_final_diagnostic_error_is_secondary_unless_no_primary`; `tests/test_docker_bootstrap_repair.py::BootstrapRepairTests::test_all_stopped_failure_kinds_refuse_before_rootfs_commit`; no blind image removal or primary-error replacement |
| Bounded uncompressed logging | `tests/test_docker_builder.py::BuilderContractTests::test_bootstrap_command_requires_exact_uncompressed_bounded_local_logs`; `tests/test_docker_builder.py::BuilderContractTests::test_bootstrap_inspection_refuses_missing_compressed_extra_or_expanded_logs`; `tests/test_docker_acceptance.py::DockerContractTests::test_acceptance_command_requires_exact_uncompressed_bounded_local_logs`; `tests/test_docker_acceptance.py::DockerContractTests::test_acceptance_inspection_refuses_missing_compressed_extra_or_expanded_logs`; exact local/max-size=4m/max-file=1/compress=false, no daemon-default or limit change |
| Start/log diagnostic preservation | `tests/test_docker_builder.py::BuilderContractTests::test_bootstrap_stopped_error_survives_log_failure_and_owned_teardown`; `tests/test_docker_acceptance.py::DockerLifecycleTests::test_acceptance_stopped_error_survives_log_failure_and_owned_teardown`; actual stopped-state export seam with synthetic Docker state, not a new hosted success or native receipt |
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
