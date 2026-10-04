# Bounded read-only discovery evidence

`network_query` supports `view=unresolved`. This is an evidence page, NOT a device
inventory or a new collection path. It lists original collector observations
joined to their immutable batch, including unqualified cached data and originals
whose identity has since resolved. Check `identity_state` and qualification; a
NULL original `entity_id` alone never means unresolved identity.

## Request contract

Only `view`, optional `address`, optional `batch_id`, `limit`, and `offset` are
accepted for this view. Filters intersect. No device ID is required.

- `address`: exact canonical unscoped IPv4/IPv6 literal. No CIDRs, hostnames,
  zone suffixes, normalized alternatives, wildcards or free text. The filter
  selects address-subject observations whose stored value contains that address;
  it does not search other fields or derive identity from an IP.
- `batch_id`: exact stored ID, 1–64 ASCII characters matching
  `[A-Za-z0-9][A-Za-z0-9_-]{0,63}`. Unknown IDs fail, including on a missing store.
  An existing empty/failed batch returns an empty page. A foreign-context batch
  is valid read-only knowledge when the operator explicitly shares that store.
- `limit`: integer 1–100, or the lower current `limits.result_count` ceiling;
  default is that ceiling. Booleans/fractions/coercions fail.
- `offset`: integer 0–10000, or the lower current `limits.page_offset` ceiling;
  default 0. Advance offset by the returned page size while `has_more=true`.
- `batch_id` is rejected on the other views. Other inventory/history filters are
  rejected on this view. No SQL, paths, commands, source, policy or grants inputs.

Ordering is `observed_at DESC, id ASC`; immutable unique IDs break timestamp ties.
Fetch limit+1 before shaping results, return at most limit, and set `has_more`
exactly from the extra row. Duplicates are separate historical observations, not
silently deduplicated devices/responders. Each invocation has one read snapshot;
concurrent appends can shift offset pages between invocations (not a cursor or a
cross-request snapshot guarantee).

The response has `view`, `evidence`, `limit`, `offset`, `has_more`,
`discovery_performed=false`, and an explicit historical-only reachability message.
A missing store gives the same empty shape and never creates directories/files.
The serialized byte cap also applies to empty responses.

## Evidence and provenance

Each evidence item exposes:

- Original observation `id`, `subject_kind`, typed `subject_anchor`,
  `entity_id=null`, `address` (address subjects only), `field` and decoded `value`.
  An unresolved anchor is a collector label, not a stable device/interface ID.
- `source`, `confidence`, `evidence_kind`, `qualified`, `observed_at`, explanation
  and neighbor state. Qualification is stored native evidence, not a tool flag.
- `freshness`: `fresh` for qualified observed data from now minus
  `stale_after_days` through now, inclusive; `stale` when strictly older; `future`
  if newer than the reader's clock; `unqualified` for cached/non-observed data.
  This classification never refreshes any stored timestamp or establishes live
  connectivity. Cached REACHABLE neighbors remain unqualified.
- `historical_responder_evidence`: qualified observed ping responses, or SSH
  device-subject response evidence. Local interface configuration and SSH address/
  interface inventory do NOT prove a response from each stored IP. Even true means
  response evidence at its recorded time, not currently reachable.
- `batch`: ID, collector, source, policy_context, local_policy_context,
  scope_kind/name/value, start/end time, original completion, whole-batch
  probe_summary and scope_absence_eligible. Summaries count all legacy V1 outcomes
  and none/local_host/exact_network/exact_target coverage independently of page
  size, including additive `not_started` from serial /28 collection. Address-level
  address_count/address_outcome_counts exclude the synthetic scope probe;
  aggregate-only historical records do not invent address counts from the CIDR.
  Complete/partial/failed is shown unchanged; a positive row in a partial batch
  does not attest full subnet coverage. Legacy per-address /24 and /25 records
  remain readable; old timeout ambiguity is not retroactively reclassified.
- `probe`: stored ID/name, outcome/diagnostic, coverage_kind/value, start/end time
  and absence eligibility. Local-host and exact-network/target coverage differ.
  A scope-coverage probe is counted in the batch total, not an additional host.
- `application`: this batch's stored application ID, batch_id, applied_at, or
  null if never applied; original identity_reason/candidate_device_ids and
  resolved_device_ids; optional latest same-subject `lineage` as described below.
- `current_address_candidate_device_ids` and `address_ownership_conflict`:
  bounded current canonical assignment candidates, separately from identity
  lineage. Two owners are an explicit address conflict. Even one owner does NOT
  attest that a MAC-less historical ping response came from that device.

An eligible complete ping batch supports only “not observed in that exact run,”
not offline/deleted. Partial/failed/passive batches cannot prove broad absence.
This view preserves coverage context; it never applies absence or changes state.

## Identity and subsequent lineage

Historical originals remain visible, including resolved ones. Attached copies
are not duplicated into this evidence page. The state vocabulary is:

| identity_state | Meaning |
| --- | --- |
| never_reconciled | No application of this batch and no eligible later same-subject application |
| reconciled_unresolved | Saved application identifies this evidence as unresolved, with no candidates |
| reconciled_conflicting | Saved unresolved candidates or multiple resolved device copies prevent unique identity |
| resolved_in_batch | An attached copy from this application resolves this original to one device |
| applied_without_identity_result | Application exists but no saved unresolved reason or attached identity copy explains this row; not silently called unresolved |
| subsequently_resolved | Latest eligible same-subject application has a unique attached identity copy |
| subsequently_conflicting | Latest eligible same-subject application has identity candidates/multiple resolved devices |
| subsequently_unresolved | Latest eligible same-subject application remains unresolved without candidates |
| subsequent_identity_unknown | Latest eligible application lacks usable identity outcome |

`identity_reason`, `candidate_device_ids`, `resolved_device_ids` and `application`
describe the ORIGINAL batch. `lineage` separately includes the latest eligible
application ID/batch/time, its state/reason/candidates/resolved_device_ids. Thus
subsequently_resolved can retain the original unresolved reason without lying
about either historical outcome. A subsequent conflict supersedes a prior
resolution in the displayed state, not in immutable history.

Lineage requires exact stored subject_kind and typed subject_anchor equality
AND the SAME origin policy_context. Original-row copy proof additionally matches
field, value and probe. Later evidence must have an observed_at at least as new
as the original. An already-applied original requires a later application append
sequence; a never-applied original requires a subsequently collected batch. The
latest eligible application append sequence is deterministic even when timestamps
tie. Unresolved collector labels additionally require equal field/value, preventing
label reuse across different addresses. An IP match with a new MAC is NEVER
same-subject lineage. Such address candidates are shown separately. This is
read-only interpretation of stored lineage, not reconciliation or an identity
authorization engine. Retired/known/stale devices are not reactivated by reading.

## Bounds and trust

Pages and per-row candidate/lineage detail are capped by result_count. Oversized
identity detail fails instead of truncating conflicts. Stored JSON/text evidence
payloads and saved receipts are bounded before JSON parsing; oversized payloads
refuse without returning a truncated value. Saved receipts are bounded
before JSON parsing by the reader's output_bytes; a lowered byte cap may refuse
older larger receipts even for limit=1. Final JSON uses that same output cap.
Saved unresolved entries require string evidence_id/reason and an optional list
of string candidate_device_ids; malformed entries fail with a controlled query
error, for original applications and subsequent lineage alike. No receipt is
rewritten or repaired by reading it.
One operation_timeout_seconds budget covers the read, with SQLite progress
interruption during long statements, bounded busy waits, Python phase checks and
snapshot cleanup on failure. No unbounded receipt or lineage walk is exposed.
No new schema/version/index/migration, hidden reconcile, policy edit, audit event,
collection, export or access grant occurs. Existing schema-v1 files work unchanged.

Shared-store foreign-profile observations remain visible, labeled by their batch's
origin and `local_policy_context=false`. They do not become the reader's last
local discovery and do not grant collection, SSH inspection or reconciliation
permission. The reader's policy is reloaded by native tool/CLI handlers. A separate
nonshared store cannot reveal the other store's observations. Same-UID processes
and trusted local SQLite producers remain outside an OS isolation guarantee.

## Zero devices does not mean zero evidence

After MAC-less ping responses, exact reconciliation can legitimately report no
new canonical devices and positive unresolved evidence. Ask for evidence, not
invented owners/names/types/links or access:

    hermes network-atlas query --query-json '{"view":"unresolved","limit":10}'
    hermes network-atlas query --query-json '{"view":"unresolved","address":"192.0.2.10","limit":10}'
    hermes network-atlas query --query-json '{"view":"unresolved","batch_id":"<returned-batch-id>","limit":10,"offset":0}'

The model equivalent is `network_query` with the same JSON arguments. The slash
inventory show command still requires a canonical ID; use the tool or query CLI
for unresolved evidence. Examples use synthetic addresses, not scan permission.
Filter interpretation of returned items by identity_state and
historical_responder_evidence to answer “which responding addresses remain
unidentified”; do not count all originals as unresolved responders.

Executable evidence is `tests/test_unresolved.py::UnresolvedEvidenceTests`, plus
real native schema/dispatch/CLI and restart comparisons in runtime smoke and
cumulative acceptance. All tests are synthetic and network-denied. Live behavior,
publication and deployment are not proved by these fixtures.
