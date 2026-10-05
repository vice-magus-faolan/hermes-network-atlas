# Contract gate decisions

This note makes the accepted addendum concrete for the serial V1 lane. It is not
an implementation claim for storage, reconciliation, or collectors. Those remain
owned by the existing Phase 1–3 cards. No generic framework or additional service.

The normative decisions below were approved at the scaffold gate. Historical
scaffold-only availability statements are not current feature claims: Phase 1
implementation/usage evidence is tracked in [Atlas Core](atlas-core.md) and
[Local Discovery](local-discovery.md) and
[Authorized SSH Inspection](authorized-ssh-inspection.md). Availability claims later in this document
record the original contract gate, not the current milestone's implementation.

## 1. Canonical facts and identity

Select facts per entity/field, never an entire device by one global source rank.
Retain all assertions and observations with source, confidence, effective/observed
UTC time, and inference explanation. Qualification is evidence, not source text.

| Field family | Highest to lowest selection | Disagreement handling |
| --- | --- | --- |
| canonical_name, description, explicit device_type override | operator assertion only | observations/proposals remain separate; absent operator value stays unset/unknown |
| retired/reactivation | explicit local operator action only | sticky until another operator action; rediscovery cannot reactivate |
| hostname, OS, interface name/type/state, address assignments | fresh qualified direct observation; operator assertion; aged qualified direct observation; inference | equal-tier disagreement remains conflict, not arbitrary winner; retain assertions separately even when superseded |
| relationship assertion | operator assertion; qualified direct evidence; inference | provenance and endpoint validation required; no fabricated edge; equal-tier disagreement stays conflict |
| ssh_alias association | existing profile-authorized alias only; operator association preferred to inference proposal | association is not permission; ambiguity remains unresolved |
| authorization, probe definitions, ceilings, sharing | current validated profile-local operator config only | no atlas fact or proposal can modify these |

Within the same source/entity/field, a later qualified observation supersedes its
older value while retaining history. Across different equally ranked sources,
disagreement stays a conflict even if timestamps differ. Sort conflicts by source,
effective time, then immutable observation ID for presentation only. Fresh means
qualified direct evidence no older than stale_after_days at the injected UTC clock;
rank never refreshes time. Treat missing effective time as unqualified, not fresh.
Address assignments are a set with per-assignment history, not a single device IPv4
field: seeing one new address does not close another valid address assignment.
Operator assertions and inference never advance first_seen/last_seen/last_checked.

Device IDs are generated UUIDs independent of names/addresses. Update device_id
accepts an existing stable ID (the scaffold validates syntax only; Phase 1 must
check existence). A configured SSH alias anchors a device inside a policy context
(profile home plus alias); a matching string from a different profile is not an
automatic identity anchor. A stable, noncolliding MAC anchors an interface first.
Joining another interface to a device requires direct same-host evidence or an
operator association. Randomized/colliding MACs are unresolved evidence, not merge
keys. IP/hostname alone never merges records. New MAC at an existing address is an
ownership conflict. Remote neighbor entries represent neighbors, not the inspected
host's own interfaces. Retain aliases, ambiguous candidate IDs, and conflicts.

## 2. Immutable collector and reconciliation records (schema version 1)

Implement these as small SQLite tables/typed records, not event sourcing. All
record IDs below are generated UUIDs; references are validated foreign keys. Times
are timezone-aware UTC serialized as RFC3339 with Z. IDs and evidence are code-owned,
not an LLM-import API. The following is the normative field contract:

    Batch
      id, schema_version=1, collector=[local_passive,ping,ssh]
      source (code-owned collector or ssh:<configured-alias>)
      policy_context (profile home identity; not transferable authority)
      scope_kind=[network,ssh_alias], scope_name, scope_value
      started_at, ended_at, completion=[complete,partial,failed]
      probes: ordered immutable tuple of ProbeOutcome
      observations: ordered immutable tuple of Observation

    ProbeOutcome
      id, probe_name (fixed code-owned identifier)
      outcome=[success,unavailable,timeout,output_limit,command_failed,parse_failed,not_started]
      started_at, ended_at
      coverage_kind=[local_host,exact_network,exact_target,none]
      coverage_value (exact configured CIDR/alias, never derived expansion)
      evidence_kind=[local_interface,cached_neighbor,ping_response,ssh_response,none]
      absence_eligible (derived by collector validation, never caller-selected)
      bounded diagnostic_code (no raw stdout/stderr, credentials, or shell text)

    Observation
      id, probe_id, subject_kind=[device,interface,address,relationship]
      subject_anchor (typed interface MAC / context-qualified alias / unresolved ID)
      field, value (validated bounded scalar or explicit typed relation/address)
      source, confidence=[observed,inferred,user_supplied]
      observed_at, evidence_kind, explanation (required for inference)
      neighbor_state (only when relevant; preserve cached/failed states)

    ReconciliationResult
      id, batch_id (UNIQUE), schema_version=1, applied_at
      new, changed, unchanged, missing, conflicting
        (each immutable ordered tuple of stable entity IDs / typed field deltas)
      unresolved (immutable ordered tuple of evidence IDs and candidate IDs)
      audit_event_ids (immutable ordered tuple)

Batch/observations/probe outcomes are inserted once atomically, never edited after
insertion. Collection failure inserts bounded failure evidence, never partial
canonical state. Applied eligibility/result is a separate unique application row,
not a mutation to the immutable batch. Failed/partial batches can supply validated
positive evidence; they cannot assert broad absence. Reconciliation writes current
facts, histories, status transitions, immutable result, and events in one explicit
transaction. Retry returns the stored result byte-for-byte without new events.
Reject inconsistent times/outcomes, out-of-scope observations, unknown enums, and
excessive counts before insertion. No subprocess executes under a write lock.

Issue #2 adds not_started for budget exhaustion before child spawn. timeout now
means started work exceeded its effective deadline, not an unreachable host.
success/completed_at_boundary retains a valid completed transport after parsing
crossed the transport deadline; whole-operation persistence still must succeed.
All are native diagnostics, never authority from source XML. Schema version 1
and immutable legacy records are retained: no columns/history are rewritten.
Older binaries unaware of the additive outcome enum fail closed when reading new
not_started batches; update shared-store readers deliberately before consuming
these records. Legacy operation_deadline_exceeded timeouts cannot retrospectively
prove whether a child started; retain their ambiguity rather than rewriting them.
Status probe_summary adds address_count and address_outcome_counts for native
ping_<numeric-index> records only, excluding ping_coverage. Aggregate-only legacy
evidence reports zero such records instead of inventing checks from its CIDR.

## 3. Freshness and absence

Local successful interface metadata qualifies for that local interface only.
Passive remote neighbors (including cached REACHABLE entries) supply known-address
and observed-in-batch evidence, NOT proven present-time reachability or an inventory.
INCOMPLETE/FAILED entries never advance last_seen. Ping/SSH successful positive
responses qualify last_seen for that subject; failed checks never do. first_seen is
the first qualifying positive time. last_checked advances only for relevant
successfully executed/parsed checks. Optional probe failure does not invalidate a
different successful positive probe or make the whole host disappear.

Only a complete, successfully parsed ping batch may assert “not observed in this
run” for previously associated addresses inside its EXACT configured scope. This
is not “offline” and never deletion. Partial/failed batches and passive neighbors
cannot supply absence. A full exact-target successful check can update that target's
last_checked without implying absence of its unrelated interfaces/addresses.
Previously observed devices become stale only after the configured age threshold
(default 14 days). Never-seen assertions remain known/unknown. Query/map computes
age read-only; reconciliation persists transitions/events. Retirement stays sticky.

## 4. Configuration, ceilings, and sharing

Authoritative policy file: get_hermes_home()/network-atlas/config.yaml, with strict
version 1 keys implemented in config.py. Missing file is deny-all. An existing
empty/null/malformed file is invalid, not an implicit reset. YAML 1.2 safe parser;
booleans must be real true/false values, not integers/strings. Unknown nested keys,
duplicate keys, noncanonical CIDRs, alias injection, and coercions fail closed.
No plugin surface is registered before this policy validates. Every invocation
reloads the registration profile's policy; stale grants cannot survive edits.

Use networks.<name>.{cidr,discovery.{passive,ping}}, ssh.{enabled,hosts.<name>.
{alias,inspect}}, limits.<name>, retention.stale_after_days, render.
{include_addresses,include_interfaces}, and store.shared_sqlite_path. This fixes
the original example's timeout placement: all numerical ceilings live in limits,
not discovery. Policy objects and nested sequences are immutable snapshots.

Issue #6 adds only network-local discovery.icmp_echo (strict bool, default false)
and discovery.tcp_ports (list of 0..4 distinct integers in 1..65535, sorted into
an immutable tuple; default [80,443]). TCP 4403 is rejected with no override.
ICMP requires ping authorization; active policy must select at least one method.
No global/caller/atlas-derived method grants. Stage 1 validates these fields but
refuses nonlegacy ping with host_discovery_transport_staged before effects.
Passive and legacy traffic are unchanged. Old binaries reject additive keys;
coordinate shared readers deliberately. See host-discovery-policy.md for the
datagram-only feasibility decision, helper rejection, combined budgets and
schema-version-1 additive method/aggregate provenance contract. This amendment
does not rewrite any historical batch or infer services/identity from ports.

| Bound | Default/hard V1 maximum |
| --- | --- |
| command_timeout_seconds | 15 |
| host_timeout_seconds | 10 |
| operation_timeout_seconds | 120 |
| concurrent_probes | 4 |
| output_bytes (combined stdout/stderr per command) | 1,048,576 |
| observations per batch / probe outcomes per batch | 4,096 each |
| input_chars per string | 4,096 |
| result_count per query page | 100 |
| page_offset | 10,000 |
| busy_timeout_ms | 5,000 |
| configuration bytes | 65,536 |
| configured networks / SSH targets | 32 each |
| names, IDs, configured aliases | 64 ASCII characters |
| IPv4 addresses per configured range | 256 |

limits allows positive integer reductions only; boolean, fractional, NaN/infinite,
zero, negative, and over-ceiling values are rejected. Page offset can be zero at
invocation; the policy ceiling itself must be positive. stale_after_days is a
positive integer with default 14 and maximum 3650. IPv6 is passive/storage only.
This V1 implementation rejects IPv4 scopes broader than /24 even in passive mode;
no silent slicing. Fixed collector argv and deadlines/output enforcement land in
the corresponding transport cards. Bounds in this scaffold do not claim those
future subprocess implementations already exist.

Default database: profile home/network-atlas/atlas.sqlite3. Shared path requires
explicit absolute store.shared_sqlite_path ending in .sqlite3; no caller-chosen
paths. Shared knowledge does not share grants: every profile's access answers and
inspection use its OWN config. Exports always stay profile-local at
exports/network_map.md and exports/network_map.mmd. Shared DB readers must never
trust alias/permission text from another profile. SQLite and file modes are not
same-UID isolation. Phase 1 creates private directories (0700), DB/config/WAL/audit
and exports (0600), handles transactions/foreign keys/busy bounds, and tests two
profiles sharing facts without sharing inspection permission. This scaffold
loads policy read-only and creates no database or export.

## 5. Operator attestation and native compatibility

Current Hermes APIs were inspected at f42f579cf8bac4918ac9599bece71618afadd846,
v0.21.4+canary.20260930T070235Z. Official docs checked on 2026-09-30:
https://hermes-agent.nousresearch.com/docs/developer-guide/plugins and
https://hermes-agent.nousresearch.com/docs/user-guide/features/plugins.
The docs advertise directory plugin discovery, register_tool, register_command,
and register_cli_command. Installed APIs are the executable contract; docs are
not evidence that schema validation, origin attestation, or sandboxing occurs.

Reconnaissance locations in that exact runtime:
- hermes_cli/plugins.py:270 get_config reads one relative settings key, not an
  entire strict operator policy; :457 native tool registration; :664 native CLI
  argparse registration; :678 slash handler accepts only raw_args.
- cli.py:1296 and gateway/run_inbound.py:1106 invoke slash handlers with raw text;
  neither supplies verified direct-operator attestation to the handler.
- hermes_cli/plugins_loader.py:392 manifest config_schema warns only; cannot
  enforce policy. Network Atlas validates its own complete policy before register.
- tools/registry.py:893 dispatch does not enforce our JSON schema; handlers must
  reject unknown arguments/types themselves.
- hermes_cli/plugins_manifest.py:150 dependency declarations are surfaced, not
  installed by discovery; requires_hermes is gated by the native loader.

Therefore all network_update tool proposals are inference, with a required
explanation. No source/confidence/token/operator/policy arguments exist, and
unknown arguments fail at the handler as well as the schema. Runtime kwargs do
not promote provenance. /network status works; /network update ALWAYS refuses
user_supplied writes on this runtime. Equivalent trusted operator route:
hermes network-atlas validate-update. This validation-only CLI constructs a user /
user_supplied envelope itself, including retirement/reactivation booleans. Phase 1
must wire the same trusted native CLI path into audited updates and rename/add
its applying command; validation receipts now say applied=false, persisted=false.
This is NOT evidence that atlas updates already persist.

The operator/local native code is trusted. The local CLI is not cryptographic human
attestation or an OS sandbox: a same-UID process or another Hermes terminal tool
can invoke it. It is intentionally outside the Atlas model-tool argument surface,
exactly the conservative local-route fallback in addendum section 5. No credentials
or attestation tokens enter model arguments. If stronger origin isolation is later
required, it needs a steward decision, not a caller-selected flag.

Supported plugin syntax: Python >=3.11,<3.15; declared Hermes >=0.21.4,<0.22.
Real native smoke has been exercised on the exact canary above with Python 3.14.7;
other runtime versions are not claimed tested. Keep this narrow compatibility
range until additional exact-runtime checks pass. Native dependency declaration:
ruamel.yaml>=0.18.16,<0.19 (already present in tested Hermes). This upper-bounded
range accommodates Hermes's exact host pin without adding another YAML package.
Use supported plugin dependency admission/PM in an isolated test installation;
never pip-edit the production runtime. Discovery does not install dependencies.

## 6. Evidence and remaining gates

Canonical verifier requires behavioral tests AND actual isolated Hermes discovery,
real registry/schema/dispatch, native slash/CLI registration and attestation split,
disabled selection, invalid-config registration refusal, reload rejection, and
unload cleanup. The runtime smoke copies only plugin source into a synthetic
scratch home and sets an explicit plugins.enabled selection. It blocks network
connect/bind/DNS calls and does not import bootstrap/PM or repair dependencies.
No live profile data or actual atlas is copied. No fake registry acceptance.

This is supported directory installation plus native loader opt-in behavior,
not a claim that the PM-managed `hermes plugins install/enable` command cycle has
been exercised. Those commands can resolve/publish dependency environments;
full isolated admission/CLI command-cycle testing remains an explicit A01 gate
for cumulative V1 acceptance. Do not weaken that gate or count these smoke checks
as final installation/restart acceptance. Persistence, collectors, reconciliation,
map, and A02–A13 cumulative scenario still belong to subsequent cards.
