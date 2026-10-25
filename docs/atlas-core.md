# Atlas Core

Atlas stores structured knowledge, provenance and history in SQLite. Explicit
collection and reconciliation are covered in [Local Discovery](local-discovery.md)
and [Authorized SSH Inspection](authorized-ssh-inspection.md).

## Storage and profile boundary

Each invocation reads `ctx.get_config("policy", {})` and resolves the current
profile home through native `get_hermes_home()` for ownership and exports.
Public `plugin_data_dir("network-atlas")` independently supplies the default
`atlas.sqlite3` location. Symlinking `plugin-data` or its `network-atlas` subdirectory
relocates data without changing profile identity. Hermes owns settings fallback, caching
and worker snapshots; Atlas validates the returned domain values. Empty settings
mean empty allowlists. No model update can change configuration. Only the explicit
operator converter writes native settings; see [conversion](operator-guide.md#convert-legacy-policy-and-storage).

`store.shared_sqlite_path` explicitly selects an absolute shared SQLite file.
Only knowledge is shared. Alias associations carry the current invocation profile's
resolved home as their policy context. Another profile cannot obtain inspection
permission or use its identically spelled alias as an identity anchor simply by
reading that shared store. Ambiguous alias associations authorize no device.
Authorization is always current local policy, not an access result or atlas fact.
Native storage resolution can create managed directories, but no read creates or
migrates the database or changes settings. Store remains Atlas's relational,
read-only/deadline/transaction boundary rather than a second JSON state store.

The original schema is in `storage_schema.sql`; schema 2 adds endpoint projection
through `storage_endpoints.sql`, and schema 3 adds immutable successor reservations
through `storage_continuations.sql`. `storage.py` initializes or additively upgrades
schema 1/2 transactionally under a bounded write lock. Read-only opens support
schema 1/2 without migration. A nonempty unversioned database or
future version is refused without repair/downgrade. See endpoint-checks.md for
upgrade compatibility. Foreign keys are enabled for
every connection. Write transactions use BEGIN IMMEDIATE, bounded busy waits,
and rollback even on interruption. WAL supports simultaneous readers. SQLite
may maintain private WAL/shared-memory coordination files; queries do not mutate
canonical rows, initialize/migrate the store, or collect data.

Atlas-created directories are 0700, database/WAL/journal files and generated exports 0600;
Hermes-managed storage directories follow native defaults. Keep the profile private.
Existing shared parent directories are not chmodded. The database file itself
is made private on writable open. Existing operator config is not silently
chmodded or rewritten. Same-UID processes and trusted native code are not isolated
by file modes or SQLite. Never publish an atlas, private config, or private exports.

Tables cover devices, interfaces, current/historical address assignments,
relations, context-qualified aliases, access evidence, observations, immutable
batches/probes, unique application/result metadata, and audit events. Triggers
reject updates/deletes of observations, batches, probes, applications, access
evidence, and audit events. Evidence insertions and their events are atomic.
Typed batch storage validates counts, times,
allowlisted scope, per-probe outcomes, neighbor state and address scope before
inserting anything, and never rewrites canonical identities.

## Operator updates and manual seeding

Use the native local CLI to record operator-supplied knowledge. The following
names and addresses are synthetic; select your profile with `hermes -p PROFILE`.

    hermes network-atlas create --name "Synthetic router"

This returns a generated stable device_id. Creation records user/user_supplied
knowledge, status known, and no artificial first_seen/last_seen/last_checked.
Use returned IDs verbatim in subsequent commands:

    hermes network-atlas update --device-id <device-id> --field device_type --value-json '"router"'
    hermes network-atlas update --device-id <device-id> --field description --value-json '"Operator assertion"'
    hermes network-atlas interface --device-id <device-id> --name eth0 --mac 00:11:22:33:44:55 --interface-type ethernet
    hermes network-atlas address --interface-id <interface-id> --address 192.0.2.10 --prefix-length 24
    hermes network-atlas end-address --assignment-id <assignment-id>
    hermes network-atlas update --device-id <device-id> --field retired --value-json true

Reactivation uses retired=false through the same operator route. Relationships
use a typed value, never free-form diagram text:

    hermes network-atlas update --device-id <source-id> --field relationship --value-json '{"target_device":"<target-id>","relationship_type":"hosted_on"}'

Optional source_interface/target_interface must reference existing interfaces
belonging to the corresponding device. Self edges and unknown endpoints fail.
Missing relationship references name `value.target_device`,
`value.source_interface` or `value.target_interface`; the valid subject ID is unchanged.
Supported types: physical, virtual, parent, bridge_member, routes_via, hosted_on,
unknown. Every stored edge retains source/confidence/time. An alias association:

    hermes network-atlas update --device-id <device-id> --field ssh_alias --value-json '"lab-router"'

requires current local policy to already authorize lab-router for Atlas inspection.
It cannot grant or enlarge a permission. Association is additive; to revoke
inspection authority, the operator removes/disables the permission in policy.
Model alias suggestions remain inference and do not become identity anchors or
access associations. No inspection has happened simply because an alias is known.

`validate-update` remains a compatibility/dry validation command: its receipts
still say applied=false/persisted=false and do not verify entity existence. The
applying `update` command checks existence and returns operation/observation/event
IDs. `/network update` still refuses because the inspected slash API cannot attest
operator origin. The native local CLI is a trusted-local-route convention, not
cryptographic proof of a human. Other same-UID tools/processes can invoke it;
this is outside the Network Atlas model-tool boundary, not an OS sandbox.

## Model updates, provenance, and identity

`network_update` requires device_id, field, value, and a nonempty explanation.
It records inference/inferred regardless of origin-like runtime kwargs. Source,
confidence, operator flags, permissions, commands, and policy inputs are rejected.
Retirement/reactivation is operator-only. A successful inference receipt means
its evidence was persisted, not that it became a canonical fact.

Canonical values are selected per entity and field, not by one global source rank:

| Field family | Highest to lowest precedence |
| --- | --- |
| Friendly name, description, device type, retirement/reactivation | Operator assertion only |
| Hostname, OS, interface facts, other descriptive facts | Fresh qualified direct evidence; operator assertion; aged qualified direct evidence; inference |
| Relationship, SSH alias assertion | Operator assertion; qualified direct evidence; inference |
| Collection/SSH permissions, probe definitions, limits, sharing | Current local operator configuration only; never atlas assertions |

Alias assertions still require the policy and identity checks above. Relationship
endpoints must be valid; no assertion manufactures a physical link. Within a source,
later assertions supersede older assertions; same-time native appends use append order.
Across equally ranked sources, differing values remain a conflict and no winner
is manufactured. Unqualified evidence is not direct truth. History retains
superseded assertions, explanations, and sources. Qualified evidence/time comes
from native code, never model arguments. Future collectors must validate scope
and same-subject evidence before invoking native core primitives.

UUIDs are independent of names/IPs. A stable unicast globally administered MAC
anchors an interface first. Local/randomized, multicast, zero, or colliding MACs
remain uncertain. Explicit operator association or direct local same-host evidence
can join interfaces to a device. Identical IPs or hostnames never merge devices.
Current IP collisions expose all bounded candidate owners. New address assertions
preserve other valid IPv4/IPv6 assignments; only explicit end-address closes an
assignment. Historical addresses and their provenance remain queryable. Address
first_seen/last_seen columns track assignment evidence/assertion effective times,
not proof of reachability; device sighting clocks advance only on qualifying
positive direct evidence. Operator assertions and inference do not advance device
sighting/check clocks. Never-seen devices remain known. Freshness is computed
read-only from UTC time and stale_after_days (default 14 days); retirement is sticky.

## Read-only query and maps

`network_query` defaults to a device page. It supports view=devices/status/history/unresolved,
device_id, name (friendly name or hostname), address (current assignments),
device_type, status, access_method=ssh, relationship, related_to, text, limit and
offset. Filters intersect; relationship queries match either endpoint. Inferred
supported relationships remain visibly inferred. Text searches canonical values
literally, not SQL or an embedded query language. Conflicting fields have no
canonical value and do not match a text/value filter. History requires device_id
and returns immutable observation pages including losing operator assertions and
inference explanations. Scalar selection provenance is in fields.evidence.

`view=unresolved` is a separate original-evidence page, accepting only exact
address, optional batch_id and pagination. It does not require a canonical ID.
It includes original resolved history with explicit application/identity lineage,
not a naive NULL-entity unresolved predicate. Qualified historical responses,
unqualified caches, freshness, origin/policy_context and batch/probe coverage stay
visible; shared foreign knowledge never transfers authority. Zero canonical
devices can coexist with positive response evidence. See the complete
[evidence request/response and schema-v1 lineage contract](unresolved-evidence.md).

    hermes network-atlas query --query-json '{"access_method":"ssh","limit":10}'
    hermes network-atlas query --query-json '{"view":"history","device_id":"<device-id>","limit":10}'
    /network status
    /network show <device-id>
    /network map markdown

Queries are parameterized, explicitly read-only, and use a consistent snapshot.
Limit <=100 and offset <=10000, or lower local limits. Strings <=4096 characters
(or lower policy limits). Child evidence per entity is bounded too: oversized
entity details fail explicitly rather than silently omit conflicts; history can
still be paginated. Successful tool and CLI responses are bounded by output_bytes
after JSON escaping and UTF-8 encoding, including a trailing newline. Mutation
receipts are checked before commit; overflow rolls back the assertion and event
together (including alias, retirement, and relationship changes). Fixed-shape
interface/address receipts are checked before mutation. Validation-only and status
CLI responses are bounded too. Fixed refusal messages remain available even if
the operator sets a byte limit too small to hold an error envelope. Queries never discover.
Access answers separate "authorized for Atlas SSH inspection" from local-context
last-inspection success/failure/time. Config alone does not establish reachability.

Status reports `known_devices` as total inventory, `observed_devices` and
`stale_devices` as age-qualified subsets, and `status_counts` for known/retired
records too. Observed does not mean reachable now. `configured_scopes` lists each
current named CIDR and enabled discovery modes. `last_discovery` is the latest
local-profile LAN batch, distinct from `last_collection` (which can be SSH) and
`last_inspection`. It includes immutable scope, start/end time, complete/partial/
failed qualification, whole-batch `probe_summary`, bounded per-probe detail, and
`scope_absence_eligible`. Status totals are independent of inventory pagination:
even a /24 batch with 257 probes remains reportable with `result_count=1`.
`probe_summary` includes `total_count`, fixed-enum `outcome_counts` and
`coverage_counts` (none/local_host/exact_network/exact_target), `failure_count`
and `absence_eligible_count`, aggregated over ALL stored probes. These counts
describe probe outcomes, not reachable device counts; the synthetic scope-coverage
probe is included. Absence qualification likewise uses the whole batch, never
just displayed details.

`address_count` and fixed-enum `address_outcome_counts` separately count native
ping_<numeric-index> address checks, excluding the synthetic ping_coverage record.
They apply to new chunked scans and legacy per-address /24 and /25 batches; these
are checks, not responding-host/device counts. Aggregate-only legacy batches and
non-ping collectors have no such per-address records (zero), not CIDR-derived
invented checks. `not_started` is a non-success outcome, so it contributes to
failure_count and disqualifies absence like timeout. Legacy timeout diagnostics
remain unchanged and cannot retrospectively distinguish unstarted work.

`probes` is a sample capped at `limits.result_count`, not a complete list when
`omitted_count>0`. It orders failures first, then absence-eligible coverage, then
probe name, deterministically. `probe_summary.detail_limit`, `returned_count`,
`omitted_count` and `omitted_failure_count` make omitted detail explicit; even
undisplayed failures contribute to every outcome/coverage total. No failure is
silently presented as success. For example, /24 with one timeout has 257 probes,
255 successes and two failures (timeout plus unsuccessful scope coverage).
With detail_limit=1 it reports both failures in totals and one omitted failure.
For new chunked /24 discovery, one failed 16-address chunk has 240 address
successes, 16 unknown/failed checks, and unsuccessful synthetic scope coverage:
257 total probes but exactly 256 address checks. A success with diagnostic
completed_at_boundary remains a success; see local-discovery.md for bounds.
Status has no per-probe pagination; device history is NOT a route to batch probe
metadata. The original bounded collection receipt contains all per-probe outcome/
diagnostic entries at collection time. Inventory/history limits are unchanged,
and serialized public status responses still enforce `output_bytes` (too small
a byte ceiling refuses without mutation). `last_inspection` retains its separate
observation-bounded fixed-probe attempt evidence, not inventory pagination.
Even eligible ping absence means only not observed in that exact run. Shared
foreign batches do not claim a local last discovery. Availability flags and
`stage=v1` describe implemented code, not successful installation or connectivity.

`/network help` lists exact command arities and the trusted local operator update
route. Unknown commands/extra arguments return usage and apply nothing. Status,
show, map, discover, inspect and reconcile share the same validated model/CLI
core paths; slash updates still fail closed on unattested origin.

`network_map` supports text, markdown and mermaid plus export=true. CLI equivalent:

    hermes network-atlas map --format markdown --export

Only fixed profile-local exports/network_map.md and exports/network_map.mmd are
written. Rendering uses stored supported edges, stable ID ordering, escaped labels,
explicit provenance, stale/retired/isolated/uncertain states, and no regeneration
time. Ambiguous alias associations mark nodes uncertain in every format, including
Mermaid and fixed exports; text/Markdown name the unresolved aliases separately
from inspection authorization. No owner or permission is selected for a colliding
alias. Inference edges are dashed and labelled. No unknown physical connectivity
is invented. The complete map is capped by observations (default 4096 devices),
child detail limits, and output_bytes; overflow refuses instead of truncating a
node/edge silently. Every export attempt is audited before file writes, and a
completion event follows successful replacement. Each file replacement is atomic;
filesystem interruption between the two can leave mismatched generated files.
Regenerate both from SQLite to recover. Symlink export destinations are refused.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for isolated behavioral tests and
[SECURITY.md](../SECURITY.md) for the trust model and verification limits.
