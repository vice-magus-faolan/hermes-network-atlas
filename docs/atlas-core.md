# Atlas Core (Phase 1)

This guide describes the Phase 1 structured-knowledge milestone. Phase 2 now adds
explicit discovery and reconciliation; see [Local Discovery](local-discovery.md).
Phase 3 adds [Authorized SSH Inspection](authorized-ssh-inspection.md).
Service enumeration, live installation and gateway changes are not part of these
milestones. Independent review and cumulative acceptance retain their gates.

## Storage and profile boundary

Registration resolves `get_hermes_home()` and validates the entire policy before
registering any surface. Every invocation reloads that profile's policy. The
default database is `<profile-home>/network-atlas/atlas.sqlite3`. Missing policy
means empty allowlists. Existing empty/invalid policy fails closed. Configuration
is read-only to the plugin; the operator must maintain it with mode 0600 in a
private directory. No model update can change configuration.

`store.shared_sqlite_path` explicitly selects an absolute shared SQLite file.
Only knowledge is shared. Alias associations carry the registration profile's
resolved home as their policy context. Another profile cannot obtain inspection
permission or use its identically spelled alias as an identity anchor simply by
reading that shared store. Ambiguous alias associations authorize no device.
Authorization is always current local policy, not an access result or atlas fact.
No database read creates a second profile directory or changes its configuration.

Schema version 1 is in `storage_schema.sql`; `storage.py` initializes an empty
file transactionally under a bounded write lock. A nonempty unversioned database
or future version is refused without repair/downgrade. There is no migration
from a prior persisted atlas: the parent scaffold never created one. Future
versions must add an explicit reviewed migration. Foreign keys are enabled for
every connection. Write transactions use BEGIN IMMEDIATE, bounded busy waits,
and rollback even on interruption. WAL supports simultaneous readers. SQLite
may maintain private WAL/shared-memory coordination files; queries do not mutate
canonical rows, initialize/migrate the store, or collect data.

New directories are 0700, database/WAL/journal files and generated exports 0600.
Existing shared parent directories are not chmodded. The database file itself
is made private on writable open. Existing operator config is not silently
chmodded or rewritten. Same-UID processes and trusted native code are not isolated
by file modes or SQLite. Never publish an atlas, private config, or private exports.

Tables cover devices, interfaces, current/historical address assignments,
relations, context-qualified aliases, access evidence, observations, immutable
batches/probes, unique application/result metadata, and audit events. Triggers
reject updates/deletes of observations, batches, probes, applications, access
evidence, and audit events. Evidence insertions and their events are atomic.
Application storage was established in Phase 1 and is now used by Phase 2;
that algorithm/evidence is documented separately. Typed batch storage validates counts, times,
allowlisted scope, per-probe outcomes, neighbor state and address scope before
inserting anything, and never rewrites canonical identities.

## Operator updates and manual seeding

These commands describe the native local CLI registered with Hermes, not a grant
to install or seed a live profile. Use an explicitly isolated home for examples.
All names and example addresses below are synthetic.

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

The per-field table in `contract-decisions.md` is implemented by `facts.py`:
operator-friendly names/descriptions/type overrides remain operator-owned;
hostname/OS/interface facts prefer fresh qualified direct evidence, then user
assertions, aged qualified evidence, then inference. Within a source, later
assertions supersede older assertions; same-time native appends use append order.
Across equally ranked sources, differing values remain a conflict and no winner
is manufactured. Unqualified evidence is not direct truth. History retains
superseded assertions, explanations, and sources. Qualified evidence/time comes
from native code, never model arguments. Future collectors must validate scope
and same-subject evidence before invoking native core primitives.

UUIDs are independent of names/IPs. A stable unicast globally administered MAC
anchors an interface first. Local/randomized, multicast, zero, or colliding MACs
remain uncertain. Explicit operator same-device association joins interfaces in the core; Phase 2
also accepts direct local same-host evidence. Identical IPs or hostnames never merge devices.
Current IP collisions expose all bounded candidate owners. New address assertions
preserve other valid IPv4/IPv6 assignments; only explicit end-address closes an
assignment. Historical addresses and their provenance remain queryable. Address
first_seen/last_seen columns track assignment evidence/assertion effective times,
not proof of reachability; device sighting clocks advance only on qualifying
positive direct evidence. Never-seen devices remain known. Freshness is computed
read-only from an injected UTC clock and stale_after_days; retirement is sticky.

## Read-only query and maps

`network_query` defaults to a device page. It supports view=devices/status/history,
device_id, name (friendly name or hostname), address (current assignments),
device_type, status, access_method=ssh, relationship, related_to, text, limit and
offset. Filters intersect; relationship queries match either endpoint. Inferred
supported relationships remain visibly inferred. Text searches canonical values
literally, not SQL or an embedded query language. Conflicting fields have no
canonical value and do not match a text/value filter. History requires device_id
and returns immutable observation pages including losing operator assertions and
inference explanations. Scalar selection provenance is in fields.evidence.

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
failed qualification, bounded per-probe outcomes, and `scope_absence_eligible`.
Even eligible ping absence means only not observed in that exact run. Shared
foreign batches do not claim a local last discovery. Availability flags and
`stage=v1` describe implemented code, not executable installation, successful
connectivity, cumulative acceptance, publication or live activation.

`/network help` lists exact command arities and the trusted local operator update
route. Unknown commands/extra arguments return usage and apply nothing. Status,
show, map, discover, inspect and reconcile share the same validated model/CLI
core paths; slash updates still fail closed on unattested origin. Regression
evidence: `tests/test_commands.py::OperatorStatusTests`.

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

## Verification and evidence

Follow current cumulative setup prerequisites in operator-guide.md, then:

    python3 -m unittest discover -s tests -p test_core.py -v
    python3 -m unittest discover -s tests -p test_runtime.py -v
    python3 scripts/verify.py

Tests use synthetic scratch homes and never live data/networks. Native smoke
exercises supported directory discovery, all six registered tools, actual native
slash/CLI handlers, applying operator/inference persistence, policy revocation,
exports, and a second native process re-query/map without discovery. Independent
fresh-process storage tests also retain IDs, assignments, relations, history and
failed access evidence. The cumulative A01/A13 supported PM install/enable and
three-alias fixture scenario are now in tests/test_acceptance.py; see
operator-guide.md. Provider chat/live network validation is not claimed.

A02/A10: PersistenceTests and BatchTests (reopen, FK, immutable history, rollback,
interrupts, bounded concurrent writers, schema refusal, atomic batch insertion,
unique/immutable application metadata). A04/A05: IdentityAndProvenanceTests.
A06: QueryUpdateMapTests plus existing boundary tests, including lowered response
limits, exact byte boundaries, Unicode/JSON expansion, and atomic receipt refusal
across tool/CLI mutations. A11: alias ambiguity and unambiguous controls, escaping/golden,
stale/isolated nodes, deterministic exports, injection and overflow tests. A12:
shared store with independent profile authority and no second-profile mutation.
A01/A03 implemented surfaces: NativeRuntimeTests and PolicyTests. Phase 2 covers
A07/A08 discovery/reconciliation separately; Phase 3 documents A09 inspection
evidence. A13 is indexed in acceptance-matrix.md, not proved by Phase 1 alone.

Native source remains the inspected f42f579cf8bac4918ac9599bece71618afadd846.
Phase 1 local execution uses its existing admitted Python 3.11.15 environment
with ruamel.yaml 0.18.17; parent scaffold evidence exercised Python 3.14.7 with
0.18.16. No production dependency installation/modification is part of these
checks. GitHub CI, publication, target integration, live activation/scans and SSH
are unperformed. No function above the conservative verifier threshold of 15 is
accepted; schema/payload validators and the simple renderer may warn near 10–14.
