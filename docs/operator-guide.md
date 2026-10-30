# Network Atlas operator runbook

Select a profile, read existing knowledge, then configure collection as needed.
Reading inventory does not require scan or SSH grants.

## Installation and support

Use stock Hermes **>=0.21.7** and its supported Python runtime (>=3.11).
As of 2026-10-26, CI targets Hermes v0.21.7 (oldest tested stable release) and
v0.22.5 (latest stable release checked that date) on Linux x86_64 and arm64.
There is no Hermes upper bound, following its additive plugin contract;
other releases are not individually verified.
The plugin declares `ruamel.yaml>=0.18.16,<0.19` for explicit legacy conversion only.

Replace PROFILE with an existing profile's name (`default` for the default
profile), COMMIT_SHA with an immutable 40-character Atlas commit, and uppercase
ID placeholders with returned IDs. Use the first column of `git ls-remote` below
for current main, or copy the full commit from a revision reviewed on GitHub.
`-p` selects the profile for each invocation.

```sh
hermes profile list
git ls-remote https://github.com/vice-magus-faolan/hermes-network-atlas.git refs/heads/main
hermes -p PROFILE plugins install https://github.com/vice-magus-faolan/hermes-network-atlas.git --ref COMMIT_SHA --no-enable
```

If this profile retains Atlas data after removal, **before enabling** follow
[Re-enable or reinstall with retained data](#re-enable-or-reinstall-with-retained-data)
to restore only its database binding. Do not accept legacy policy import or restore
an old full-grant config: either can reintroduce revoked collection grants.
For a first installation, continue with:

```sh
hermes -p PROFILE plugins enable network-atlas
hermes -p PROFILE plugins show network-atlas
hermes -p PROFILE network-atlas --help
```

Install scans the artifact and resolves dependencies, which may need network
access. Resolver errors indicate dependency or network problems; security scan
findings need inspection of the reported plugin file before installation.
Enable changes the selected profile's plugin selection. Hermes attempts
to hot-reload a responding gateway: slash commands can become available there
immediately, while Atlas's Python tools wait for a new session. If no gateway
responds, the CLI prints the fallback `hermes gateway restart` hint. A fresh CLI
process loads enabled plugins when it starts. See
[Hermes plugin documentation](https://hermes-agent.nousresearch.com/docs/user-guide/features/plugins).

## Profile-local configuration

Resolve the selected profile before opening files:

```sh
hermes profile show PROFILE
```

Use the reported profile home, not the current directory or plugin checkout.
Normally it is `~/.hermes` for default or `~/.hermes/profiles/NAME` for a named
profile; `HERMES_HOME` can override it. Paths beneath that home are:

| Path beneath the selected home | Purpose |
| --- | --- |
| `config.yaml`: `plugins.entries.network-atlas.settings.policy` | Native operator-controlled Atlas policy |
| `plugin-data/network-atlas/atlas.sqlite3` | New default knowledge, immutable evidence and history |
| `network-atlas/exports/` | Optional generated maps, never authoritative |

Atlas declares one dictionary setting, `policy`, in its native `config_schema`.
Use Hermes's config CLI to replace the complete policy value, not model tools or
a second Atlas config file. Include every grant and setting you intend to retain:

```sh
hermes -p PROFILE config set plugins.entries.network-atlas.settings.policy '{"networks":{}}'
```

This replacement removes omitted network and SSH-host grants, but also drops any
omitted store binding. To revoke all collection grants, follow
[Stop collection offline](#stop-collection-offline): preserve the recorded database
binding and verify no grants in a fresh status, including on converted profiles.
If an earlier empty-policy replacement produces missing-binding guidance, use
that procedure's binding-only recovery; do not rerun conversion or restore the old
full-grant config.
Do not use the Desktop settings JSON editor or `ctx.set_config` for grant removal:
their merging writer retains omitted keys, and writing `{}` there does not clear
existing grants.

Keep the selected profile home and native configuration private (0700/0600 is
the recommended operator boundary, not a guarantee Atlas enforces). On Linux
with stock Hermes v0.22.5, the public storage helper creates `plugin-data/` and
`plugin-data/network-atlas/` using the process umask: 0755 under 0022, 0700 under
0077. Even a query can create these directories without initializing a database.
Atlas creates a new database as 0600 and resets the selected database file to
0600 on every writable open, including an existing shared database. Loosening
that file's mode for cross-UID sharing will be undone by the next writable open.
This does not tighten existing storage directories or repair permissions on
native config, WAL sidecars, backups or unselected legacy stores. A private
database file does not make directory names, native config, exports or backups
private. Review the actual selected home, ancestor directories, files and any
shared target using your normal
filesystem policy before use; do not assume installation repaired permissions.
Same-UID processes remain trusted regardless of these mode bits.

An absent setting or empty object grants no collection. Atlas validates returned
values: unknown keys, invalid numbers, noncanonical or overbroad scopes refuse
the action with exit 2 and `applied=false`, `persisted=false`. Registration remains
available for repair/conversion. Hermes owns caching, last-known-good fallback,
managed-worker snapshots, default initialization and refresh semantics; Atlas
does not promise immediate revocation when the root config is unreadable or a
worker still holds a native snapshot. Start a fresh native session after policy
changes when needed. Stop active collectors before changing sensitive grants.

The following is the shape of the `policy` value (shown as YAML for readability),
not a standalone file. It enables passive collection only. Replace
`192.168.1.0/24` with your LAN; active, endpoint and SSH collection stay disabled:

```yaml
version: 1
networks:
  home:
    cidr: 192.168.1.0/24
    discovery:
      passive: true
      ping: false
ssh:
  enabled: false
  hosts: {}
retention:
  stale_after_days: 14
render:
  include_addresses: true
  include_interfaces: false
```

### Collection grants and limits

- `networks.NAME.discovery.passive` and `ping` default false. IPv4 scopes have at
  most 256 addresses; IPv6 is passive-only. Routes never add scan scopes.
- Active discovery and endpoint checks default to RFC1918 (`10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`) and IPv4 link-local (`169.254.0.0/16`) scopes.
  Other ranges, including documentation ranges, require the strict boolean
  `networks.NAME.allow_public: true` for that exact network, in addition to its
  enabled collection method. The default is false. This is not an exemption from
  IPv4/size, sensitive-destination, port or resource limits.
- `discovery.icmp_echo` defaults false and requires `ping: true`. TCP ports default
  to `[80, 443]`; choose at most four distinct ports in 1..65535, excluding 4403.
  ICMP-only uses `tcp_ports: []`. See [host-discovery policy](host-discovery-policy.md).
- Endpoints need the master `networks.NAME.endpoints.enabled: true`, independently
  of discovery or SSH, and at least one nonempty protocol list. TCP and UDP use
  their own `tcp_ports`/`udp_ports` selections; UDP-only uses empty/omitted TCP.
  `enabled: false` pauses both, retaining valid native settings lists for later
  re-enable; status shows only effective selections. Each list
  accepts up to 32 distinct integer ports in 1..65535; TCP excludes 4403 and UDP
  excludes 7, 19 and 4403. The full address × (TCP + UDP selections) grid
  must fit `limits.observations` before any traffic (at most 16 protocol/port pairs
  on a /24 with the hard 4096-record ceiling). For a standing mixed-protocol example
  and unchanged runtime budgets, see [endpoint policy](endpoint-checks.md#operator-policy).
- SSH needs `ssh.enabled: true` and a host entry such as
  `lab-a: {alias: lab-a, inspect: true}` under `ssh.hosts`, referencing an existing
  OpenSSH alias. Stored knowledge or a previous success cannot grant access.
- `retention.stale_after_days` defaults to 14 (1..3650). It marks age, not deletion.
  `render.include_addresses` defaults true; `include_interfaces` defaults false.
- `limits` may only lower hard ceilings: command 15s, host 10s, operation 120s,
  four concurrent probes, 1 MiB output, 4096 observations, 4096 input characters,
  100 results, offset 10000, and 5000ms SQLite busy wait. Budgets can leave work
  unstarted; a permitted /24 does not guarantee completion on a real network.

A refusal names `networks.NAME.allow_public`. First check the CIDR for typos such
as `192.186.1.0/24`; do not opt in merely to silence an error. Use the native policy
setting described above to add `allow_public: true` only for a deliberately
authorized non-private network. `status` lists the boolean in `configured_scopes`
for each named network. It does not automatically grant or start collection.
Public passive collection and stored query/map reads need no public opt-in,
even when active methods are configured. Revoking the opt-in preserves history
but refuses saved active-batch reconciliation and endpoint resume/preview/continue;
automatic batch selection and status guidance omit those ineligible actions.
Restore that network's grant only if still intended; old evidence is not authority.

Limit keys are `command_timeout_seconds`, `host_timeout_seconds`,
`operation_timeout_seconds`, `concurrent_probes`, `output_bytes`, `observations`,
`input_chars`, `result_count`, `page_offset`, and `busy_timeout_ms`. Each takes a
positive integer no larger than the ceiling above. `observations` also caps probe
outcomes per batch. Policy allows at most 32 named
networks and 32 SSH hosts. Names and aliases use 1–64 ASCII letters, digits,
underscores or hyphens and must start with a letter or digit. YAML booleans must
be `true` or `false`, not strings or numbers.

### Shared knowledge, local authority

To share knowledge, add the same absolute `.sqlite3` path to each profile's policy:

```yaml
store:
  shared_sqlite_path: /srv/private-atlas/atlas.sqlite3
```

Each profile keeps its own policy and exports. This selects a database; it does
not copy or merge the default store. Readers can query another profile's evidence,
including endpoints, but cannot apply its batches or inherit collection, inspection
or resume permissions. Keep the shared file private. See
[shared endpoint queries](endpoint-checks.md#sharing-and-upgrades).

### Cloning a converted profile

A native config-only profile clone copies Atlas's policy, including its grants
and any absolute `store.shared_sqlite_path`; it does not rebind that path to the
clone's home. Conversion and the binding-only stop both write such an explicit
path, even for a default profile's local store. A later `--clone` of that stopped
profile therefore shares the parent's database too, although its policy has no
collection grants. A clone retaining an absolute binding reads AND writes the
source's database, not an independent copy. In contrast, a config-only clone with no explicit store
binding starts with its own empty default store; it does not copy local history.
This behavior is exercised with the real native clone and public Atlas actions,
not inferred only from the copied config.

Before running collection or making inventory changes in a clone, run
`hermes -p CLONE network-atlas status`. Its `database_binding` contains the selected
resolved `profile_home` and `database_path`, including managed-directory symlinks
and explicit shared paths. Compare the source and clone's `database_path`: equal
paths select the same store, even when their `profile_home` values differ. Different
paths do not prove physical isolation (for example, hard links can alias a file).
An absent store still reports its selected path without initializing it. Status
does not copy, migrate, rebind, repair or collect; native managed directories can
still be created as described above. Model-tool status, `/network status` and
CLI `query` omit this filesystem binding; use the local operator `status` command
to inspect it, and keep its output private. This is a disclosure boundary, not
isolation from other same-UID tools or processes.

Also inspect the complete native policy for copied grants before collection.
Sharing is intentional when the inherited path is retained. Each caller still owns evidence by its own
resolved home and keeps local exports; copied grants do not authorize applying
the source profile's saved batches. A clone does, however, inherit the configured
grants for NEW collection until you explicitly replace them.

To choose independent EMPTY history instead, stop affected writers and use the
native replacing config CLI to set the clone's complete policy without `store`.
For example, the following also deliberately revokes every collection/SSH grant:

```sh
hermes -p CLONE config set plugins.entries.network-atlas.settings.policy '{}'
hermes -p CLONE network-atlas status
hermes -p CLONE network-atlas query --query-json '{"limit":10}'
```

Include every intended grant when replacing the policy, or explicitly select
another absolute shared path. Do not use the merging settings writer to remove
an inherited binding. Rebinding selects a store; it does not copy, split, merge
or rewrite existing history or ownership. Preserve the source and any existing
clone-local store and investigate unexpected inventory before writing. Moving
populated history between owners is not provided by this clone procedure.

### Convert legacy policy and storage

Use this procedure for the **first migration**, not recovery after stop, removal
or reinstall. If conversion already occurred, or that history is uncertain, keep
workers stopped and follow
[retained-data recovery](#re-enable-or-reinstall-with-retained-data) instead.
A missing binding does not establish first use: retained legacy settings may
contain revoked grants. Conversion refuses before copying a database or writing
settings unless you pass `--accept-legacy-policy` or native policy already equals
the complete conversion result. Inspect the entire legacy config privately before
accepting it; the flag explicitly authorizes importing **all** its settings and
grants, including any previously revoked ones. It is not a recovery flag or a
detector of historical revocation. Atlas has no record that can distinguish a
first migration from lost settings or an interrupted settings commit.

Upgrading source does not move data. If `network-atlas/atlas.sqlite3` exists and
no native store binding was chosen, normal actions refuse with missing-binding guidance
instead of silently showing a new empty inventory. Legacy `network-atlas/config.yaml`
is read only by the explicit converter (bounded to 64 KiB); it is never a runtime fallback.

1. Stop every Atlas writer, including sessions/gateways using the old version and
   other profiles writing the same store. Keep writers stopped and do not edit
   native or legacy settings until conversion/recovery finishes. Make a consistent
   private SQLite backup using your existing backup procedure, including WAL data.
2. Install the reviewed new revision without starting collection. Privately inspect
   the complete legacy `network-atlas/config.yaml` (if present) and confirm every
   setting and grant remains intended. Only for this deliberate first migration,
   explicitly accept that policy in a fresh CLI:

   ```sh
   hermes -p PROFILE network-atlas convert-legacy --writers-stopped --accept-legacy-policy
   hermes -p PROFILE network-atlas status
   hermes -p PROFILE network-atlas query --query-json '{"limit":10}'
   ```

3. Compare IDs, history and returned grants before restarting writers. The converter
   copies a legacy default store into managed storage with SQLite backup, including
   committed WAL rows; it retains schema, receipts and resolved-home ownership.
   It then writes the complete policy through native `set_config`, binding the
   new database explicitly. Exports keep their original profile-local location.
   An explicit `store.shared_sqlite_path` stays in place, even when it names a
   legacy location: this converts policy only, never makes private shared-store copies.

Conversion preserves the source and destination schema versions; it is not a
schema upgrade. If the selected converted store is schema 1..4, keep writers
stopped and deliberately run `hermes -p PROFILE network-atlas upgrade-store --writers-stopped`
after conversion finishes, before restarting writers. Upgrade changes only the
selected destination (or deliberately selected shared file), not retained originals.
Do not replay conversion after upgrading the destination: its schema now differs
from the original, so the exact-copy retry correctly refuses. See
[shared-store upgrade procedure](endpoint-checks.md#sharing-and-upgrades).

`--writers-stopped` attests that you stopped writers; it is not a process detector.
`--accept-legacy-policy` accepts legacy settings before effects; it does not
override conflicting native policy or stores. Originals
are retained, not renamed/deleted. Existing nonempty native settings and an existing
destination must match the conversion exactly; divergent stores/settings refuse
without overwrite or merge. The converter compares complete logical history and
checks for other-connection source commits from before the initial comparison
through a final check immediately before publication (or reuse of an equal copy).
Detected changes refuse conversion. This check is not a write lock: a commit after
it can still race publication and the separate native settings write. Keep all
writers stopped and settings unchanged through completion; this is not live migration.

A catchable failure before publication removes the converter's own temporary
copy. SIGKILL, a process crash or power loss can bypass cleanup and leave private
`.atlas-convert-*.sqlite3` files in the destination directory; these are not
automatically reused or deleted. Keep originals, WAL sidecars, any published
destination and all unknown/foreign copies intact. With writers stopped and the
complete legacy policy still intended, repeat the command with
`--accept-legacy-policy` in a fresh CLI: it makes a new copy if no destination exists, or reuses
only an equal completed destination. A failure after DB publication but before
settings commit likewise leaves that complete copy for cold retry. Investigate
remnants using private consistent backups and your existing SQLite recovery
procedure; a temporary filename alone proves neither ownership nor completeness
and is not permission to delete or promote it.

Do not resume old and new writers together. Once native history changes, replaying
the converter against old originals correctly conflicts. Preserve both stores and
repair the selected binding deliberately; never delete history to force a retry.
To roll back before any new writes, select the previous plugin revision and retained
legacy policy/store. After new writes, preserve both histories for operator recovery;
the converter does not merge them. Actual production conversion and backup are
explicit operator effects, not part of installation, registration or query.

## Read existing knowledge

These commands do not collect, reconcile, export, initialize or migrate:

```sh
hermes -p PROFILE network-atlas status
hermes -p PROFILE network-atlas query --query-json '{"limit":10,"offset":0}'
hermes -p PROFILE network-atlas map --format markdown
```

In an interactive Hermes session for the same profile, use `/network help`,
`/network status`, `/network show DEVICE_ID`, or `/network map markdown`.
There is no slash `query` command; use the model tool or local CLI for filters.

Status shows inventory, freshness, local policy and collection history separately.
SSH permission and last inspection success do not prove present reachability.
`endpoint_count` counts recorded address/protocol/port tuples, not devices or services;
`endpoint_observation_count` includes failed and unstarted history.

### Status guidance

`status` (or `network_query` with `{"view":"status"}`) adds a read-only `guidance`
object based on the same stored snapshot and current profile policy:

- `inventory_state` distinguishes empty canonical inventory from recorded devices;
  `local_collection_state` says whether this profile has any saved collection.
  Shared knowledge can exist without local collection.
- `unapplied_local_batches` counts local LAN/SSH batches without applications,
  including scopes no longer authorized. `reconcilable_batches` suggests exact
  batch IDs only for current matching local grants. Endpoint batches are separate.
- `inspection_targets` lists currently authorized, unambiguous configured aliases,
  including aliases with no device yet. `discovery_options` lists only enabled
  network/mode pairs. These are policy-eligible suggestions, not runtime availability
  claims; actions still validate policy, mappings and bounds at invocation.
  Ambiguous aliases are omitted even when their mappings exceed `result_count`;
  that ambiguity alone does not prevent reading status.
- Each suggestion group returns at most five items (fewer under `result_count`),
  with exact `total_count` and `omitted_count`. The complete status still obeys
  `output_bytes`; insufficient space refuses instead of silently hiding detail.
- `historical_unresolved_applications` counts saved applications reporting
  unresolved identity/topology, not currently unresolved devices. Follow
  `evidence_query` for address identity lineage; use `view=topology` for SSH routes
  and next-hop reasons.
- `devices_without_relationships` counts devices with no supported relationships.
  Maps retain those nodes; missing links mean unknown topology, not disconnection.

Native status replaces the former unconditional `collection_available` and
`ssh_transport_available` booleans with `availability`. Its `executable_presence`
checks whether executable `ip`, `nmap` and `ssh` files can be found on the current
PATH, without running them. `methods` reports `missing_executable` or `unverified`:
passive collection requires `ip`, legacy ping requires `nmap`, and SSH inspection
requires local `ssh`. Legacy ping is the default TCP `[80, 443]` discovery without
ICMP; enabling ICMP or changing discovery TCP ports selects `socket_ping` instead.
Socket ping and TCP/UDP endpoints need none of those executables. A missing tool
does not disable unrelated methods, and a present tool does not enable policy.

`availability.runtime` remains `unverified`: status does not execute tools, open
sockets or test socket permissions, SSH credentials/host keys, remote probes or
connectivity. Guidance carries the same caveat; it does not gate actions using
these diagnostics. No checks install tools, change policy or collect evidence.
Disabled methods and passive-only IPv6 scopes are refused before public opt-in
advice; an `allow_public` grant cannot enable them. Even an eligible method remains
subject to destination exclusions and resource bounds when explicitly invoked.

No collection grants means no collection choices, not permission to invent an alias,
change policy or run a custom scanner. An empty query/map does not trigger collection;
use status to distinguish unapplied evidence from a genuinely empty store. IP-only
responses and TCP/UDP endpoint evidence remain separate from canonical device identity.

To filter devices and inspect their provenance, use returned stable IDs:

```sh
hermes -p PROFILE network-atlas query --query-json '{"access_method":"ssh","limit":10}'
hermes -p PROFILE network-atlas query --query-json '{"view":"history","device_id":"DEVICE_ID","limit":10}'
```

`network_query` accepts the same JSON fields; see all seven tools in the
[README](../README.md#model-tools). Filters intersect; `name`, exact current
`address`, `device_type`, `status`, relationship filters, and literal `text` search
are also supported. Check `has_more`; request the next page with the same filters
and `limit`, increasing `offset` (for example 10 after offset 0
with limit 10). Local policy can lower pagination ceilings. Oversized entity
evidence refuses rather than hiding conflicts; use paginated history for detail.

### Responses without identified devices

An empty device list is not an empty network. Read unidentified responses without
assigning them to an IP's former owner:

```sh
hermes -p PROFILE network-atlas query --query-json '{"view":"unresolved","limit":10,"offset":0}'
hermes -p PROFILE network-atlas query --query-json '{"view":"unresolved","batch_id":"BATCH_ID","limit":10}'
hermes -p PROFILE network-atlas query --query-json '{"view":"unresolved","batch_id":"BATCH_ID","summary":true}'
```

Check `identity_state`, `historical_responder_evidence`, freshness and coverage.
Originals remain listed after resolution; retained totals are not current failure
counts. The batch summary separates current uncertainty from resolved/supporting
history and points to complete detail pagination. See [unresolved evidence](unresolved-evidence.md).

TCP/UDP endpoint history is another separate read-only view:

```sh
hermes -p PROFILE network-atlas query --query-json '{"view":"endpoints","limit":20,"offset":0}'
```

Filter endpoints with exact `address` or `batch_id` as needed. `open` means a
historical TCP connect or validated empty UDP reply; `closed` means TCP refusal
or post-send UDP kernel-reported rejection. Read `protocol`, `probe_method` and
`diagnostic_code`: UDP is transport-only evidence, not QUIC/local discovery or
authenticated service identity. Local UDP send success and silence do not qualify.
`no_response`, `unavailable` and `not_started` are not offline verdicts. Rows carry
no device identity or SSH access; see [endpoint history](endpoint-checks.md#read-historical-evidence).

### Explain logical next hops

After authorized SSH inspection and reconciliation, use:

```sh
hermes -p PROFILE network-atlas query --query-json '{"view":"topology","batch_id":"BATCH_ID","limit":10,"offset":0}'
hermes -p PROFILE network-atlas query --query-json '{"relationship":"routes_via"}'
hermes -p PROFILE network-atlas map --format markdown
```

The first command also works before application or without an identified peer.
Check origin/profile, timestamp, confidence, `resolution.reason` and pagination.
Inferred configured next hops require same-host route/cache evidence and an
already unambiguously identified peer; unknown/stale/conflicting support stays
queryable without an edge. Maps and relationship queries use the same current
support, not an old application's successful receipt. These are logical routing
claims, not cabling or live reachability. See the complete
[eligibility and retention rules](authorized-ssh-inspection.md#logical-topology).

### Interpret results before acting

- Direct observations, operator assertions, and explained inference remain separate.
  An IP or hostname alone never merges identities; conflicts stay visible.
- `stale` is age-based, not a failed probe. Never-seen operator records remain
  known with unknown reachability; rediscovery does not undo retirement.
- Passive tables are cached and partial. Failed or incomplete work cannot assert
  scope absence. Complete ping coverage means only "not observed in that run",
  not deleted or offline. Fresh history still does not prove reachability now.
- Status `probe_summary` covers the entire last batch, even when `probes` is only
  a sample. Check `returned_count`, `omitted_count`, and `omitted_failure_count`.
  Status has no probe pagination; device history is not batch-probe detail.
  See [Atlas Core status fields](atlas-core.md#read-only-query-and-maps).
- Maps retain isolated, stale and uncertain nodes. Missing edges mean unknown
  topology, not disconnection. Maps do not refresh or enumerate services.

## Explicit collection and reconciliation

Select a network and mode enabled in current local policy. Discovery writes an
immutable batch; reconcile applies it to inventory, then map reads the result:

```sh
hermes -p PROFILE network-atlas discover --network home --mode passive
hermes -p PROFILE network-atlas reconcile --batch-id BATCH_ID
hermes -p PROFILE network-atlas map --format markdown
```

Replace BATCH_ID with discovery's returned `batch_id`; inspect its completion and
outcomes before applying it. Passive collection requires installed iproute2 and
reads cached neighbors; an empty or partial cache is not a LAN census.

For active discovery, first configure `discovery.ping: true` and the desired
methods using the [host-discovery policy](host-discovery-policy.md), then use
`discover --network home --mode ping`. For SSH, configure the alias as above,
then collect and apply the returned batch:

```sh
hermes -p PROFILE network-atlas inspect --target lab-a
hermes -p PROFILE network-atlas reconcile --batch-id BATCH_ID
hermes -p PROFILE network-atlas query --query-json '{"device_id":"DEVICE_ID"}'
hermes -p PROFILE network-atlas map --format markdown
```

Inspect accepts a configured alias or uniquely mapped stable device ID, never
commands, SSH options or arbitrary destinations. An authorized alias does not need
a pre-existing device: reconciliation can create one from its successful inspection.
Use inspection's BATCH_ID, then the returned DEVICE_ID to read hostname, OS,
owned interfaces, addresses and provenance. Reconcile accepts eligible local
LAN or SSH batches. Exact-ID retries return the saved result without duplicate
events. Failed or partial batches contribute valid positives, not scope absence.
Slash equivalents are `/network discover home passive`, `/network inspect lab-a`,
and `/network reconcile BATCH_ID`.

TCP/UDP endpoint checking instead performs collection, persistence, projection, and
readback through one operation under its separate `endpoints` grant:

```sh
hermes -p PROFILE network-atlas check-endpoints home
hermes -p PROFILE network-atlas resume-endpoints BATCH_ID
```

If `persisted=true` but `queryable=false`, save the ID and resume instead of
rescanning. Resume never recollects. Read `completion` separately from `persisted`,
`applied`, `projected` and `queryable`. Endpoint batches do not use reconciliation
or create devices, aliases or topology. To make further bounded progress after a
timeout, use `preview-endpoints BATCH_ID`, then explicitly `continue-endpoints BATCH_ID`.
Continue makes new TCP/UDP traffic only for still-unattempted tuples and returns a new
linked batch; preview that successor to inspect progress. This is different from
no-contact resume. See [continuation and interruption](endpoint-checks.md#continue-unfinished-work--new-traffic).

### Dependencies and transport effects

Legacy ping requires installed Nmap. Opt-in ICMP and nondefault-port socket
collection need no Nmap or ping helper. Linux ICMP datagrams require existing
permission; there is no raw-socket fallback, privilege change or automatic install.
Unavailable ICMP does not erase valid TCP evidence. See
[LAN collection](local-discovery.md) and [host-discovery limits](host-discovery-policy.md).

- Local subprocesses use fixed argv without a shell. Time and output limits terminate
  and reap owned local process groups.
- TCP connects can consume slots, generate logs and cause kernel retransmissions
  without application traffic. Port 4403 is refused because contention can affect
  radio clients; other sensitive endpoints can still be affected. Checks send no
  application payloads or banner requests and make no service or version claims.
- UDP sends exactly one empty unicast datagram per selected tuple; this can cause
  logs, processing, firewall state or ICMP. No broadcast/multicast or application
  handshake is sent. See [UDP semantics and limits](endpoint-checks.md#udp-method-and-limits).
- SSH uses existing aliases, keys, known_hosts and remote Linux utilities. It
  requires BatchMode and strict host keys, with no sudo, PTY, forwarding,
  LocalCommand or multiplex reuse. Unknown or changed keys fail closed; do not
  auto-accept them. Missing commands produce failures, not weaker SSH options.
- SSH config (including ProxyJump, ProxyCommand and Match exec), installed
  executables, native plugins and same-UID code are trusted, not sandboxed.
  Local cancellation cannot guarantee termination of every remote descendant.
  See [SSH transport and trust](authorized-ssh-inspection.md) and
  [security boundaries](../SECURITY.md).

## Operator assertions and exports — explicit writes

For operator-supplied knowledge, use the trusted local CLI, not a model tool:

```sh
hermes -p PROFILE network-atlas create --name "Workstation"
hermes -p PROFILE network-atlas update --device-id DEVICE_ID --field description --value-json '"Operator assertion"'
hermes -p PROFILE network-atlas update --device-id DEVICE_ID --field ssh_alias --value-json '"lab-a"'
hermes -p PROFILE network-atlas update --device-id DEVICE_ID --field retired --value-json true
```

Use the returned device ID. Alias association requires current inspection
permission, never grants it. Retirement preserves history; use `false` to reactivate.
`/network update` refuses; use the local CLI for operator facts. Model
`network_update` persists explained inference only, never operator assertions or
retirement. `validate-update` only validates, with `applied=false` and
`persisted=false`. See [manual seeding](atlas-core.md#operator-updates-and-manual-seeding).

To export both generated map files:

```sh
hermes -p PROFILE network-atlas map --format mermaid --export
```

This writes profile-local `exports/network_map.md` and `network_map.mmd` beneath
`network-atlas`, even with a shared database. If interrupted between replacements,
regenerate both from SQLite; they are not a cross-file atomic snapshot.
An `export: symlink destination refused` error means one of these fixed paths is
a symlink. Restore regular generated-file destinations without modifying the
symlink targets or database, then retry. Symlink-destination refusals retain a
`map_export_requested` audit event but no `map_exported` completion event.

## Stop, uninstall and clean reset

Stopping collection, removing plugin code and erasing inventory are different
operations. Atlas has no background collector of its own. None of the steps below
authorizes stopping another user's processes or deleting a shared store.

### Stop collection offline

1. Stop issuing collection actions. Finish or cancel in-flight Atlas work and stop
   affected sessions/workers/gateways using your normal operator procedure. Include
   every writer to a shared database; a config change cannot cancel running work
   or revoke an already loaded worker snapshot.
2. **Before changing settings**, record privately:

   ```sh
   hermes profile show PROFILE
   hermes -p PROFILE network-atlas status
   ```

   Read `database_binding.profile_home` and `database_binding.database_path` from
   local status, not an assumed default. Set ATLAS_HOME and ATLAS_DB below to those
   exact absolute paths. Privately inspect the native policy with
   `hermes -p PROFILE config get plugins.entries.network-atlas.settings.policy`.
   Set ATLAS_BINDING to its validated absolute `.sqlite3` store binding, preserving
   that spelling even if it is a symlink to a differently named file. Without an
   explicit binding, use the resolved managed `plugin-data/network-atlas` directory
   plus `atlas.sqlite3`. Verify ATLAS_BINDING resolves to ATLAS_DB; use the binding
   in config and the resolved target for inventory, ownership and backups.
   Set BACKUP to a new private directory outside the profile
   and all reset targets. If an earlier `{}` stop already causes `legacy store
   present`, or removal forgot the binding, use
   [Recover the selected binding](#recover-the-selected-binding) below. Do not
   restore the old full-grant config or rerun `convert-legacy`: conversion can
   restore old grants. Preserve the current native config, then replace the policy
   with only that store binding:

   ```sh
   ATLAS_HOME=/absolute/selected/profile-home
   ATLAS_BINDING=/absolute/configured/atlas.sqlite3
   ATLAS_DB=/absolute/selected/database-file
   BACKUP=/absolute/private/atlas-backup-UNIQUE
   umask 077
   mkdir "$BACKUP" &&
   cp "$ATLAS_HOME/config.yaml" "$BACKUP/config.yaml" &&
   hermes -p PROFILE config set plugins.entries.network-atlas.settings.policy \
     "$(python3 -c 'import json, sys; print(json.dumps({"store": {"shared_sqlite_path": sys.argv[1]}}))' "$ATLAS_BINDING")" &&
   hermes -p PROFILE network-atlas status
   ```

   Use the native **replacing** config CLI, not the merging Desktop settings writer
   or `ctx.set_config`: merging can retain grants. Plain `cp` under `umask 077`
   creates a 0600 backup even when the original is 0644; do not use `cp -p`.
   In the fresh status,
   `configured_networks` and `authorized_for_atlas_ssh_inspection` must both be empty.
   This needs no network or dependency resync, leaves the plugin available for
   reads, and retains stored history. Investigate a failed write or unexpected
   grants rather than assuming collection stopped.

   The binding-only policy retains ATLAS_DB through ATLAS_BINDING for reads and
   backup, including after conversion. Conversion leaves the legacy database in place;
   removing `store.shared_sqlite_path` with `{}` then makes status report a missing binding
   instead of reporting no grants. **Do not rerun conversion as stop recovery.**
   Repeat the binding-only replacement above, with a new BACKUP, to repair that
   state or verify an already-stopped profile. Stored history grants no authority.
   Removing a custom/shared binding is a separate deliberate detachment, not a stop
   requirement or evidence that the previously selected store was erased.

### Recover the selected binding

Use the privately recorded binding or inspect the saved native config without
restoring it; a saved native selection takes precedence over legacy inputs.
Keep the accepted configuration spelling (ATLAS_BINDING) distinct from the
resolved database target (ATLAS_DB). Missing handwritten notes alone need not block
recovery of a converted profile: if the legacy inputs are unchanged, conversion's selection is
deterministic. Privately inspect `network-atlas/config.yaml` beneath the resolved
ATLAS_HOME. If its `store.shared_sqlite_path` is present, it must be a validated
absolute path ending in `.sqlite3`; preserve that literal value as ATLAS_BINDING.
Resolve filesystem symlinks in it to establish ATLAS_DB. For example,
`/owned/atlas.sqlite3` pointing to `/owned/inventory.db` remains a valid binding;
putting the resolved `inventory.db` in config would fail the `.sqlite3` requirement.
Treat the value as a literal path: do not expand `~` or environment variables;
relative paths are rejected. If the key is absent (including when the legacy
config is absent), resolve ATLAS_HOME's `plugin-data/network-atlas` directory,
including any directory symlinks, then append `atlas.sqlite3` for ATLAS_BINDING.
Resolve that full path for ATLAS_DB as well. That is the managed
conversion destination, not the retained legacy `network-atlas/atlas.sqlite3`.

This derives the path only; do not execute conversion or import legacy grants.
If the legacy inputs, symlinks or later native store selection changed, establish
the actual selected binding from saved native config/backup or other private
records instead. Stop if it remains uncertain; do not guess a new store or move
shared data. Verify ATLAS_BINDING resolves to the established ATLAS_DB, then use
only ATLAS_BINDING in the binding-only replacement, never the old grants.

### Back up retained data before removal or reset

Keep all writers stopped and close all readers/connections until backup and any
reset finish. Protect BACKUP and its files as carefully as the original
config/history. Confirm path ownership,
symlinks, hard links and other users before changing files; distinct path strings
do not prove independent storage. Exports can also be redirected or shared by
filesystem links. If ownership or use is uncertain, retain the files and stop.

For an existing ATLAS_DB, Python's standard SQLite backup API creates a complete
standalone copy, including committed WAL data. Run this only with a new backup
filename; it refuses to overwrite one. An absent database needs no SQLite backup.

```sh
python3 - "$ATLAS_DB" "$BACKUP/atlas.sqlite3" <<'PY'
from contextlib import closing
from pathlib import Path
import os
import sqlite3
import sys

source_path, backup_path = map(Path, sys.argv[1:])
with closing(sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True)) as source:
    fd = os.open(backup_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    with closing(sqlite3.connect(backup_path)) as backup:
        source.backup(backup)
        if backup.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise RuntimeError("Backup integrity check failed; retain the original")
PY
```

Also copy any existing regular `network-atlas/exports/network_map.md` and
`network_map.mmd` beneath ATLAS_HOME into a private `exports/` directory in BACKUP.
Save any older owned legacy config/database and their SQLite sidecars separately,
without overwriting this backup. Verify the backup opens and retains expected
device IDs and history before touching originals; `integrity_check` alone does
not establish that you selected the right store. Exports are useful copies, not
a replacement for SQLite history. Never copy only the main file of an active
WAL database, discard a WAL to make a store open, or overwrite a good backup after
a failed attempt.

### Disable or uninstall — network required

After the offline stop and backup, choose one native operation:

```sh
hermes -p PROFILE plugins disable network-atlas
# Or remove the installed plugin code:
hermes -p PROFILE plugins remove network-atlas
hermes -p PROFILE plugins list
```

In stock v0.21.7 and v0.22.5, disable marks Atlas disabled in the selected profile
but retains its settings, including the database binding. Remove deletes the
installed plugin code and its config entry, including that binding. Neither
erases inventory or exports.
After disable, privately inspect the actual native config:

```sh
hermes -p PROFILE config get plugins.entries.network-atlas.settings.policy
```

Require exactly the binding-only policy set above (no network or SSH grants), not
merely a disabled listing. If grants remain, repeat the offline replacing stop and
verify the saved config before any enable. Do not delete a converted profile's
binding just to make the entry absent. After remove, verify its config entry is
absent; inspect the saved native file if the config command reports a missing key.
Before any enable or reinstall, follow the retained-data procedure below, or
complete an intentional empty reset first. Restoring an old entry restores grants.

The maintainer's [issue #34 UAT](https://github.com/vice-magus-faolan/hermes-network-atlas/issues/34)
reported running disable/remove with Hermes still running, retained data/exports,
and old inventory on reinstall. Its claim that disable removed the policy is not
supported by either release's source; do not rely on it. This source inspection is
not a new online lifecycle trial. Treat lifecycle changes as online operations:
disable's dependency/environment resync can reach PyPI; the reported
offline disable failed with a traceback. Remove clears code/config without that
resync; it still is not the offline stop procedure.
Use the replacing-policy stop above while offline, not repeated uninstall attempts.
After any failure, inspect actual native selection/config and retained files.
Follow native session/restart hints; a successful command is not proof that an
old loaded session or in-flight operation has stopped. No live restart is implied.

### Re-enable or reinstall with retained data

Keep workers stopped and retain the selected/shared database, legacy files,
exports and private backups. If disabled but still installed, no reinstall is
needed. If removed, first install the reviewed revision **without enabling**:

```sh
hermes -p PROFILE plugins install https://github.com/vice-magus-faolan/hermes-network-atlas.git --ref COMMIT_SHA --no-enable
```

Removal forgot the binding. **Before enabling**, establish ATLAS_BINDING and ATLAS_DB using
[Recover the selected binding](#recover-the-selected-binding), then replace the
complete policy with only that binding, even if the new entry looks empty:

```sh
ATLAS_BINDING=/absolute/configured/atlas.sqlite3
hermes -p PROFILE config set plugins.entries.network-atlas.settings.policy \
  "$(python3 -c 'import json, sys; print(json.dumps({"store": {"shared_sqlite_path": sys.argv[1]}}))' "$ATLAS_BINDING")" &&
hermes -p PROFILE config get plugins.entries.network-atlas.settings.policy
```

Require exactly the intended validated binding spelling, resolving to ATLAS_DB,
and no network or SSH grants in that readback.
**Do not reconvert, accept legacy policy import, or restore the old full-grant
config**: those can bring back revoked grants. If already enabled with a missing
binding, keep workers stopped and apply this same replacing config command, not
conversion. Current conversion refuses an unaccepted policy import before database
copy/settings writes; older revisions may still suggest unconditional conversion
and restore grants silently. Neither behavior makes conversion a recovery procedure.

Only after verifying the binding-only policy, enable and read back in fresh
processes:

```sh
hermes -p PROFILE plugins enable network-atlas
hermes -p PROFILE network-atlas status
```

Require the intended `database_binding` and empty `configured_networks` and
`authorized_for_atlas_ssh_inspection` before starting workers. Retained history
should still be readable; zero inventory is not required. These config commands
work offline, but installation and enable's dependency resync may need network.

### Intentional clean reset and readback

Only proceed after the verified backup, with all writers/readers closed and the
exact targets confirmed **exclusively yours**. There is no Atlas reset command.

- Resolve ATLAS_HOME and ATLAS_DB first. If ATLAS_DB is outside resolved ATLAS_HOME,
  treat it as shared and **leave it untouched**, even if its filename looks like a
  default store. A native clone can inherit an absolute binding into its source
  profile's home. Being inside ATLAS_HOME is not proof of isolation: check links,
  other profiles/users and in-flight work too.
- For a confirmed owned unshared store inside ATLAS_HOME, remove or privately
  quarantine the recorded ATLAS_DB and any adjacent `ATLAS_DB-wal`, `ATLAS_DB-shm`,
  `ATLAS_DB-journal`. These suffixes
  append to the full filename (for example `atlas.sqlite3-wal`). Handle the set
  only after closing all connections; never move/delete an in-use SQLite store.
- If ATLAS_DB was custom, inspect the default `plugin-data/network-atlas/atlas.sqlite3`
  beneath ATLAS_HOME as well. An earlier default inventory can become active when
  the binding is removed. Back up each owned populated store separately, using
  distinct backup names, before resetting it; stop if any target is shared/unknown.
- Remove/quarantine the two generated export files listed above. Inspect other
  files individually; do not recursively delete a profile, `plugin-data/`, a shared
  directory or BACKUP. Preserve unrelated plugin and foreign-profile data.
- If the selected store is shared, **do not delete it**. Leave other users' history
  intact. A binding-only stop safely keeps it readable without collection authority.
  To detach, first retain any legacy files as described below, then replace with `{}`
  and inspect this profile's default store: it may contain earlier inventory.
  Detachment gives an empty active selection only when that default is empty;
  it is not erasure of shared data. Never relocate a parent's store to reset a clone.
- For a fully empty profile, also inventory and privately relocate any exclusively
  owned legacy `network-atlas/atlas.sqlite3` plus sidecars and
  `network-atlas/config.yaml`, and other known retained Atlas copies. A legacy DB
  left in place causes missing-binding refusal instead of an empty read. Do not
  rerun conversion or restore the old binding/config on reinstall. Shared/unknown
  originals and backups are retained intentionally, not claimed erased.

Before re-enabling writers, check the recorded old store and exports are absent
from their active paths (and not dangling links), not merely that status succeeds.
For this intentional empty reset only, retain legacy files outside active paths
before removing an old binding, then verify the native config has no collection
grants. If the plugin remains enabled, use fresh processes. If disabled but still
installed, run only `hermes -p PROFILE plugins enable network-atlas`; no reinstall
is needed. If removed, install the reviewed revision with `--no-enable`, verify
the config has no grants, then enable. Do not use this empty-reset path for retained
data: use the binding-only pre-enable recovery above instead. Before re-enabling
writers run:

```sh
hermes -p PROFILE network-atlas status
hermes -p PROFILE network-atlas query --query-json '{"limit":10}'
hermes -p PROFILE network-atlas map --format markdown
```

Confirm the intended `database_binding`, no grants, `known_devices: 0`,
`last_collection: null`, no endpoint history, an empty device list with
`has_more: false`, and no generated exports. An absent selected database should
remain absent after these reads; native managed directories may still be created.
These empty-reset checks do not apply to a stop that intentionally retains inventory
through its binding-only policy; that case must show no grants, not zero history.
An empty device list alone can hide saved evidence. Keep backups/retired copies
outside active paths; reinstall does not erase them or ask before using a database
still at its selected path. Restoring an old config can reattach history **and
restore collection authority**: recovery is a separate deliberate operator action.

## Troubleshooting and data care

Application errors name the responsible field or policy setting without echoing
its value. Correct that field in the request or the selected profile's policy.
CLI JSON errors distinguish `query-json` from `value-json`; an inspection `target`
error refers to the requested SSH alias or device ID, not a separate update field.
`limits.observations` refusals mean the selected scope/methods or fixed SSH probes
cannot fit the record budget; reduce collection scope/methods or restore a
sufficient budget within the hard ceiling before retrying.
`store`, `local I/O`, and `atlas state or bounds` errors instead indicate local
availability, schema, evidence or limit problems; changing a target does not
repair them. Raw exception text, SQL and transport stderr are not returned.
Transport failures remain per-probe outcomes/diagnostics, not invalid arguments.
For endpoint failures, keep the returned `batch_id`, `stage` and persistence flags;
resume a saved batch after repairing the reported category, rather than rescanning.

- Command unavailable: confirm PROFILE, supported Hermes version and
  `plugins show network-atlas`. Atlas domain errors normally leave the command
  registered; inspect native plugin-load diagnostics, then retry
  `network-atlas --help` in a fresh CLI process.
- Policy refusal: check the selected profile's Atlas config, not the inventory.
  Correct the reported keys, types or noncanonical scopes. Read-only queries need
  no collection grants. Output refusal means the response exceeds `limits`;
  request a smaller page or restore sufficient limits within the hard ceilings.
- No devices: read `unresolved` and `endpoints` history before concluding no
  evidence exists. Query and map never trigger a refresh as recovery.
- Incomplete collection: inspect per-method diagnostics and whole-batch coverage.
  Timeouts leave reachability unknown; unavailable ICMP can reflect existing OS
  permissions. Reduce the configured scope or enabled methods if work cannot fit
  the budget. Endpoint recovery uses its stored ID rather than another scan.
- Store or version failure: preserve the database and use a compatible Atlas version;
  make a consistent backup before changing versions. Ordinary writes to schema
  1..4 refuse before collection; reads remain available without migration. The
  explicit local `upgrade-store --writers-stopped` command upgrades to 5 transactionally.
  Older binaries cannot read/write schema 5, even though its indexes are additive.
  See [upgrade compatibility](endpoint-checks.md#sharing-and-upgrades).

Older readers may also reject additive configuration keys or `not_started` probe
outcomes. Update shared-store readers before using new features; historical
batches are not rewritten to fit an older reader.

Keep policy, database, WAL, audit history, exports, and backups private. Use a
consistent SQLite backup before upgrades; copying only an active WAL-mode database
file can omit committed data. Never attach live stores, policy, private exports,
keys, passwords, or tokens to public issues. SQLite and file modes do not isolate
same-UID processes. See [CONTRIBUTING.md](../CONTRIBUTING.md) for isolated tests.
