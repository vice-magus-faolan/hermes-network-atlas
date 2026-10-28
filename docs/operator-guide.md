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

This replacement removes omitted network and SSH-host grants. To revoke all
collection grants, replace the value with `{}` using the same command. Verify
with `hermes -p PROFILE network-atlas status` in a fresh process.
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
- TCP endpoints need `enabled: true` and a nonempty `tcp_ports` list under
  `networks.NAME.endpoints`, independently of discovery or SSH. UDP needs its own
  explicit nonempty `udp_ports` list, regardless of TCP enablement. Each list
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
clone's home. Conversion writes such an explicit path even for a formerly local
store. The converted clone therefore reads AND writes the source's database,
not an independent copy. In contrast, a config-only clone with no explicit store
binding starts with its own empty default store; it does not copy local history.
This behavior is exercised with the real native clone and public Atlas actions,
not inferred only from the copied config.

Before running collection or making inventory changes in a clone, inspect its
complete native policy in that profile's `config.yaml`, especially the absolute
store binding (or its absence). Fresh `hermes -p CLONE network-atlas status` and
`query` calls verify grants and inventory, but do not report the resolved database
path; they cannot by themselves prove isolation. Sharing is intentional when the
inherited path is retained. Each caller still owns evidence by its own
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

Upgrading source does not move data. If `network-atlas/atlas.sqlite3` exists and
no native store binding was chosen, normal actions refuse with conversion guidance
instead of silently showing a new empty inventory. Legacy `network-atlas/config.yaml`
is read only by the explicit converter (bounded to 64 KiB); it is never a runtime fallback.

1. Stop every Atlas writer, including sessions/gateways using the old version and
   other profiles writing the same store. Keep writers stopped and do not edit
   native or legacy settings until conversion/recovery finishes. Make a consistent
   private SQLite backup using your existing backup procedure, including WAL data.
2. Install the reviewed new revision without starting collection. In a fresh CLI:

   ```sh
   hermes -p PROFILE network-atlas convert-legacy --writers-stopped
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

The flag attests that you stopped writers; it is not a process detector. Originals
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
destination and all unknown/foreign copies intact. With writers stopped, repeat
the command in a fresh CLI: it makes a new copy if no destination exists, or reuses
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
  make a consistent backup before changing versions. Writable opens upgrade
  schema 1..3 to 4 transactionally; read-only access does not migrate.
  Older binaries cannot read/write schema 4. See [upgrade compatibility](endpoint-checks.md#sharing-and-upgrades).

Older readers may also reject additive configuration keys or `not_started` probe
outcomes. Update shared-store readers before using new features; historical
batches are not rewritten to fit an older reader.

Keep policy, database, WAL, audit history, exports, and backups private. Use a
consistent SQLite backup before upgrades; copying only an active WAL-mode database
file can omit committed data. Never attach live stores, policy, private exports,
keys, passwords, or tokens to public issues. SQLite and file modes do not isolate
same-UID processes. See [CONTRIBUTING.md](../CONTRIBUTING.md) for isolated tests.
