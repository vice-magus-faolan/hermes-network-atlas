# Network Atlas operator runbook

Select a profile, read existing knowledge, then configure collection as needed.
Reading inventory does not require scan or SSH grants.

## Installation and support

Use stock Hermes **>=0.21.4** and Python >=3.11,<3.15.
CI checks Hermes v0.21.7 and v0.22.2 on Linux x86_64 and arm64; check the selected
revision's successful jobs for executed coverage. There is no Hermes upper bound,
following its additive plugin contract, but other releases are not individually
verified.
The plugin declares `ruamel.yaml>=0.18.16,<0.19` as its extra runtime dependency.

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
access. Diagnose resolver or security failures rather than bypassing them.
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
| `network-atlas/config.yaml` | Operator-controlled collection, sharing, and limits policy |
| `network-atlas/atlas.sqlite3` | Default knowledge, immutable evidence and history |
| `network-atlas/exports/` | Optional generated maps, never authoritative |

Atlas policy is separate from Hermes's own `config.yaml` and plugin selector.
A missing Atlas config grants no collection and permits existing-knowledge reads.
For read-only use, a minimal file is `version: 1` with `networks: {}`.
Empty files, duplicate or unknown keys, invalid numbers, and noncanonical or
overbroad CIDRs fail closed. Policy is checked before registration and again on
invocation. A malformed policy can prevent `network-atlas` from being registered,
leaving the command unavailable. If an already-registered CLI catches invalid
policy during invocation, it exits 2 with `applied=false` and `persisted=false`
before dispatch or store changes.

Edit policy directly, not through model tools; use mode 0600 in a 0700 directory.
This example enables passive collection only. Replace `192.168.1.0/24` with your
actual LAN's canonical network. Active, endpoint and SSH collection stay disabled:

```yaml
version: 1
networks:
  lab:
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
- `discovery.icmp_echo` defaults false and requires `ping: true`. TCP ports default
  to `[80, 443]`; choose at most four distinct ports in 1..65535, excluding 4403.
  ICMP-only uses `tcp_ports: []`. See [host-discovery policy](host-discovery-policy.md).
- Endpoint checks need `enabled: true` and a nonempty `tcp_ports` list under
  `networks.NAME.endpoints`, independently of discovery or SSH. The same port
  limits apply; see [endpoint policy](endpoint-checks.md#operator-policy).
- SSH needs `ssh.enabled: true` and a host entry such as
  `lab-a: {alias: lab-a, inspect: true}` under `ssh.hosts`, referencing an existing
  OpenSSH alias. Stored knowledge or a previous success cannot grant access.
- `retention.stale_after_days` defaults to 14 (1..3650). It marks age, not deletion.
  `render.include_addresses` defaults true; `include_interfaces` defaults false.
- `limits` may only lower hard ceilings: command 15s, host 10s, operation 120s,
  four concurrent probes, 1 MiB output, 4096 observations, 4096 input characters,
  100 results, offset 10000, and 5000ms SQLite busy wait. Budgets can leave work
  unstarted; a permitted /24 does not guarantee completion on a real network.

### Shared knowledge, local authority

To share knowledge, add the same absolute `.sqlite3` path to each profile's policy:

```yaml
store:
  shared_sqlite_path: /srv/private-atlas/atlas.sqlite3
```

This selects a database; it does not copy or merge the default store. Readers can
query another profile's evidence, including endpoints, but cannot apply its batches
or inherit collection, inspection or resume permissions. Policy and exports stay
profile-local. Keep the shared file private. See
[shared endpoint queries](endpoint-checks.md#sharing-and-upgrades).

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
`endpoint_count` counts recorded address and port pairs, not devices or services;
`endpoint_observation_count` includes failed and unstarted history.

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
```

Check `identity_state`, `historical_responder_evidence`, freshness and coverage.
Originals remain listed after resolution; see [unresolved evidence](unresolved-evidence.md).

TCP endpoint history is another separate read-only view:

```sh
hermes -p PROFILE network-atlas query --query-json '{"view":"endpoints","limit":20,"offset":0}'
```

Filter endpoints with exact `address` or `batch_id` as needed. `open` means a
historical TCP connect; `closed` means refusal. Neither identifies a service.
`no_response`, `unavailable` and `not_started` are not offline verdicts. Rows carry
no device identity or SSH access; see [endpoint history](endpoint-checks.md#read-historical-evidence).

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
hermes -p PROFILE network-atlas discover --network lab --mode passive
hermes -p PROFILE network-atlas reconcile --batch-id BATCH_ID
hermes -p PROFILE network-atlas map --format markdown
```

Replace BATCH_ID with discovery's returned `batch_id`; inspect its completion and
outcomes before applying it. Passive collection requires installed iproute2 and
reads cached neighbors; an empty or partial cache is not a LAN census.

For active discovery, first configure `discovery.ping: true` and the desired
methods using the [host-discovery policy](host-discovery-policy.md), then use
`discover --network lab --mode ping`. For SSH, configure the alias as above,
then collect and apply the returned batch:

```sh
hermes -p PROFILE network-atlas inspect --target lab-a
hermes -p PROFILE network-atlas reconcile --batch-id BATCH_ID
```

Inspect accepts a configured alias or uniquely mapped stable device ID, never
commands, SSH options or arbitrary destinations. Reconcile accepts eligible local
LAN or SSH batches. Exact-ID retries return the saved result without duplicate
events. Failed or partial batches contribute valid positives, not scope absence.
Slash equivalents are `/network discover lab passive`, `/network inspect lab-a`,
and `/network reconcile BATCH_ID`.

TCP endpoint checking instead performs collection, persistence, projection, and
readback through one operation under its separate `endpoints` grant:

```sh
hermes -p PROFILE network-atlas check-endpoints lab
hermes -p PROFILE network-atlas resume-endpoints BATCH_ID
```

If `persisted=true` but `queryable=false`, save the ID and resume instead of
rescanning. Resume never recollects. Read `completion` separately from `persisted`,
`applied`, `projected` and `queryable`. Endpoint batches do not use reconciliation
or create devices, aliases or topology. See [endpoint recovery](endpoint-checks.md#commands-and-recovery).

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

To deliberately write both generated map files:

```sh
hermes -p PROFILE network-atlas map --format mermaid --export
```

This writes profile-local `exports/network_map.md` and `network_map.mmd` beneath
`network-atlas`, even with a shared database. If interrupted between replacements,
regenerate both from SQLite; they are not a cross-file atomic snapshot.

## Troubleshooting and data care

- Command unavailable: confirm PROFILE, supported Hermes version and
  `plugins show network-atlas`. Check policy errors: malformed policy can stop
  registration before the command exists. Correct the file, then retry
  `network-atlas --help` in a fresh CLI process.
- Policy refusal: check the selected profile's Atlas config, not the inventory.
  Correct invalid keys, types or noncanonical scopes; do not
  broaden grants to fix a read-only query. Check `limits` when output is refused.
- No devices: read `unresolved` and `endpoints` history before concluding no
  evidence exists. Query and map never trigger a refresh as recovery.
- Incomplete collection: inspect per-method diagnostics and whole-batch coverage.
  Do not turn timeouts into offline claims, raise hard ceilings, or retry with
  privileged helpers. Endpoint recovery uses its stored ID, not another scan.
- Store or version failure: preserve the database and use a compatible Atlas version;
  never delete it to repair an inspection or query error. Writable opens upgrade
  schema 1 to 2 transactionally; read-only schema-1 access does not migrate.
  Older binaries cannot write schema 2. See [upgrade compatibility](endpoint-checks.md#sharing-and-upgrades).

Keep policy, database, WAL, audit history, exports, and backups private. Use a
consistent SQLite backup before upgrades; copying only an active WAL-mode database
file can omit committed data. Never attach live stores, policy, private exports,
keys, passwords, or tokens to public issues. SQLite and file modes do not isolate
same-UID processes. See [CONTRIBUTING.md](../CONTRIBUTING.md) for isolated tests.
