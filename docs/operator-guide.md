# Network Atlas operator runbook

Use this guide to select the right profile, read existing knowledge, and explicitly
maintain or collect evidence. Reading inventory does not require scan or SSH grants.
Examples are instructions, not authorization for installation, policy changes,
live collection, or gateway restarts.

## Installation and support

Atlas is a native directory plugin (`plugin.yaml` and `__init__.py` at the repository
root). It declares Hermes >=0.21.4,<0.22 and supports Python >=3.11,<3.15. Use stock
NousResearch/hermes-agent; no core patch or fork is needed. Its only extra runtime
dependency is `ruamel.yaml>=0.18.16,<0.19`, declared in the manifest.

The repository validation uses unmodified official Hermes v0.21.6, with Python
3.14.7 in the Docker image. Native directory-plugin registration, tool/slash/CLI
dispatch, synthetic collection, and fresh-process persistence are exercised.
This is not package-manager install/enable or live-network acceptance. A declared
Linux x86_64/arm64 CI matrix alone does not prove either job passed, and does not
establish other releases/platforms, real host keys, provider chat, or gateway
restart behavior. Do not infer support for latest Hermes from the version range.

Choose an existing profile and an immutable reviewed Atlas revision. In all shell
examples, replace PROFILE with that profile's name (`default` for the default
profile). Replace REVIEWED_SHA and uppercase ID placeholders before running them.
Do not change the sticky default just to use Atlas.

```sh
hermes profile list
hermes -p PROFILE plugins install https://github.com/vice-magus-faolan/hermes-network-atlas.git --ref REVIEWED_SHA --no-enable
hermes -p PROFILE plugins enable network-atlas
hermes -p PROFILE plugins show network-atlas
hermes -p PROFILE network-atlas --help
```

Install scans the selected artifact; native dependency resolution may require
network access. Retain ordinary security scanning and dependency/capability
consent. Do not use force, suppress scans, hand-edit Hermes's enabled list, or
pip dependencies into production to bypass a failure. Missing dependencies,
resolver conflicts, or incomplete package-intelligence warnings need diagnosis,
not an assumption of safety. See [Hermes plugin documentation](https://hermes-agent.nousresearch.com/docs/user-guide/features/plugins).

Enable changes the selected profile's plugin selection. Start a new Hermes process
for that profile to use its registered tools/commands. Treat any restart of a
running gateway as a separate deployment decision; an enable hint is not consent.

## Profile-local configuration

Resolve the selected profile before opening files:

```sh
hermes profile show PROFILE
```

Atlas resolves its home with Hermes's profile-aware `get_hermes_home()`, not the
current directory or the plugin checkout. Normally the default profile uses
`~/.hermes` and named profiles use `~/.hermes/profiles/NAME`; a custom
`HERMES_HOME` can change the resolved location. Use the actual selected home:

| Path beneath the selected home | Purpose |
| --- | --- |
| `network-atlas/config.yaml` | Operator-controlled collection, sharing, and limits policy |
| `network-atlas/atlas.sqlite3` | Default canonical knowledge and immutable evidence/history |
| `network-atlas/exports/` | Optional generated maps, never authoritative |

Atlas policy is separate from Hermes's own `config.yaml` and plugin selector.
A missing Atlas config grants no collection permissions and still permits reads
of existing knowledge. An existing empty/malformed file, duplicate/unknown keys,
invalid numbers, or noncanonical/overbroad CIDRs fail closed at registration and
each invocation. Invalid-policy CLI refusal exits 2 with
`applied=false/persisted=false`, before dispatch or store changes.

Only the operator maintains this file: mode 0600 in a 0700 directory, not through
model tools. The README's minimal policy grants no collection. The following
expanded example uses a reserved documentation network, enables only explicit
passive collection, and disables active/endpoint/SSH collection. It is not a live
network authorization; replace scopes and enable methods only with approval.

```yaml
version: 1
networks:
  lab:
    cidr: 192.0.2.0/29
    discovery:
      passive: true
      ping: false
      icmp_echo: false
      tcp_ports: [80, 443]
ssh:
  enabled: false
  hosts:
    lab-a: {alias: lab-a, inspect: false}
retention:
  stale_after_days: 14
render:
  include_addresses: true
  include_interfaces: false
```

### Collection grants and limits

- `networks.NAME.discovery.passive` and `ping` default false. Active discovery is
  IPv4-only; every configured IPv4 range has at most 256 addresses. Passive IPv6
  knowledge does not authorize active IPv6 scanning or routes-derived scopes.
- `discovery.icmp_echo` defaults false and requires `ping: true`.
  `discovery.tcp_ports` defaults to `[80, 443]`; choose at most four distinct integer
  ports in 1..65535, excluding 4403. ICMP-only uses `tcp_ports: []`. Read the
  [host-discovery policy](host-discovery-policy.md) before changing methods.
- `networks.NAME.endpoints` is separately opt-in: both `enabled: true` and a
  nonempty `tcp_ports` list are required. It has the same four-port/4403 constraints;
  ping, ICMP, and SSH grants do not enable endpoint checks. See
  [endpoint policy and recovery](endpoint-checks.md).
- SSH needs `ssh.enabled: true` and a host with an existing OpenSSH `alias` and
  `inspect: true`. Stored knowledge or a previous success cannot grant access.
- `retention.stale_after_days` defaults to 14 (1..3650). It marks age, not deletion.
  `render.include_addresses` defaults true; `include_interfaces` defaults false.
- `limits` may only lower hard ceilings: command 15s, host 10s, operation 120s,
  four concurrent probes, 1 MiB output, 4096 observations/input characters,
  100 results, offset 10000, and 5000ms SQLite busy wait. Budgets can leave work
  unstarted; a permitted /24 does not guarantee completion on a real network.

### Shared knowledge, local authority

To deliberately share an atlas, operators of each participating profile can add
an absolute `.sqlite3` path to their own policy, for example:

```yaml
store:
  shared_sqlite_path: /srv/private-atlas/atlas.sqlite3
```

This selects a different physical database; it does not copy or merge the default
store. Readers of that file can query foreign evidence, including endpoints,
without collection/SSH grants. They cannot apply foreign batches or inherit alias
anchors, inspection, collection, or resume authority. A separate database sees
none of the shared file's knowledge. Exports and policy stay profile-local.
File permissions and same-UID trust still apply. See [Atlas Core](atlas-core.md)
and [shared endpoint queries](endpoint-checks.md#sharing-and-upgrades).

## Read existing knowledge

After selecting PROFILE, start here. These commands do not collect, reconcile,
export, initialize, or migrate the database:

```sh
hermes -p PROFILE network-atlas status
hermes -p PROFILE network-atlas query --query-json '{"limit":10,"offset":0}'
hermes -p PROFILE network-atlas map --format markdown
```

Equivalent model calls (tool name followed by arguments) are:

```text
network_query {"view":"status"}
network_query {"limit":10,"offset":0}
network_map {"format":"markdown","export":false}
```

In an interactive Hermes session for the same profile, use `/network help`,
`/network status`, `/network show DEVICE_ID`, or `/network map markdown`.
There is no slash `query` command; use the model tool or local CLI for filters.

Status separates known inventory, age-qualified observed/stale subsets, current
configured scopes/authorized SSH aliases, last local discovery, last inspection,
and endpoint history counts. Configured SSH permission and last inspection
success/failure are different facts; neither proves present reachability.
`endpoint_count` counts distinct recorded address/port tuples, not devices or
services. `endpoint_observation_count` includes failed and unstarted history.

To filter devices and inspect their provenance, use returned stable IDs:

```sh
hermes -p PROFILE network-atlas query --query-json '{"access_method":"ssh","limit":10}'
hermes -p PROFILE network-atlas query --query-json '{"device_id":"DEVICE_ID"}'
hermes -p PROFILE network-atlas query --query-json '{"view":"history","device_id":"DEVICE_ID","limit":10}'
```

`network_query` accepts the same JSON fields. Filters intersect; `name`, exact
current `address`, `device_type`, `status`, relationship filters, and literal
`text` search are also supported. Check `has_more`; request the next page with
the same filters/limit and an increased `offset` (for example 10 after offset 0
with limit 10). Local policy can lower pagination ceilings. Oversized entity
evidence refuses rather than hiding conflicts; use paginated history for detail.

### Responses without identified devices

An empty device list is not an empty network. MAC-less responses can remain
unidentified rather than being assigned to an IP's former owner. Read original
discovery evidence separately:

```sh
hermes -p PROFILE network-atlas query --query-json '{"view":"unresolved","limit":10,"offset":0}'
hermes -p PROFILE network-atlas query --query-json '{"view":"unresolved","address":"192.0.2.10","limit":10}'
hermes -p PROFILE network-atlas query --query-json '{"view":"unresolved","batch_id":"BATCH_ID","limit":10}'
```

Inspect `identity_state`, `historical_responder_evidence`, freshness, origin/policy
context, and batch/probe coverage. Never-applied, unresolved/conflicting, and
later-resolved originals remain distinguishable. Historical originals stay listed
after resolution. See [unresolved evidence and lineage](unresolved-evidence.md).

TCP endpoint history is another separate read-only view:

```sh
hermes -p PROFILE network-atlas query --query-json '{"view":"endpoints","limit":20,"offset":0}'
hermes -p PROFILE network-atlas query --query-json '{"view":"endpoints","address":"192.0.2.10","limit":20}'
```

It retains address/port, state, UTC time, diagnostic, batch and profile scope.
`open` means a historical TCP connect; `closed` means refusal, not a listening
service. `no_response`, `unavailable`, and `not_started` are not offline verdicts.
Endpoint rows have no device identity and do not grant SSH access. These queries
work on an explicitly shared store too; see [endpoint query semantics](endpoint-checks.md#read-historical-evidence).

### Interpret results before acting

- Direct observations, operator-supplied assertions, and explained inference retain
  separate provenance. Inference cannot silently become operator truth. An IP or
  hostname alone never merges identities; conflicts stay visible.
- `stale` is age-based, not the result of one failed probe. Never-seen operator
  records remain known/unknown. Retirement is operator-owned and sticky.
- Passive neighbor tables are cached/partial. Failed, partial, timed-out, excluded,
  unavailable, or unstarted work cannot assert scope absence. Even qualified
  complete ping coverage means only "not observed in that exact run", not deleted
  or offline. Fresh historical evidence still does not prove reachability now.
- Status `probe_summary` covers the entire last batch, even when `probes` is only
  a bounded sample. Check `returned_count`, `omitted_count`, and
  `omitted_failure_count`; device pagination cannot hide whole-batch failures.
  Status has no probe pagination; device history is not batch-probe detail.
  See [Atlas Core status fields](atlas-core.md#read-only-query-and-maps).
- Maps use only stored supported relations, escape labels, and retain isolated,
  stale, and uncertain nodes. An absent edge is unknown topology, not proof of
  disconnection. No service enumeration or background refresh is performed.

## Explicit collection and reconciliation

Only proceed for operator-approved scopes already in current local policy.
These commands write immutable evidence and, for discovery/inspection, do not yet
change canonical devices:

```sh
hermes -p PROFILE network-atlas discover --network lab --mode passive
hermes -p PROFILE network-atlas discover --network lab --mode ping
hermes -p PROFILE network-atlas inspect --target lab-a
```

Select a configured network name and mode, never a raw range. Inspect accepts a
currently authorized alias or uniquely mapped stable device ID, never commands,
SSH options, or arbitrary destinations. Save each returned batch ID and inspect
completion/outcomes. To apply one eligible local LAN/SSH batch atomically:

```sh
hermes -p PROFILE network-atlas reconcile --batch-id BATCH_ID
```

Exact-ID retries return the saved reconciliation result without duplicate events.
Failed/partial batches can contribute valid positives, not unsupported absence.
Slash equivalents are `/network discover lab passive`, `/network inspect lab-a`,
and `/network reconcile BATCH_ID`. Model tools use `network_discover` with
`{"network":"lab","mode":"passive"}`, `network_inspect` with `{"target":"lab-a"}`,
and `network_reconcile` with `{"batch_id":"BATCH_ID"}`.

TCP endpoint checking instead performs collection, persistence, projection, and
readback through one operation under its separate `endpoints` grant:

```sh
hermes -p PROFILE network-atlas check-endpoints lab
hermes -p PROFILE network-atlas resume-endpoints BATCH_ID
```

Run resume only when a saved endpoint batch needs projection/readback recovery;
it never recollects. If `persisted=true` but `queryable=false`, retain the ID and
resume rather than rescan. `completion` describes collection separately from
`persisted`, `applied`/`projected`, and `queryable` progress. Endpoint batches do
not use `network_reconcile` and create no devices, aliases, or topology. See the
[endpoint runbook](endpoint-checks.md#commands-and-recovery) for stage flags,
revocation, incomplete work, and recovery constraints.

### Dependencies and transport effects

Passive collection needs installed iproute2; legacy ping uses optional installed
Nmap with fixed bounded host-discovery argv. Opt-in ICMP/nondefault-port socket
collection needs no Nmap or ping helper. Linux ICMP echo datagrams require existing
permission: no raw sockets, helper fallback, privilege changes, or automatic
installation. Unavailable ICMP does not erase valid TCP evidence (or vice versa).
Requested methods are not proof of transmitted packets. See
[LAN collection](local-discovery.md) and [host-discovery limits](host-discovery-policy.md).

TCP connects can consume remote slots, generate logs, and trigger kernel
retransmissions without application traffic. Port 4403 is refused because
connection contention can affect radio clients; other sensitive endpoints remain
an operator risk. Host-discovery and endpoint TCP checks do not read banners or
send application payloads. They do not identify services or versions; service/OS/
NSE/UDP enumeration and vulnerability scanning are outside these checks. Authorized
SSH inspection separately gathers fixed Linux host inventory.

SSH requires existing operator-managed OpenSSH aliases, keys, known_hosts, and
remote Linux utilities. Fixed read-only probes require BatchMode and strict host
keys, with no sudo, PTY, forwarding, LocalCommand, or multiplex reuse. Unknown or
changed host keys fail closed; never auto-accept them to make inspection work.
Missing commands or rejected safety options produce bounded failures, not weaker
SSH. Operator SSH config (including ProxyJump/ProxyCommand/Match exec), installed
executables, native plugins, and same-UID processes are trusted, not sandboxed.
Local cancellation cannot guarantee termination of every remote descendant.
See [SSH transport and trust](authorized-ssh-inspection.md) and [security boundaries](../SECURITY.md).

## Operator assertions and exports — explicit writes

For operator-supplied knowledge, use the trusted local CLI, not a model tool:

```sh
hermes -p PROFILE network-atlas create --name "Workstation"
hermes -p PROFILE network-atlas update --device-id DEVICE_ID --field description --value-json '"Operator assertion"'
hermes -p PROFILE network-atlas update --device-id DEVICE_ID --field ssh_alias --value-json '"lab-a"'
hermes -p PROFILE network-atlas update --device-id DEVICE_ID --field retired --value-json true
```

Use the returned device ID. Alias association requires existing current inspection
permission and never grants it. Retirement does not delete history; reactivation
uses the same update with `false`. `/network update` refuses because slash origin
cannot attest a human. The local CLI is a trusted-route convention, not
cryptographic human attestation. Model `network_update` persists explained inference
only, regardless of caller `source=user` claims. Applying receipts report
`persisted=true`; `validate-update` is validation-only and reports
`applied=false/persisted=false`. See [manual seeding and typed relations](atlas-core.md#operator-updates-and-manual-seeding).

To deliberately write both generated map files:

```sh
hermes -p PROFILE network-atlas map --format mermaid --export
```

This writes fixed profile-local `exports/network_map.md` and `network_map.mmd`
beneath `network-atlas`, even with a shared database. It is an audited write, not
the read-only workflow above. If interrupted between replacements, regenerate both
from SQLite; the two files are not a cross-file atomic snapshot.

## Troubleshooting and data care

- Command unavailable: confirm PROFILE and `plugins show network-atlas`; use
  `network-atlas --help` in a new process. Do not enable a different profile or
  install another runtime merely to fix command discovery.
- Policy refusal: check the selected profile's Atlas config, not the inventory.
  Remove invalid keys/types or correct canonical scopes as the operator; do not
  broaden grants to fix a read-only query. Check `limits` when output is refused.
- No devices: read `unresolved` and `endpoints` history before concluding no
  evidence exists. Query/map never trigger a refresh as recovery.
- Incomplete collection: inspect per-method diagnostics and whole-batch coverage.
  Do not turn timeouts into offline claims, raise hard ceilings, or retry with
  privileged helpers. Endpoint recovery uses its stored ID, not another scan.
- Store/version failure: preserve the database and use a compatible Atlas version;
  never delete it to repair an inspection/query error. Writable opens upgrade
  schema 1 to 2 transactionally; read-only schema-1 access does not migrate.
  Older binaries cannot write schema 2. See [upgrade compatibility](endpoint-checks.md#sharing-and-upgrades).

Keep policy, DB/WAL, audit history, exports, and backups private. Use a consistent
SQLite backup before approved upgrades; copying only an active WAL-mode database
file can omit committed data. Never attach live stores/config, private exports,
keys, passwords, or tokens to public issues. SQLite/file modes do not isolate
same-UID processes. Contributor-only synthetic verification is documented in
[CONTRIBUTING.md](../CONTRIBUTING.md); it must not use a live atlas or network.
