# Durable native TCP endpoint checks

This narrow part of issue #1 adds historical address/port evidence, not service
identification or a general scanner. A fixed numeric TCP connect is sufficient to
record connected/open, refused/closed and no-response outcomes without Nmap
service detection, ICMP prerequisites, application traffic or a new scanning
framework. Device identity may remain completely unresolved.

## Operator policy

Endpoint checking has its own opt-in grant on each named IPv4 network. Existing
`discovery.ping`, `discovery.tcp_ports`, ICMP and SSH permissions do not enable it.
No policy means no endpoint traffic. This documentation-only example is not live
authorization:

```yaml
version: 1
networks:
  lab:
    cidr: 192.0.2.8/31
    discovery:
      ping: false
    endpoints:
      enabled: true
      tcp_ports: [22, 2222]
```

The list must contain one to four distinct integer ports in 1..65535, excluding
4403. Both `enabled: true` and the nonempty list are required; omitted endpoints
are disabled. IPv4 ranges have at most 256 addresses. Network/broadcast and
special destinations are recorded as excluded, not contacted. Host-discovery
TCP defaults and existing collectors are unchanged. Older Atlas versions reject
these new policy keys rather than silently permitting them.

Callers select a configured network name, never addresses, ports, commands,
provenance, Nmap flags or bounds. Operator limits may only lower the existing V1
ceilings. The shared nonblocking socket scheduler enforces one operation deadline,
one concurrency ceiling, at most 8 starts/second per concurrency slot (32 maximum),
and one nonrenewing per-host deadline. Attempts get a fair reduced time slice so
one filtered port cannot consume every later port's allowance. There are no
retries. A part of the operation deadline is reserved for durable storage,
projection and readback. Every owned socket closes on completion or interruption;
no child process, raw socket, privilege change, DNS or ICMP check is needed.

The TCP handshake itself may consume connection slots or cause remote logs and
kernel retransmissions. This is not a zero-effect probe. 4403 is excluded at both
policy and socket boundaries because connection contention can affect radio
clients. Other sensitive endpoints remain an operator selection risk.

## One operation, durable completion

The model tool is `network_check_endpoints` with exactly one selection:
`{"network":"lab"}` to collect, or `{"batch_id":"<returned-id>"}` to resume.
The same operation is exposed through the native local CLI and slash command:

```sh
hermes network-atlas check-endpoints --network lab
hermes network-atlas check-endpoints --batch-id <returned-id>
```

```text
/network check-endpoints lab
/network resume-endpoints <returned-id>
```

A normal receipt reports:

- `persisted`: immutable batch and all per-address/port outcomes committed;
- `applied` / `projected`: endpoint evidence and its application marker committed;
- `queryable`: a fresh read connection successfully verified the exact batch count;
- `stage`: the current or completed stage (`projection`, `readback`, `queryable`);
- `collection_performed`: false on resume, true after a new collection;
- `completion`: complete, partial or failed collection, independent of durable
  lifecycle success; a failed check can still be durably recorded and queried;
- final `state_counts` / `observation_count`: all planned checks, not only positives.

Only connected/refused count as successful TCP response checks. Timeout,
unavailable and not-started remain separate, so complete does not mean all ports
open. Partial collection preserves earlier valid results and accounts for the
unexamined tail; no outcome asserts offline state or absence.

After persistence, a projection/readback/output failure returns an error with the
same durable batch ID and honest stage flags. Resume that ID; do not issue a new
network selection merely to finish applying it. Projection is one transaction
using the existing unique-per-batch application marker; simultaneous or repeated
resumes cannot duplicate rows or audit events. Resume needs the original profile
and still-matching local network/port policy. Revoked policy leaves the historical
batch queryable as knowledge but cannot authorize projection. A failed local
resume retains the actual previously committed applied/projected state; it does
not claim a new successful readback merely because a projection already exists.
If lowered record/output limits prevent recovery, the operator must restore
sufficient limits within the existing ceilings. No automatic policy expansion
or recollection occurs. Before-persistence failure cannot promise a recoverable
batch; retrying collection is a new explicitly requested check.

`network_reconcile` remains the identity-oriented LAN/SSH route and rejects
endpoint batches. Endpoint projection creates no devices, interfaces, address
assignments, aliases, SSH capabilities, assertions or topology.

## Read historical evidence

```sh
hermes network-atlas query --query-json '{"view":"endpoints","limit":20}'
hermes network-atlas query --query-json '{"view":"endpoints","address":"192.0.2.8","limit":20}'
hermes network-atlas query --query-json '{"view":"endpoints","batch_id":"<returned-id>","limit":20}'
hermes network-atlas status
```

`network_query` accepts these same filters. `limit`/`offset` are bounded by local
policy, ordering is timestamp plus unique probe ID, and `has_more` is explicit.
`total_count` counts matching historical outcomes, including failed/unstarted
checks. Each row retains the numeric address, TCP port, state, original UTC check
time, diagnostic and probe ID, exact collector/batch/profile/network scope and
collection completion. Qualified means an actual historical TCP response only:

- `open`: TCP connected; it does not prove which service or device answered;
- `closed`: TCP refused; it is not a listening service;
- `no_response`: a started attempt timed out; firewall/offline conclusions unknown;
- `unavailable`: excluded destination or unavailable local transport;
- `not_started`: no check began before its applicable budget expired.

Coverage says attempted address/port or not checked, never complete host inventory.
All rows are historical; current reachability and identity remain not established.
`device_id` is always null. Existing or conflicting address assignments cannot
attach this evidence to either old or new owners after DHCP/address reuse.

Normal status exposes endpoint-query availability, distinct recorded endpoint
address/port tuples (`endpoint_count`), all historical outcomes
(`endpoint_observation_count`), distinct tuples with at least one historical
response (`responding_endpoint_count`), evidence batches and unprojected batches.
These are separate from identified-device counts. A configured but unstarted
endpoint is not represented as a responder.

## Sharing and upgrades

Profiles can explicitly configure the same physical `store.shared_sqlite_path`.
A fresh second profile can query the same evidence without collection/SSH grants;
knowledge is global to that file, but collection and resume authority stay local.
No config or permissions are copied. A profile using another store sees nothing
from the shared file. Same-UID/native code remains trusted; SQLite is not an OS
security boundary.

Store schema 2 adds only an endpoint-projection table/index and immutable guards.
A writable open transactionally upgrades an existing schema-1 store, preserving
original rows and their immutable triggers. Batch/application envelope versions
remain 1. Read-only opens support schema 1 without migration and report no new
endpoint rows. Upgrade failure rolls back DDL and the version together. New
schema-2 stores are not writable by older Atlas binaries; retain backups and use
a compatible reader rather than attempting a downgrade. No production migration
or live scan is part of the test suite.

SSH greeting/banner reading is deliberately not implemented or enabled in this
slice. Greeting/banner policy or tool arguments, including malformed/oversized
values, fail closed. No application bytes are sent or read, no credentials or
host keys are touched, and an open customary port is not advertised as SSH access.
General service/version/OS/NSE/UDP/vulnerability scanning and external scan-import
pipelines remain deferred.

## Synthetic verification

Run the existing `python3 -m pytest -q` suite on stock supported Hermes. The normal
Docker verifier runs native validate/doctor and that suite with networking disabled.
`tests/test_endpoints.py` covers independent policy, transport outcomes/budgets,
projection and persistence failure/recovery, concurrent resume, query bounds,
address reuse and transactional schema-1 upgrades. The native runtime test runs
actual registered tool/slash/CLI handlers in three fresh fixture-profile processes:
writer A, shared reader B with no grants, and isolated reader C. All socket
transports are non-forwarding synthetic fixtures. This is not live-network,
installation/activation, hosted CI or independent-review acceptance.
