# Durable native TCP endpoint checks

Illustrative receipt for a two-address, two-port check:

```json
{"batch_id":"<returned-id>","persisted":true,"applied":true,"projected":true,
 "queryable":true,"stage":"queryable","collection_performed":true,
 "completion":"complete","observation_count":4,
 "state_counts":{"open":2,"closed":2,"no_response":0,"unavailable":0,"not_started":0}}
```

`persisted` means the immutable batch is saved; `applied`/`projected` mean its
endpoint rows committed; `queryable` means fresh readback verified the batch.
Collection completion is separate: failed checks can still be saved and queried.
These are historical TCP outcomes, not service identification or device identity.

If `persisted=true` but `queryable=false`, save the returned batch ID and run
`hermes network-atlas resume-endpoints <returned-id>` (or
`/network resume-endpoints <returned-id>`). Do not rescan to finish projection or
readback. Resume never recollects and cannot duplicate rows or audit events.
The receipt's `stage` and flags retain the actual committed progress on failure.

## Operator policy

Endpoint checking has its own opt-in grant on each named IPv4 network. Existing
`discovery.ping`, `discovery.tcp_ports`, ICMP and SSH permissions do not enable it.
No policy means no endpoint traffic.

```yaml
version: 1
networks:
  home:
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
TCP defaults remain unchanged. Older Atlas versions reject these new policy keys.

Callers select a configured name, never addresses, ports, commands or bounds.
Operator limits can only lower V1 ceilings. Checks share one operation deadline,
concurrency/rate limit (at most 32 starts/second) and nonrenewing per-host budget;
fair reduced attempt deadlines leave time for later ports and durable storage.
There are no retries, helper processes, DNS/ICMP prerequisites or raw sockets.
Owned sockets close on completion or interruption.

The TCP handshake itself may consume connection slots or cause remote logs and
kernel retransmissions. This is not a zero-effect probe. 4403 is excluded at both
policy and socket boundaries because connection contention can affect radio
clients. Other sensitive endpoints remain an operator selection risk.

## Commands and recovery

The model tool is `network_check_endpoints` with exactly one selection:
`{"network":"home"}` to collect, or `{"batch_id":"<returned-id>"}` to resume.
The same operation is exposed through the native local CLI and slash command:

```sh
hermes network-atlas check-endpoints home
hermes network-atlas resume-endpoints <returned-id>
```

```text
/network check-endpoints home
/network resume-endpoints <returned-id>
```

`collection_performed` is false on resume. `completion` is complete only when
every eligible check connected or was refused, partial when some succeeded, and
failed when none succeeded (including zero eligible work). Excluded destinations
do not prevent completion; they remain in immutable history and final
`state_counts`/`observation_count` alongside every failed or unstarted check.

Resume requires the original profile and matching local network/port policy.
Revocation preserves historical query access but cannot authorize projection.
An `endpoint policy` recovery error includes removed/disabled networks, changed
CIDRs and changed port grids. Restore the original authorization only if still
appropriate, then resume the saved batch; do not delete history or recollect.
Changed authorization is reported before observation-budget limits, even if a
larger CIDR or port list exceeds the existing budget. With unchanged authorization,
an observation-grid budget refusal names `limits.observations`, not network/port
authorization. If lowered record/output limits prevent recovery, restore sufficient limits
within existing ceilings. No automatic policy expansion occurs. A failure before
persistence cannot promise a recoverable ID; another collection is a new check.

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
- `no_response`: connect timed out or reported host unreachable (`tcp_host_unreachable`);
- `unavailable`: excluded destination or unavailable local transport;
- `not_started`: no check began before its applicable budget expired.

Host unreachable is a timeout-style result of connect/SO_ERROR, not a local
socket-setup failure. It does not prove a SYN was sent or a host is absent.
The shared host-discovery transport reports this same diagnostic without
creating positive response evidence. Permission, protocol and other local socket
failures remain distinct unavailable diagnostics.

Coverage says connect attempted or not checked, never complete host inventory.
All rows are historical; current reachability and identity remain not established.
`device_id` is always null. Existing or conflicting address assignments cannot
attach this evidence to either old or new owners after DHCP/address reuse.

Normal status exposes distinct recorded endpoint
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
a compatible reader rather than attempting a downgrade.

SSH greeting/banner reading is not supported; those inputs fail closed. No
application bytes are sent/read, no credentials or host keys are touched, and an
open customary port does not grant SSH access. Service/version/OS/NSE/UDP and
vulnerability scanning or external scan imports are outside this feature.
