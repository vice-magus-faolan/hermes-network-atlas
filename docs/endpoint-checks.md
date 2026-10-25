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
`{"network":"home"}` to collect, `{"batch_id":"<returned-id>"}` to resume,
`{"preview_batch_id":"<returned-id>"}` to preview remaining work, or
`{"continue_batch_id":"<returned-id>"}` to explicitly make new TCP checks.
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

## Continue unfinished work — new traffic

After a timed-out collection, use its saved ID. First resume it if projection or
readback failed. Then preview, explicitly continue once, and inspect the returned
successor ID:

```sh
hermes network-atlas preview-endpoints BATCH_ID
hermes network-atlas continue-endpoints BATCH_ID
hermes network-atlas preview-endpoints SUCCESSOR_BATCH_ID
```

Slash equivalents are `/network preview-endpoints BATCH_ID` and
`/network continue-endpoints BATCH_ID`. Preview is read-only: no transport,
database creation/upgrade, evidence changes or policy changes. `remaining` lists
up to the configured query-result cap; `omitted_remaining` counts the rest.
`progress.scope=selected_batch_ancestry` labels the selected batch and its ancestors,
not its latest descendants. Its historical `total`, `attempted`,
`responded`, `still_unattempted`, `excluded` and non-excluded `unavailable` counts
describe that selection only. An old root's counts do not reflect later progress;
select the returned `successor_batch_id` and repeat as needed to inspect later runs.
Attempted counts open/closed/no-response connects, not unavailable local transport.

Continue makes NEW TCP traffic only for saved `not_started` tuples. It never
retries open, closed, no-response or unavailable results, and never contacts
excluded destinations. Current profile ownership and the exact original named
network, CIDR and port grant must still match; evidence or another profile cannot
grant access. The original grid must still fit `limits.observations`. All existing
invocation deadlines, concurrency/rate, socket cleanup and output/record ceilings
still apply, with the [continuation persistence reserve](#continuation-persistence-reserve)
described below. A continuation can remain partial: inspect its successor preview
before choosing another explicit invocation. No scheduler or automatic retry exists.

Original batches, completion, applications and probe timestamps stay unchanged.
Successors store only their selected subset with new times; endpoint query rows
carry `parent_batch_id` (null for original runs). Cumulative progress combines
historical runs, not a simultaneous census, current reachability or device identity.
An `exhausted` selection means no continuable work, not that every endpoint answered.

The immutable reservation and exact saved subset establish parent/child order;
UTC timestamps are historical evidence, not a causal clock. A backward UTC step
between runs or between reservation and child start does not invalidate a legitimate
saved successor. Times are never clamped or rewritten, and timestamp-sorted query
rows can therefore place a successor before its parent. Ancestry progress follows
the reservation links instead. Operation and host deadlines use monotonic time.
Within each batch, probe times must still be ordered inside the batch envelope.
A clock reversal during collection that violates that envelope prevents saving
the child; its reservation remains uncertain, with no automatic recollection.

Each parent reserves at most one immutable successor before traffic. Repeating or
concurrently continuing that same parent never recollects: it returns the saved
successor's no-contact recovery result, or `uncertain` if the reserved child is not
durable. Preview reports `continued` and `successor_batch_id` for a saved successor;
select that ID to make further progress. If projection failed, resume that child.
An uncertain reservation can mean active collection OR a producer that crashed,
was interrupted or failed to save. Confirm that the original producer exited or
reached its original operation deadline, then preview the parent again. A claim's
creation time and a newly lowered current timeout do not establish that original
deadline. Waiting or previewing cannot restore unsaved evidence. Do not start
another full check to bypass the reservation. If no child was saved after the
producer ended, retain the parent and reserved child IDs: effects are unknown,
no child can be resumed, and the reservation is not cleared.
Do not delete history or assume nothing ran. A separately chosen new full check
can repeat prior contacts; it is not recovery. This is not crash-exactly-once TCP.
`limits.observations` bounds each batch and the original authorized grid, not the
sum of historical rows. Superseded `not_started` rows do not consume a cumulative
quota. Complete ancestry validation counts against the real operation deadline.
Continuation refuses before reservation or traffic if validation leaves
insufficient time for useful collection and its persistence reserve. After this
validation-budget refusal, no successor is reserved and no endpoints are contacted.
If `limits.operation_timeout_seconds` was lowered, the operator can explicitly
increase it within the existing **120-second ceiling**, then repeat
`continue-endpoints` with the **same saved batch ID**. Atlas never raises it
automatically. If already at the ceiling, retain the saved IDs/history and report
the capacity limit for operator review; do not delete/reset evidence or start a
full rescan to bypass it.

### Continuation persistence reserve

Continuation always reserves one quarter of `limits.operation_timeout_seconds`
for persistence, even when `limits.busy_timeout_ms` is lowered. A full check instead
reserves the smaller of `limits.busy_timeout_ms / 1000` seconds and that quarter.
With the defaults (120 seconds overall, 5000 ms busy timeout), collection deadlines
are **90 seconds for continuation versus 115 seconds for a full check**, measured
from operation start. Validation and reservation consume part of that same window;
these are not promises of that much socket time or complete coverage.

An admitted run reuses its request-local validated ancestry for its exact reserved child's
save/projection; cold recovery independently validates history. Per-batch reads
and retained probe objects are bounded, with a separate structural limit of 4096
batches (including the root). That structural limit is not an execution-time
guarantee: large retained or zero-progress histories can exhaust the time budget
first. A structural-limit
refusal names the batch bound: retain the saved IDs/history for operator review,
not deletion or a full rescan. If a lowered `limits.observations` blocks the original
grid, check that setting against the grid before retrying within the hard ceilings.

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

Store schema 2 adds the endpoint projection; schema 3 adds immutable continuation
reservations. A writable open transactionally upgrades schema 1 or 2, preserving
original rows and their immutable triggers. Batch/application envelope versions
remain 1. Read-only opens support schema 1 and 2 without migration (schema 1 has
no endpoint rows). Upgrade failure rolls back DDL and the version together.
Schema-3 stores require compatible readers AND writers. Retain backups and update
all shared-store readers and writers before any writer upgrades the database,
rather than attempting a downgrade. An older writer may contact endpoints before
discovering that it cannot persist to the upgraded store.

SSH greeting/banner reading is not supported; those inputs fail closed. No
application bytes are sent/read, no credentials or host keys are touched, and an
open customary port does not grant SSH access. Service/version/OS/NSE/UDP and
vulnerability scanning or external scan imports are outside this feature.
