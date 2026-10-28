# Local Discovery and Reconciliation

Collect a bounded LAN observation batch, then explicitly reconcile it into
inventory. See the [operator runbook](operator-guide.md) for installation,
profile selection and a passive-only quick start.

## Explicit lifecycle and policy

`network_discover` takes exactly `network` (configured name) and `mode`
(`passive` or `ping`). Unknown arguments, disabled/unconfigured modes, CIDR/URL/
option strings as network names, IPv6 ping, noncanonical CIDRs and IPv4 ranges
above 256 addresses fail closed. Every invocation validates the current native
`policy` value returned by `ctx.get_config`, using Hermes's settings lifecycle;
see [configuration](operator-guide.md#profile-local-configuration).
Empty allowlists are deny-all. No tool may modify policy or raise its bounds.
Ping also requires a private/link-local scope unless the named network has explicit
public opt-in. Passive mode remains permitted without that opt-in. See
[collection grants](operator-guide.md#collection-grants-and-limits).

Collection finishes before opening a writable store. It atomically inserts an
immutable batch, ordered probe outcomes, parsed observations and batch_stored
local audit event, not canonical inventory. Receipts have batch_id, completion,
per-probe names/outcomes/diagnostic codes/counts, persisted=true, applied=false.
No raw stdout/stderr is retained. Missing tools produce executable_missing;
they are never installed automatically. iproute2 is required for passive mode;
Nmap is optional and required only for legacy ping. Active discovery must be
explicitly enabled by the operator. Opt-in sockets need no ping/Nmap helper.

`network_reconcile` takes only an optional stored batch_id. Omitting it selects
the latest eligible unapplied LAN/SSH batch from this profile, skipping revoked scopes.
The saved network/mode/scope
must still match current local policy. Another profile's shared evidence is
readable knowledge, not permission to apply its batches under this profile.
No probes run during reconciliation. SSH batch application is documented in
[Authorized SSH Inspection](authorized-ssh-inspection.md).

An explicit ID from a revoked scope is refused with the responsible
`network.discovery.passive`, `network.discovery.ping`, or
`ssh.enabled/ssh.hosts.inspect` setting and repair guidance, without changing
stored history. Restore policy only if that collection is still intended, or
select a currently eligible batch; a saved batch never grants authorization.

With a network named `home` enabled in local policy:

    hermes network-atlas discover --network home --mode passive
    hermes network-atlas reconcile --batch-id <returned-batch-id>
    /network discover home passive
    /network reconcile <returned-batch-id>

A successful reconciliation atomically writes canonical evidence references,
assignments, sighting/check clocks, events and an immutable unique application
result. It returns new/changed/unchanged device IDs, typed missing entries,
complete saved conflicts, bounded unresolved samples with full totals, and audit event IDs.
The [uncertainty summary and drilldown](unresolved-evidence.md#compact-uncertainty-and-current-state)
distinguish observations from affected diagnostic subjects without changing identity.
`missing` explicitly means not_observed_in_this_run, never offline/deleted.
The explicit batch-ID replay returns the same projection of the saved application,
including its original applied_at and event IDs, without adding history/events or refreshing
clocks. An omitted ID is a new selection, not an idempotency key. Smaller output
limits can refuse an old large result without altering it; a lowered observations
ceiling can also refuse replay's uncertainty projection even when the saved result
fits the byte limit. See [replay bounds](unresolved-evidence.md#bounds-and-trust).

Reconciliation starts one monotonic operation budget before opening SQLite. The
same absolute deadline covers schema initialization, every lock wait, SQL work,
Python application phases and the precommit check; it is never reset when a
transaction begins. Busy allowances are the lesser of configured busy_timeout_ms
and the remaining budget. SQLite's progress handler interrupts running statements
every 1,000 VM instructions. Expiry rolls back canonical evidence, clocks, audit
events and application metadata, leaving the immutable input batch retryable.
Rollback/connection cleanup is allowed after expiry so locks cannot be stranded.
These are cooperative process/SQLite bounds, not real-time guarantees against OS
descheduling or a blocked filesystem syscall.

Fact ranking uses indexed entity/field-specific history before windowing. Each
touched scalar field is selected once before and once after all its batch copies,
not twice per observation. The report/events describe the final batch change;
intermediate assertions remain immutable history, and field events reference the
selected canonical evidence IDs. Ordinary source precedence/append ordering is
unchanged. A large history may still exhaust the lowered budget and must roll back.

## Fixed transports and enforced bounds

Passive argv is exactly:

    ip -j addr
    ip -j route
    ip -j neigh

These run serially. Route JSON is validated as local metadata only; it never
creates a network target or an inferred routes_via edge. Out-of-selected-scope
local/neighbor addresses are ignored, not imported or probed. Malformed formats,
duplicate JSON keys, excessive records, invalid prefixes/states/MACs or scalar
values fail that probe, not every other successful positive probe.

Legacy active discovery (ICMP disabled and TCP exactly [80,443]) accounts for every
address in the exact configured IPv4 CIDR. Like socket discovery, it excludes
network/broadcast destinations for prefixes below /31 and other special
destinations refused by host transport. /31-/32 addresses remain eligible.
Exclusions use the configured scope, not artificial chunk boundaries: an interior
/28 boundary can be an ordinary host in a /24. It splits the scope in ascending order
into fixed /28 chunks (16 addresses); scopes smaller than /28 are one chunk.
Exactly one owned child runs at a time, with internal Nmap outstanding probes
capped at C=limits.concurrent_probes (1..4):

    nmap -sn -n -PS80,443 -v --host-timeout <configured-seconds>s --max-parallelism <C> --max-rate <8*C> -oX - [--exclude <code-derived-exclusions>] <code-derived-chunk-CIDR>

Targets and optional comma-separated exclusions are derived only from the validated
selected CIDR, never caller strings or routes. All-excluded chunks launch no child.
Aggregate process concurrency is 1; aggregate internal outstanding
probe concurrency is 1*C<=4, not four children each running four probes. The
additional code-owned rate cap is 8*C<=32 packets/second per Nmap invocation;
serial execution prevents rate multiplication across simultaneous children.
Nmap documents this as an average sending-rate cap, not an instantaneous wire-
packet/OS sandbox guarantee (it may catch up after delays); kernel ARP and trusted
executables remain outside such a guarantee. No --min-rate or timing template
forces traffic. Lowering C lowers both internal parallelism and this extra cap.
--max-hostgroup is intentionally absent: Nmap documents it as ineffective for -sn.

The whole chunk is externally bounded by min(command_timeout_seconds,
host_timeout_seconds, remaining transport budget), default at most 10 seconds.
Thus host-discovery internals cannot outlive the existing per-host wall ceiling;
--host-timeout is also retained, not relied on as the sole bound. No timeout,
privilege, supported subnet size or existing resource ceiling was increased.
There is no shell, elevation, arbitrary port range,
script, service/OS scan, UDP probe, target file or automatic installation.
-PS80,443 explicitly overrides Nmap's default discovery probe set: these fixed
TCP SYN/connect probes discover hosts, not services. -sn suppresses port scans;
-n suppresses DNS; XML goes to stdout, not a caller-selected file. Already
privileged Nmap may substitute ARP for directly attached Ethernet targets;
unprivileged execution generally uses TCP connect. No privilege is acquired by
the plugin. Installed executables and PATH are trusted local inputs, not a
sandbox. Reference: https://nmap.org/book/host-discovery-controls.html.

Each chunk must have a successful complete XML summary with total equal to its
non-excluded address count, up+down=total, and up equal to the number of positive host
records. [Verbosity (`-v`)](https://nmap.org/book/output-formats-commandline-flags.html)
requests explicit down-host records and native reasons;
every non-excluded address must appear exactly once. Omitted down hosts do not
establish coverage. A down host with `no-response` is a completed check, not an
offline assertion. Native route errors (`net-unreach`, `no-route`, `reject-route`)
produce `unavailable/nmap_route_unavailable`; other unavailable or unknown down-host
reasons produce `unavailable/nmap_discovery_unavailable`. These diagnostics apply
only to the affected address: valid positives and completed no-response checks in
the same fully validated chunk survive. Skipped targets or omitted
host records produce `unavailable/nmap_incomplete_coverage`. This uses native XML,
not raw stderr matching or a separate route probe. Raw diagnostics remain discarded.
The whole chunk is validated before any address evidence is accepted.
Every host must have exactly one numeric IPv4 address inside the requested chunk,
one valid status, no timeout marker and at most one MAC. Duplicate host/IP/status/
runstats records, other address families, inconsistent/truncated output and
out-of-chunk injection are refused. UTF-8 byte, element and observation bounds
remain enforced. Only the literal empty <!DOCTYPE nmaprun> is accepted; external
DTDs, internal subsets, ENTITY declarations, UTF-16/NUL tricks are refused.
Reported MACs anchor identity; IP-only responses remain unresolved evidence.
Unprivileged/off-link Nmap often cannot report a MAC: the atlas does not guess
that an existing owner of a responding IP is the same device, or import stale
neighbor MACs to manufacture certainty. An IP response can prevent a false
absence report but cannot refresh an unidentified owner's last_seen.

Defaults/hard ceilings stay in validated Limits: 15 seconds per command,
10 seconds per active host, 120 seconds per operation, 4 concurrent probes,
1 MiB combined stdout/stderr per command, 4096 observations/probe outcomes per
batch, and lowerable input/response/query/busy limits. Whole-operation monotonic
time is shared across all children; queued work cannot spawn after expiry.
Collection reserves a bounded slice for SQLite finalization, lowers busy waits
to the remaining budget, and checks the deadline before commit. Parsing and
aggregate observation overflow fail probes; overflow disqualifies exact coverage.
Every active address gets an outcome, and a separate ping_coverage probe succeeds
only when every address check succeeded. Per-address ping_0..ping_N records
retain their legacy shape; a successful chunk derives checked-not-observed outcomes
only for explicit completed no-response records, not fake host observations.
Excluded addresses retain `unavailable/destination_excluded`, never success. As on
the socket path, they make /24 (and other prefixes below /31) scope coverage partial
even when all eligible checks completed, so these ordinary subnets cannot report
whole-scope `missing` devices. Complete /31-/32 scopes can still report
`not_observed_in_this_run`. All non-excluded addresses of a failed chunk
remain unknown with that failure's outcome: a chunk timeout does not attest that
each individual address received a packet before cancellation. Earlier completed chunks retain their
positive evidence even if a later chunk times out or produces invalid/output-limit
XML. An interrupted chunk's unfinished XML is not salvaged as complete evidence.
Partial/failed scans cannot assert
absence even when they contain useful positive observations.

Deadline accounting distinguishes not_started/operation_deadline_exceeded (no
child launched for this work), timeout/deadline_exceeded (a launched child killed
at its effective deadline), and success/completed_at_boundary (complete transport
and valid parse retained even if cleanup/postprocessing crossed the transport
boundary). Valid all-no-response XML can establish completed checks without any
positive observation; an empty host list or zero scanned targets cannot. Zero
observations alone is never the failure criterion. No later chunk starts after the
shared transport deadline; the runner also rechecks immediately before spawning.
Persistence still must fit the whole-operation
budget and is atomic: receipt/output/SQL/operation failure rolls back without
claiming a persisted batch or changing prior history. Bounds are cooperative,
not a guarantee against OS descheduling between the last check and a syscall.

A /24 uses 16 serial chunks; a /25 uses eight; smaller scopes never expand.
Completed chunk evidence survives later failures, but collection does not resume
across batches. Fixed chunk size 16 and rate factor 8 do not guarantee real-world
/24 completion: slow/failing networks or lowered limits may leave partial results.

The runner is POSIX with waitid/WNOWAIT (tested on Linux). It uses shell=False,
null stdin, closed inherited descriptors and a new owned process group. Output
is read incrementally with a combined byte cap. Deadline/output/interrupt and
normal exit cleanup SIGKILL the owned group and reap the direct child. WNOWAIT
retains the leader PID until group cleanup, preventing PID-reuse signalling of
an unrelated group. Descendant SIGKILL scheduling is asynchronous; orphan reaping
belongs to init. Deliberately self-detaching executables are outside the trusted
fixed-command contract, not a claimed OS sandbox. Unsupported runners fail
usefully without launching a child. No subprocess runs under a DB write lock.

## Opt-in ICMP/TCP host discovery

Network-local policy selects direct socket collection whenever
icmp_echo is true or tcp_ports differs from [80,443]. Both socket and legacy Nmap
paths require current scope admission; old Nmap evidence is never reinterpreted.
See [host-discovery-policy.md](host-discovery-policy.md)
for the controlling datagram-only permission, strict four-port cap/4403 exclusion,
shared deadline/rate/concurrency/receive/result budgets and fair scheduling.
2222 and optional 22000 are operator examples, not global defaults or services.

Each enabled method has immutable probe/port/time/diagnostic evidence. Successful
TCP connect or refusal and a matching header-only ICMP reply qualify a host
response; neither infers device identity, application identity, access or topology.
Aggregate ping_<index> records count each configured address once. They contain no
duplicate observations; contributing positives remain on method probes. Distinct
responding_address_count is separate from address_count, method attempt count,
total_count (including coverage) and observation count. A failed method may coexist
with positive response evidence and a failed aggregate check. Excluded endpoints
make opt-in /24 coverage partial even when every ordinary host responds.

No response remains uncertainty: firewall policy, routing, loss and timing can
look alike. A requested method name is not proof of transmission. Disabled methods
are not attempted; unavailable diagnostics do not establish complete coverage.
Neither packet-free capability open/close nor a privileged preinstalled ping
executable proves Atlas transport. No helper, raw fallback or privilege change is
selected. TCP connects can affect connection-limited endpoints despite no payload;
the hard 4403 exclusion is not a guarantee that all other endpoints are harmless.

## Identity, address sets and freshness

A unique stable MAC resolves an interface, then its owner. A previously unknown
stable MAC creates a UUID device/interface; address/name strings never merge
records. Randomized/multicast/zero/colliding MACs and IP-only observations remain
unresolved with bounded candidate IDs. Equal-rank fact disagreements and address
ownership conflicts remain visible, never resolved by presentation ordering.

Local ip addr output provides direct same-host evidence: multiple new stable
interfaces can belong to one local device, or join one existing anchored owner
when all existing resolved interfaces agree. Contradictory existing owners are
reported and never merged or stripped of interfaces. Remote neighbors never
become interfaces of the local host merely because it reported them. No physical
or hosting topology is fabricated by these collectors.

Distinct local interface names sharing a MAC are not a unique identity anchor.
Reconciliation preflights the entire batch before applying any observation: all
observations for that MAC remain unresolved, with a duplicate_local_interface_mac
conflict and the local names retained. Existing interfaces, addresses and clocks
are not overwritten by that ambiguous evidence. Row reversal cannot select a
winner. Multiple addresses on one named interface are not a MAC collision. The
parser rejects duplicate interface names, and retains colliding local names even
when one has no selected-scope address; it still excludes out-of-scope IPs.
These protections apply to legacy unapplied batches that retain distinct names.

Observations are immutable: reconciliation appends canonical references retaining
batch/probe/source/time/qualification/neighbor state, not edits to raw evidence.
Operator assertions and losing values survive. Current assignment sets are
additive. A new ping/neighbor IP does not end another valid IPv4/IPv6 assignment;
complete ping is not a same-interface address inventory. Historical transitions
remain explicit operator end-address actions. Assignment times
are evidence effective times, not claims of reachability; older batches cannot
regress device or assignment clocks. IP movement preserves the same interface/
device ID and old evidence; a new MAC at an old IP creates a conflict, not a stolen
identity. Query exposes batch_id, neighbor_state, observed_in_batch and
reachable_by_this_probe separately from current assignment membership.

Successful local-interface metadata qualifies local presence only. Passive
cached neighbors (even REACHABLE) never qualify last_seen or prove current
reachability/inventory. FAILED/INCOMPLETE neighbors cannot refresh last_checked.
Successful parsed cached-address checks can update last_checked, not last_seen.
Successful identified ping responses update first_seen/last_seen/last_checked
monotonically. A successful complete exact scan checks known scoped addresses;
no responding address for a device reports not observed in that run. It is not
immediate staleness or deletion and says nothing about unrelated scopes.

Freshness uses an injectable UTC clock and stale_after_days (default 14).
Never-seen operator/cached records stay known; previously seen records become
stale only after the age threshold. Query/map compute age read-only. Explicit
reconciliation persists freshness transitions as audit events (no schema
migration is needed); reappearance advances clocks/status, but never reverses
operator retirement. Natural age transitions can be recorded even when a failed
batch provides no new sightings; failure itself is not evidence of absence.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for isolated behavioral tests and
[SECURITY.md](../SECURITY.md) for the trust model and verification limits.
