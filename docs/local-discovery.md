# Local Discovery and Reconciliation (Phase 2)

Phase 1 Atlas Core and Phase 2 are implemented; V1 is not complete or released.
SSH transport, cumulative PM-managed install/enable acceptance, integration,
publication and live activation remain separate gates. No real LAN was scanned
and no live profile was installed, changed, seeded or restarted for this work.

## Explicit lifecycle and policy

`network_discover` takes exactly `network` (configured name) and `mode`
(`passive` or `ping`). Unknown arguments, disabled/unconfigured modes, CIDR/URL/
option strings as network names, IPv6 ping, noncanonical CIDRs and IPv4 ranges
above 256 addresses fail closed. Policy is reloaded from the registration
profile's operator-owned network-atlas/config.yaml for every invocation.
Empty allowlists are deny-all. No tool may modify policy or raise its bounds.

Collection finishes before opening a writable store. It atomically inserts an
immutable batch, ordered probe outcomes, parsed observations and batch_stored
local audit event, not canonical inventory. Receipts have batch_id, completion,
per-probe names/outcomes/diagnostic codes/counts, persisted=true, applied=false.
No raw stdout/stderr is retained. Missing tools produce executable_missing;
they are never installed automatically. iproute2 is required for passive mode;
Nmap is optional and ping must be explicitly enabled by the operator.

`network_reconcile` takes only an optional stored batch_id. Omitting it selects
the latest eligible unapplied LAN batch from this profile, skipping revoked scopes.
The saved network/mode/scope
must still match current local policy. Another profile's shared evidence is
readable knowledge, not permission to apply its batches under this profile.
No probes run during reconciliation. SSH batch application remains Phase 3.

Equivalent commands (synthetic examples, not permission for live effects):

    hermes network-atlas discover --network lab --mode passive
    hermes network-atlas reconcile --batch-id <returned-batch-id>
    /network discover lab passive
    /network reconcile <returned-batch-id>

A successful reconciliation atomically writes canonical evidence references,
assignments, sighting/check clocks, events and an immutable unique application
result. It returns new/changed/unchanged device IDs, typed missing/conflicting
entries, unresolved evidence IDs/candidate device IDs, and audit event IDs.
`missing` explicitly means not_observed_in_this_run, never offline/deleted.
The explicit batch-ID replay returns the exact saved result, including its
original applied_at and event IDs, without adding history/events or refreshing
clocks. An omitted ID is a new selection, not an idempotency key. Smaller output
limits can refuse an old large result without altering it.

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

Active discovery enumerates every address in the exact configured IPv4 CIDR,
including network/broadcast addresses, and invokes one bounded host-discovery
command per address, with at most concurrent_probes owned children (default 4):

    nmap -sn -n -PS80,443 --host-timeout <configured-seconds>s --max-parallelism 1 -oX - <code-derived-numeric-address>

Targets are derived only from the validated selected CIDR, never caller strings
or routes. This per-host shape enforces a real per-host wall deadline instead
of trusting that a single whole-range Nmap process applies --host-timeout to all
of its discovery work. There is no shell, elevation, arbitrary port range,
script, service/OS scan, UDP probe, target file or automatic installation.
-PS80,443 explicitly overrides Nmap's default discovery probe set: these fixed
TCP SYN/connect probes discover hosts, not services. -sn suppresses port scans;
-n suppresses DNS; XML goes to stdout, not a caller-selected file. Already
privileged Nmap may substitute ARP for directly attached Ethernet targets;
unprivileged execution generally uses TCP connect. No privilege is acquired by
the plugin. Installed executables and PATH are trusted local inputs, not a
sandbox. Reference: https://nmap.org/book/host-discovery-controls.html.

Each numeric target must have a successful complete one-target XML summary,
consistent up/down/total counts, non-timeout host data and only that IP. XML
entities, inconsistent/truncated output and out-of-target injection are refused.
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
only when every host command/parse succeeded. Partial/failed scans cannot assert
absence even when they contain useful positive observations.

The runner is POSIX with waitid/WNOWAIT (tested on Linux). It uses shell=False,
null stdin, closed inherited descriptors and a new owned process group. Output
is read incrementally with a combined byte cap. Deadline/output/interrupt and
normal exit cleanup SIGKILL the owned group and reap the direct child. WNOWAIT
retains the leader PID until group cleanup, preventing PID-reuse signalling of
an unrelated group. Descendant SIGKILL scheduling is asynchronous; orphan reaping
belongs to init. Deliberately self-detaching executables are outside the trusted
fixed-command contract, not a claimed OS sandbox. Unsupported runners fail
usefully without launching a child. No subprocess runs under a DB write lock.

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

Observations are immutable: reconciliation appends canonical references retaining
batch/probe/source/time/qualification/neighbor state, not edits to raw evidence.
Operator assertions and losing values survive. Current assignment sets are
additive. A new ping/neighbor IP does not end another valid IPv4/IPv6 assignment;
complete ping is not a same-interface address inventory. Historical transitions
remain explicit operator end-address actions in this milestone. Assignment times
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

## Verification and remaining gates

Use an existing compatible admitted Hermes interpreter read-only and a declared
scratch TMPDIR. No live home/config/atlas is a test fixture. Canonical command:

    python3 scripts/verify.py
    python3 -m unittest discover -s tests -p 'test_discovery*.py' -v
    python3 -m unittest discover -s tests -p test_runtime.py -v

A03: current allowlists/modes, no raw targets/options/policy inputs, configuration
CIDR/IPv4/IPv6 and lowered bounds. A07: immutable new/changed/unchanged/missing/
conflicting results, interface identity, multi-address sets, partial/failed scans,
cached/failed neighbors, stale/never-seen/reappearance/retirement, old batches and
idempotent replay. A08: exact argv, bounded machine-readable parsing, malicious
output, actual output/host/operation deadlines, concurrency, direct-child reaping,
descendant group cleanup and unrelated-process control, missing dependencies.
A10: atomic rollback/receipt overflow, write-lock exclusion during subprocesses,
busy writer retry, immutable application persistence and fresh native reopen.
These are tests/test_discovery.py, tests/test_discovery_extra.py and the actual
native fixture in tests/test_runtime.py / scripts/runtime_smoke.py. The native
loader/registry/handlers are real; transport is a scratch-only executable fixture
scripts/offline_probe.py, never the host's real ip/Nmap. Reopen removes that fake
binary and uses a fixture-only PATH to prove stored querying/replay without
collection. Synthetic output is explicitly a fixture, not reported live evidence.

Phase 1 checks remain in the same verifier. Existing schema version 1 is retained.
Full PM-managed install/enable, three-alias SSH transport and cumulative A13 V1
acceptance remain downstream. GitHub CI, other runtime combinations, real network
reachability, publication, main advancement and live activation are unperformed.
