# Host-discovery policy and bounded transport

Host discovery records address responses, not services or device identity.
Passive collection and legacy TCP 80/443 discovery remain available alongside
explicitly enabled ICMP/TCP socket methods.

## Operator authority and schema

Configuration version 1 supports these network-local keys:

    networks.<name>.discovery.icmp_echo: false
    networks.<name>.discovery.tcp_ports: [80, 443]

`ping` is the explicit active-discovery setting; passive permission does not
imply active permission. `icmp_echo` is a strict boolean, default false.
`tcp_ports` is a YAML/JSON list of at most **4** distinct strict integers in
1..65535, default [80, 443]. Strings, booleans, floats, ranges, null, mapping,
sets, tuples, duplicates, unknown keys and over-cap lists fail closed. The
validated tuple is sorted and immutable; caller list edits cannot alter grants.
An empty list disables TCP, allowing ICMP-only policy. `ping: true` with no TCP
ports and ICMP disabled is invalid. `icmp_echo: true` requires `ping: true`.
Explicit TCP lists can be configured behind `ping: false` but authorize no traffic.
IPv6 ICMP/active discovery is refused; IPv6 remains passive/storage-only.

TCP **4403** (Meshtastic) is a code-enforced sensitive exclusion, rejected even
in an operator list. There is no exclusion override, helper path, capability
selector, payload, rate, probe option or method argument on model/CLI surfaces.
No other port is inferred from discoveries, stored facts, aliases, services or
previous success.

For example, synthetic `192.0.2.0/29` policy may select `ping: true`,
`icmp_echo: true`, `tcp_ports: [80, 443, 2222, 22000]`. 2222 and optional 22000
are examples, not global defaults, live policy changes or evidence of services.
All original scope, timeout, concurrency, output, observation and rate ceilings
remain. A range is still at most 256 IPv4 addresses; lists are per named network,
never global. Every invocation reloads local policy; shared evidence cannot
transfer permission. Legacy files omit the new keys and retain exactly the
existing Nmap TCP 80/443 request with no implicit ICMP or extra ports. Old
binaries reject these additive config keys; deliberately update readers first.

## ICMP datagram sockets and capability diagnostics

Atlas uses Linux `AF_INET/SOCK_DGRAM/IPPROTO_ICMP` echo
sockets only, under the process's already-existing kernel/security permission.
No raw sockets, new capabilities, sudo, sysctl/kernel/firewall changes, capability
installer, execution with an elevated file-owner identity or Nmap `-PE` fallback.
An unavailable ICMP method does not suppress a permitted TCP method. ICMP-only
unavailable collection is an honest failed/partial attempt, not a reason to weaken
permission.

The internal packet-free capability diagnostic is not a registered tool. When
disabled it opens nothing. Unsupported platform and expired budget
also open nothing. On Linux it opens and immediately closes exactly one ICMP
datagram socket, without bind/connect/send/receive/DNS. It does not read profiles,
`/proc` permission settings, executable paths or live network state. Tests mock
this boundary; tests never open a real echo socket.

The diagnostic reports:

| State | Diagnostic | Meaning |
| --- | --- | --- |
| disabled | icmp_disabled | No active grant; no socket attempted |
| not_started | operation_deadline_exceeded | Shared budget expired before open |
| unavailable | icmp_platform_unsupported | Only Linux echo-datagram semantics supported |
| unavailable | icmp_permission_denied | Existing permission denied; no fallback |
| unavailable | icmp_protocol_unsupported | Kernel/socket protocol unsupported |
| unavailable | icmp_socket_open_failed | Other bounded OS/resource failure |
| unverified | icmp_socket_opened_transport_unverified | Socket creation permitted, transport NOT proven |

Linux ping_group_range, credentials, namespace, LSM and seccomp can affect socket
creation. Reading one setting cannot prove effective permission. A successful
open does not prove that binding, sending, routing, firewall policy, reply
receipt or target reachability will work. Capability cannot be established fully
until an explicitly authorized bounded transport attempt; recheck runtime errors
rather than caching open success as authority. Diagnostics never retain raw OS
error strings. Interruption propagates and context-manager closure owns cleanup.
No dependency on an external ping executable is introduced.

## Combined budgets and evidence

Legacy default policy uses the serial Nmap /28 argv in
[local-discovery.md](local-discovery.md), including existing ARP caveats. Opt-in
multi-method policy uses code-owned numeric IPv4 destinations from the selected
validated CIDR, direct TCP connect attempts on the validated tuple and ordinary
ICMP echo-datagram attempts. No application writes/handshakes, discovery payloads,
TCP banner reads, UDP, DNS, service/version/OS/NSE scanning or invented identity.
ICMP sends only the 8-byte echo header (one request, no data payload); replies
must match numeric source, echo type/code and owned identifier/sequence. Reject
out-of-scope, multicast and broadcast destinations before socket transport;
account excluded addresses without pretending they were checked.
Opt-in socket collection also excludes loopback, unspecified and reserved
destinations. Network/broadcast endpoints are excluded for prefixes below /31;
/31 and /32 retain their ordinary host-address semantics. Those excluded method
records make coverage partial/failed, including an otherwise responsive /24.
Legacy Nmap accounting remains unchanged rather than rewriting its semantics.

All methods and ports consume ONE monotonic operation deadline (<=120s), ONE
aggregate outstanding-probe ceiling (<=4), ONE aggregate initiation-rate cap
(<=8*C attempts/s), and shared output/result/observation bounds. Per-address
wall time from its first attempt is <=min(host timeout, command timeout,
remaining transport budget); no fresh host budget for each port or method.
Capability checks, scheduling, parsing and cleanup also consume that deadline.
Reserve persistence time using the existing collector rule; no network work
under DB write locks. Scheduling must give later addresses opportunities rather
than allocating the entire operation to the first method or ports; bounded
round-robin address/method scheduling is required. No method retries beyond one
attempt per address/port. Socket closure owns cancellation; any legacy child
still uses the reviewed terminate/reap process-group runner. Kernel TCP/ARP
retransmits are not a promised instantaneous wire-packet sandbox. No real-world
/24 completion or reachability guarantee is made.

The implementation uses windows no larger than C addresses with rotated first
methods and address/method passes within each window. It spaces initiation by
1/(8*C) seconds with no burst. Each attempt additionally gets at most
min(host,command)/(enabled-method-count+1) seconds, clipped to that host's
original deadline and the shared transport deadline. This deliberate reduction
reserves opportunities for other methods; rate waiting still consumes host time.
There are no per-method operation deadlines, retries or independent concurrency.
Expired queued methods report not_started/host_deadline_before_start; socket
timeouts report timeout/effective_transport_deadline. A successful TCP connect
or ECONNREFUSED qualifies as host response, never proof of a service. Other
OS failures are unavailable with bounded diagnostics, never raw error text.
Datagram replies must be exactly eight bytes with a valid Internet checksum;
unrelated replies consume the SAME receive-byte budget and are ignored. Exhaustion
closes owned sockets and leaves explicit output_limit outcomes. TCP does no
application write/read; Linux kernel handshake/retransmission behavior is not
claimed under instantaneous application control.

Keep schema version 1 and immutable historical batches unchanged. New method
probes use `icmp_<address-index>` and `tcp_<port>_<address-index>`; contributing
positive observations live on those method probes with their own UTC times,
`ping_response` evidence and existing unresolved address anchors. Method/port is
code-owned probe provenance, never a service/identity assertion. Keep aggregate
`ping_<address-index>` records (no duplicated observations) and `ping_coverage`
so address_count counts hosts once, not attempts, ports or coverage. Retain all
contributing positives; deduplicate address-level views, not immutable evidence.
Legacy Nmap `ping_<index>` observations retain legacy/unspecified-method meaning;
never retrospectively relabel them ICMP or a particular responding TCP port.

Use existing success/unavailable/timeout/not_started/command_failed outcomes
with bounded native diagnostics for disabled/unavailable/excluded/checked-no-
response distinctions, not new persisted enums. Disabled methods are disclosed
from policy, not executed. Excluded addresses use unavailable diagnostics and
never qualify absence. A method success with no response is a completed check,
not a positive host. Failed chunks cannot attest per-address packets. Whole-batch
completion and exact coverage must fail conservatively if any enabled method is
unavailable, timed out, excluded or not started; positive evidence from another
method survives. Partial/failed batches remain absence-ineligible. The worst-case
aggregate, method and coverage probe count is checked against the lowered observation
ceiling before transport; aggregate observation limits also apply.
IP-only responses do not create devices, refresh an assumed IP owner, infer
access or manufacture topology. Original/later unresolved lineage stays intact.

## Counts, transmission evidence and limitations

`address_count` counts aggregate ping_<index> records, including excluded and
not-started addresses. `address_outcome_counts.success` counts completed aggregate
checks, not responders. `responding_address_count` deduplicates qualifying positive
address observations across all contributing methods. `total_count` includes every
method record, aggregate and synthetic coverage; observation counts retain each
positive method separately. For two /31 hosts and ICMP plus four TCP ports there
are 13 probe records and, if every method responds, 10 observations but only two
responding addresses. A TCP refusal qualifies a response, not a listening service.

A probe name records a requested method, not a wire-packet receipt. Disabled
methods do no work and are disclosed by policy. not_started means no send/connect
was initiated. unavailable can happen at open, bind or transport: it does not
prove a packet was transmitted. timeout follows an initiated owned attempt but
cannot prove what traversed the firewall or reached the target. A matching ICMP
reply or connect/refusal result is actual response evidence for that method at
its original UTC time, not current reachability. Legacy Nmap success attests a
completed chunk/check, not individual transmitted packets or a responding method.
No historical evidence is upgraded from requested flags to ICMP proof.

ICMP, web TCP and extra ports can all be filtered or rate-limited. No reply cannot
identify UFW, distinguish loss/routing from filtering, or prove a host offline.
TCP connection attempts can contend with client limits or cause endpoint logs
and kernel retransmissions without application payloads. Excluding 4403 avoids
the known single-client radio transport risk; it is not an assurance that every
other TCP port is harmless. No Syncthing, SSH, Meshtastic, service or identity is
inferred from port numbers or replies. No UDP discovery is included.

## Operating safely

Choose the profile, named network/CIDR and methods/ports deliberately before
collection, excluding connection-sensitive endpoints. Begin with a small scope
and inspect the returned batch's outcomes, original times, exclusions and
not-started work. Read stored evidence before repeating collection. Reconciliation
is a separate write; it does not resolve an identity from an IP alone. Keep real
policy, addresses and evidence private. The [operator runbook](operator-guide.md)
contains the collection commands; [SECURITY.md](../SECURITY.md) covers trust and
verification limits, and [CONTRIBUTING.md](../CONTRIBUTING.md) covers tests.

## References

- https://man7.org/linux/man-pages/man7/icmp.7.html (Linux echo socket permissions)
- https://man7.org/linux/man-pages/man8/ping.8.html (iputils payload, flags and privileges)
- https://nmap.org/book/host-discovery-controls.html (explicit probe/ARP behavior)

Echo datagrams work only where existing OS permissions permit them. An unavailable
diagnostic is not a request to change privileges or firewall/kernel settings.
