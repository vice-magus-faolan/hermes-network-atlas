# Security boundaries

Network Atlas observes and remembers; it does not administer infrastructure.
V1 must enforce allowlisted named networks, authorized SSH aliases, fixed
read-only probes, strict host keys, bounded subprocess execution/output, and
transactional provenance/history. It is not a generic shell, vulnerability
scanner, or privileged network manager.

Native plugin code, the local operator, installed executables, and the operator's
SSH configuration are trusted. The plugin is not an OS sandbox for other Hermes
tools or same-UID processes. Remote output and discovered labels are untrusted.
An SSH allowlist restricts this plugin, not every ability of the agent account.
Sharing atlas state does not share profile-local inspection authority.

Phase 2 collection is explicit and uses only named configured networks/modes.
Fixed passive ip JSON commands or legacy code-derived bounded Nmap -sn/-n/-PS80,443
host-discovery commands run outside DB write locks. Passive neighbors never
establish reachability or absence; only successful complete exact ping coverage
can report not observed in that run. No response deletes a device or un-retires it.
Owned POSIX process groups have output/deadline cleanup and direct-child reaping;
trusted executables are not an OS sandbox. See docs/local-discovery.md for the
exact argv, ARP/TCP behavior, identity limits and offline fixture evidence.

Issue #6 validates opt-in ICMP echo and at most four network-local TCP
ports; 4403 is excluded with no override. Opt-in sockets use numeric authorized
destinations, no TCP writes/reads and only an eight-byte ICMP header. Only Linux
echo datagrams under existing permission are selected for ICMP transport:
no raw sockets, privileged helper fallback, sudo or
grants. Packet-free open/close diagnostics do not prove transport/reachability.
Existing policy/ceilings and TCP 80/443 behavior remain unchanged. See
docs/host-discovery-policy.md for shared budgets, socket cancellation and
method/identity boundaries. Failed/partial method coverage never asserts absence.
No preinstalled ping executable or its capabilities are relied on; denied echo
datagrams never trigger a privileged/raw helper. Extra TCP 2222/optional 22000
are explicit operator choices, not service guesses. A TCP connect can consume an
endpoint connection slot or generate logs/kernel retransmissions even without
application traffic. 4403 is refused because connection contention can affect
radio clients; other connection-sensitive endpoints remain an operator risk.
Method names/flags are not proof of transmission. Capability open/close proves
neither send permission nor replies; unavailable and timeout evidence cannot
diagnose a firewall, prove offline state, or transfer foreign profile authority.
Any future live validation needs a separately approved exact scope and read-only
recipe; it is never a CI test or a reason to weaken firewall/kernel settings.

Phase 3 resolves only a current profile-authorized alias or uniquely mapped
device ID. All seven remote commands are code-owned read-only Linux probes.
BatchMode/strict host keys, no PTY/forwarding/LocalCommand/multiplex reuse/key
updates/backgrounding are explicit. Shared/cached knowledge and past success
cannot grant access. Remote neighbor records are not imported as interfaces of
the inspected host. Failure evidence is bounded and canonical facts survive.
See docs/authorized-ssh-inspection.md for exact argv, host/operation budgets,
parser/identity controls and synthetic-only native restart verification.
ProxyJump/ProxyCommand and Match exec remain operator-trusted config, not a
sandboxed jump path; killing local SSH cannot guarantee remote descendant
cancellation. No runtime tool can supply or modify a command or SSH option.

Configuration examples and fixtures are synthetic, never live authorization.
Supported isolated native install/enable may acquire dependencies during explicit
scratch-only setup. Canonical Atlas acceptance is a separate socket-denied process
with non-forwarding synthetic transports. Admission evidence is candidate-bound;
security scan/refusal/consent controls are not mocked or disabled. This test guard
is not a production sandbox. See docs/operator-guide.md for the exact boundary.
The prospective externally signed CAUTION route is inactive by default and binds
complete commit/tree, pinned core/scanner bytes, full findings and an external
effect scope. DANGEROUS always refuses. No signer/anchor/approval is shipped.
Candidate-authored workflows and writable outside paths are not human authority:
activation requires an independently pinned operator-owned controller and protected
external trust anchor, separately authorized/provisioned. A PTY carries the ordinary
prompt only; it is never consent. See docs/native-caution-confirmation.md for tests,
same-UID limitations and outstanding real local/CI admission gates.
No live scan, SSH inspection, private device seeding, or plugin deployment is
part of repository bootstrap or default CI. Never attach a real atlas database,
private exports, SSH keys, passwords, tokens, or live config to a public issue.

For suspected security defects, do not publish exploit details or private
network data in an issue. Use GitHub private vulnerability reporting when the
repository offers it; otherwise contact a maintainer privately to arrange a
safe report. See docs/implementation-addendum.md for required negative tests
and the explicit SSH-config/local-user trust limitations.
