# Security boundaries

Network Atlas observes and remembers; it does not administer infrastructure.
It is not a generic shell, vulnerability scanner, or privileged network manager.

## Collection and authorization

Collection is explicit and restricted to named networks, enabled methods, or SSH
aliases in the selected profile's operator-controlled policy. Missing policy
grants no collection; malformed policy fails closed. Policy is validated before
registration and reloaded on invocation. Tool arguments, stored facts, past
successes and shared evidence cannot grant or expand access. Query and map only
read stored knowledge; map export is a separate explicit local write.

Configured IPv4 scopes contain at most 256 addresses; IPv6 is passive/storage-only.
Routes never authorize additional ranges. Passive collection reads local `ip`
JSON. Legacy active discovery uses bounded Nmap host discovery, not service/OS,
script or UDP scanning. Opt-in sockets use numeric authorized destinations,
at most four configured TCP ports, and Linux ICMP echo datagrams under existing
permissions. There is no raw-socket/helper fallback, sudo or privilege grant.
TCP checks send/read no application bytes; ICMP sends only an eight-byte header.
TCP handshakes can still consume connection slots, generate logs and trigger
kernel retransmissions. Port 4403 is refused without override because contention
can affect radio clients; other sensitive endpoints remain an operator risk.
See [LAN collection](docs/local-discovery.md), [host discovery](docs/host-discovery-policy.md)
and the separate opt-in [endpoint policy](docs/endpoint-checks.md).

## Fixed commands, bounded execution and SSH

Local subprocesses use code-owned fixed argv with `shell=False`, null stdin,
closed inherited descriptors and their own process group. Callers cannot supply
commands, SSH options, flags or arbitrary destinations. The POSIX runner streams
combined stdout/stderr under a byte cap, kills only its owned group and reaps its
direct child on success, failure, deadline, output overflow or interruption.
The leader PID is retained until group cleanup to prevent PID-reuse signalling.
Deliberately self-detaching executables are outside this trusted-command boundary.

Code enforces command, host and whole-operation deadlines, shared concurrency,
output, record and query limits. Policy can lower, not raise, their hard ceilings.
Owned sockets close on completion/cancellation. Collection runs outside database
write locks; atomic persistence and rollback protect existing history. Deadlines
are cooperative bounds, not hard real-time guarantees against OS descheduling or
blocked filesystem calls.

SSH resolves only a current authorized alias or a uniquely mapped device ID and
runs seven fixed read-only Linux probes. It requires BatchMode and strict existing
host keys, with no key auto-acceptance/update, PTY, forwarding, LocalCommand,
multiplex reuse or backgrounding. Credentials remain with OpenSSH, not Atlas.
Unknown/changed keys and unsupported options fail rather than weakening transport.
The remote account normally executes the fixed command through its login shell;
no caller text is interpolated. [SSH transport details](docs/authorized-ssh-inspection.md)
list the exact probes and hardened options.

Native plugins, same-UID code, installed executables, remote accounts and local
SSH configuration are trusted. ProxyJump, ProxyCommand and Match exec can execute
local commands or reach other machines; hardened options do not sandbox those
paths. Local SSH group cleanup cannot guarantee termination of remote descendants.
Atlas restricts its own tool surface, not other tools or the account's abilities.

## Evidence, sharing and privacy

Remote output and discovered labels are untrusted data: parsers bound and validate
them, never execute or obey them. Raw probe output is discarded. Operator facts,
qualified observations and explained inference remain distinct. Model updates
cannot attest operator origin; the local operator CLI is a trusted route, not
cryptographic human attestation or isolation from other same-UID processes.
IPs/hostnames alone never merge devices, and unknown topology is not invented.
Passive caches and failed/partial checks cannot prove absence. Even complete ping
coverage means only "not observed in that run", not offline or deleted. Historical
success and packet-free capability diagnostics do not prove reachability now.
Retirement remains operator-owned. See [provenance and identity](docs/atlas-core.md).

Profiles may share a database; each keeps its own collection/SSH policy and local
exports. File permissions and SQLite do not isolate same-UID processes. Keep
configuration, SQLite/WAL, history, exports and backups private; they can reveal
addresses, hostnames, aliases and topology. Use a consistent SQLite backup before
upgrades. Generated exports are not authoritative or cross-file atomic; regenerate
both after interruption. See the [operator runbook](docs/operator-guide.md).

## Testing and reporting

CI acquires stock Hermes/dependencies online and exercises real native enable/status
in fresh synthetic homes. It then runs validate, doctor and application tests
non-root with Docker networking disabled and capabilities dropped. Fixtures use
synthetic, non-forwarding transports and deny Python connect/bind/DNS attempts;
that Python tripwire alone is not an OS sandbox for executable children. These
checks do not validate a real LAN, SSH host key, production install or live gateway.
Examples are synthetic; actual collection requires the operator's selected scope.

Request a private reporting channel through [repository issues](https://github.com/vice-magus-faolan/hermes-network-atlas/issues),
giving only a non-sensitive description of the affected feature. Do not publish
exploit details, real atlas databases, policy, private exports, keys, passwords or
tokens. Share sensitive evidence only after arranging a confidential channel.
