# Implementation addendum

Accepted bootstrap direction: 2026-09-30. This addendum resolves ambiguities in
project-specification.md without expanding V1. The original remains verbatim.
A builder may propose a simpler implementation, but changing an invariant or
external-effect boundary requires steward/operator approval before execution.

## 1. Scope and source of authority

V1 includes phases 1, 2, and 3 of the delivery plan. Proxmox API discovery is
Phase 4 (the original section 10's "Phase 2" refers to future integration, not
the V1 local-discovery milestone). Rich LLDP/router collectors, service
inventory/enumeration, and automatic context injection are deferred.

Public source contains synthetic data only. Original example networks/devices
are illustrative, not authorization to scan or inspect actual hosts.

## 2. Collection and reconciliation lifecycle

Collectors append bounded observation batches; they do not silently rewrite
canonical device identity. A batch has an immutable ID, collector/source,
configured scope, UTC start/end times, per-probe outcomes, and completion state:
complete, partial, or failed. Persist observations and batch metadata atomically.
Do not persist secrets or unbounded raw output.

network_reconcile takes a stored batch ID (or latest eligible unapplied batch),
selects canonical facts deterministically, and writes state plus audit events
in one transaction. Persist its result so retries return the same result without
duplicate events. Applied batches remain history. Failed/partial results may
contribute valid positive observations, but never assert absence for an
unexamined scope or unsuccessful probe. Interrupted collection cannot partially
mutate canonical state. No external subprocess runs while holding a write lock.

Every mutation, including batch insertion, user updates, and reconciliation,
has a local audit event tied to actor/source, timestamp, and operation/batch ID.
Use schema versioning, foreign keys, bounded busy waits, explicit transactions,
and failure rollback. No general event-sourcing framework is needed.

## 3. Freshness and absence

A passive neighbor table is partial and includes cached entries. It never proves
a complete inventory, current reachability, or disappearance. Preserve neighbor
state/source; failed or incomplete neighbor entries cannot refresh positive
reachability. Distinguish "known address", "observed in this run", and "reachable
by this probe" in storage and output.

A completed ping batch can report "not observed in this run" within its exact
scope, not "offline" or "deleted". Collector failure is not disappearance.
last_checked advances only for a relevant successful check. last_seen advances
only on qualifying positive evidence, never on a failed check or inferred/user
fact. Never-seen user records remain known/unknown, not artificially observed.

Use the configured stale threshold (default 14 days), not immediate failure,
to classify previously observed devices as stale. Queries/rendering may compute
age-based freshness read-only; explicit reconciliation persists transitions and
events. Use injectable clocks in tests. Retirement is operator-owned and is not
automatically reversed by rediscovery. Preserve first_seen, last_seen,
last_checked, retirement, and history across restarts.

## 4. Identity and canonical fact selection

Stable atlas device IDs are independent of address/name. Configured SSH aliases
are strong identity anchors within a policy context. A stable MAC anchors an
interface first; one device can have several MACs, and collisions/randomized MACs
must remain explicit uncertainty. Hostname or IP alone never automatically
merges unrelated records. Reports must expose ambiguous matches and address
ownership conflicts rather than quietly choosing one. Do not attach all remote
neighbor-table entries to the inspected host.

Define and test a small, documented per-field selection table before coding:
- Operator-friendly names, descriptions, type overrides, and retirement remain
  operator-owned; conflicting observations are preserved, not silently applied.
- Current network/OS/hostname facts prefer qualified fresh direct observations;
  user assertions remain separately visible. Stale observations do not become
  fresh merely because they outrank inference.
- Inference never outranks an operator fact or qualifying direct observation.
- Equal-rank disagreement is retained as a conflict; stable ordering is for
  deterministic presentation, not a way to manufacture certainty.

Record value, source, confidence category, observation/effective time, and any
inference explanation. Track current versus historical address assignments;
new MAC at an old address must not steal the previous device identity. A
possible address change should not collapse valid multi-address interfaces.
Relations likewise retain provenance and can reference validated interfaces.

## 5. Authorization and operator provenance

Policy lives in validated operator-controlled configuration, not in canonical
facts and not in tool arguments. Tools cannot edit network allowlists, SSH host
permissions, probe definitions, bounds, or shared-store authorization.
network_update may associate an existing authorized alias with a device; this
association cannot grant permissions. Revalidate current local policy for every
inspection, including when reading a shared atlas created by another profile.
Unknown config keys and unknown tool arguments fail closed where they could
hide authority-bearing input. Parameterized SQL only; free text is a bounded
search string, never SQL, shell text, or an embedded LLM query program.

Do not trust a caller-provided source='user' as operator attestation. V1's safe
default is: LLM tool proposals are inference with an explanation; direct
operator updates enter via a native operator command or local CLI using a
runtime-verified operator path. Implement /network update (or an equivalent
CLI) for that purpose. Operator retirement/reactivation uses that path. If the
installed runtime cannot reliably distinguish direct operator origin, fail
closed on user_supplied writes and document the operator-only local route.
Neither credentials nor attestation tokens are passed through LLM arguments.

Inspection capability is scoped to Network Atlas, not a promise that other
Hermes tools cannot execute commands. Native plugin code and the local operator
are trusted; this plugin is not an OS sandbox for arbitrary Hermes processes.

## 6. Bounded subprocess and discovery policy

Discovery inputs reference configured network names only, never raw targets,
routes-derived ranges, files of targets, URLs, flags, or commands. Default empty
allowlists; ping/SSH are opt-in. Validate canonical CIDRs and numeric bounds at
startup and at invocation. V1 active discovery is IPv4 only with at most 256
addresses per configured range; IPv6 can be stored/passively observed but has
no implicit exhaustive scan. Reject broader ranges instead of silently slicing
or expanding them. Passive local metadata outside the selected scope may inform
the local host only, not authorize network-wide probing.

Default ceilings: 15 seconds per command, 10 seconds host timeout, 120 seconds
whole operation, 4 concurrent probes, and 1 MiB combined stdout/stderr per
command. Operator config may lower these; increasing V1 ceilings requires a
reviewed policy change, not a tool override. Also bound observations, input
strings, result counts, and query pagination. Validate limits as positive
numbers; enforce a whole-operation deadline as well as individual timeouts.

Use fixed argv and shell=False for local process execution. Stream bounded
output and terminate/reap owned process groups on deadline/output limit so an
unbounded child cannot allocate arbitrary memory or survive failure. Do not
kill unrelated processes. No elevation, no scan scripts, no service/OS detection,
no arbitrary port ranges, no UDP scanning/probes, no target files. The reviewed
Nmap host-discovery argv must select explicit non-UDP probes, numeric output,
and machine-readable results, rather than assuming -sn means ICMP-only. Document
ARP behavior on directly attached LANs. No Nmap installation is automatic.

Remote output, hostnames, labels, os-release text, and neighbor data are untrusted
data. Parse bounded documented formats; never eval, execute, or obey their text.
Missing optional executables produce explicit capability/failure evidence.

## 7. SSH transport safety

Resolve targets only from the current profile's configured allowlist; a known
atlas device is not automatically authorized. Validate alias syntax to exclude
option-like destinations, whitespace/control characters, and shell syntax.
Select only fixed code-owned Linux probes, independent of host/alias values.
No arbitrary command, probe text, ssh options, username, hostname, or port from
tool arguments. No sudo, interactive shell, PTY, credentials in atlas, or
known_hosts auto-acceptance. Require BatchMode and StrictHostKeyChecking=yes.
Disable local command execution, session multiplex reuse, agent/X11 forwarding,
and port forwarding for inspections. Existing host keys and credentials remain
managed by OpenSSH; unknown or changed keys fail closed.

The operator's SSH config is a trusted input and may deliberately use ProxyJump
or ProxyCommand. Do not pretend arbitrary SSH config is sandboxed: document that
trust boundary and any permitted jump path; plugin input cannot create or alter
one. Keep probe success/failure distinct, and do not corrupt existing canonical
state when a host, command, parser, or optional executable fails. Timeouts and
output limits apply locally to SSH. They cannot guarantee cancellation of every
remote descendant after disconnect; use short non-daemon read-only commands and
document that transport limitation.

## 8. Profiles and sharing

Resolve default paths through Hermes's profile-aware home helper, not a hardcoded
~/.hermes. Default atlas/config/export paths are under that profile's network-atlas
directory. Support an explicitly operator-configured shared SQLite path so the
primary agent and delegated workers can read the same atlas without copying it.
Configuration/inspection authority stays profile-local even with shared data.
Document local-user/file-permission trust; same-UID processes are not isolated
by SQLite. Test two isolated profiles sharing knowledge without sharing inspect
permission. No modifications to other profiles as a side effect of installation.

Access answers say "authorized for Network Atlas SSH inspection" and, separately,
"last inspection succeeded/failed at ...". Configuration alone is not proof of
current reachability. Do not advertise development/admin authority as an Atlas
capability. Default file permissions should restrict database, config, WAL,
audit, and exports; public Git exclusions are a second line, not access control.

## 9. Rendering, documentation, and testing

Use exports/network_map.md and exports/network_map.mmd consistently. Render
only stored supported relations; display confidence, stale status, and isolated
nodes without invented links. Stable IDs/order and escaped Markdown/Mermaid
labels prevent churn and diagram injection. Avoid regeneration timestamps when
state is unchanged. Exports are generated, never authoritative. Explicit exports
write only to configured local paths, not arbitrary caller-chosen destinations.

The canonical verifier must run the implemented module tests and integration
smoke checks, not just bootstrap documentation checks. Required evidence:
- Real native plugin discovery, tool schemas/handlers, command registration, and
  supported install/enable flow in an isolated Hermes home; no live activation.
- Persistent query/map after reopening the database in a fresh process.
- Fixture-based clean-install acceptance with three synthetic SSH aliases;
  bounded discovery, inspection, reconciliation, conflicts/absence, and restart.
- Negative arbitrary-command/option/range/policy/provenance tests, malicious
  output/label tests, output/deadline caps, failed/partial collection, repeated
  reconciliation, concurrent/failed transactions, and shared-profile isolation.
- Operator docs explaining installation, security/trust boundaries, missing
  dependencies, user attestation, querying, exports, and explicit live validation.

A fixture acceptance test is not a claim that a real home network was validated.
Live installation, private seeding, scanning, inspection, and gateway restarts
require later explicit operator scope. Plugin Doctor complements tests; it is
not a security sandbox or full runtime acceptance proof.

## 10. Delivery boundaries

Bootstrap publication is authorized by the operator's project-creation request.
Implementation cards authorize local code/tests/commits, independent exact-SHA
review, guarded target advancement, and safe non-force merged-worktree cleanup.
They do not authorize later pushes, releases, deployments, profile changes,
plugin installs into live homes, discovery of actual networks, SSH to actual
hosts, gateway restarts, or branch deletion. Preserve an enforceable human
approval dependency for later external publication/live effects.

Maintain one reusable serial feature lane. Each successor starts only after its
parent's exact-SHA review and after verifying no active writer and a clean tree.
Final delivery separately proves combined tests, target ancestry, and cleanup.
Do not confuse reviewed component cards with repository delivery or V1 runtime
activation. Builder/reviewer remediation stays on the same native card.

## References for implementation reconnaissance

- https://hermes-agent.nousresearch.com/docs/user-guide/features/plugins
- https://hermes-agent.nousresearch.com/docs/developer-guide/plugins
- https://hermes-agent.nousresearch.com/docs/user-guide/features/kanban
- https://man.openbsd.org/ssh_config
- https://nmap.org/book/host-discovery-controls.html

Re-read current docs and installed CLI/runtime contracts at implementation time.
