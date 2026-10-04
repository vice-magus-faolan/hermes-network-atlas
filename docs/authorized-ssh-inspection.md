# Authorized SSH Inspection (Phase 3)

Phase 3 implements an explicitly invoked, fixed read-only Linux collector and
SSH batch reconciliation. Cumulative synthetic V1 acceptance and supported
PM-managed install/enable are documented in operator-guide.md. Independent final
review, target integration and publication retain separate gates.
No actual SSH host, LAN, live profile or private atlas was used for this work.

## Input and authority

`network_inspect` accepts exactly `{"target":"lab-router"}`. Target is either a
currently configured authorized SSH alias or an exact stable atlas device ID
with one unambiguous locally authorized alias association. Names are 1–64 ASCII
alphanumeric/underscore/hyphen characters and cannot start with a hyphen.
The handler enforces the schema independently of Hermes registry validation.
There are no hostname, username, port, command, flag, option, probe, credential,
source, permission, output path or limit arguments. Raw IPs/hostnames are not
looked up as destinations. Operator policy can deliberately name an SSH alias;
only that configured name is used, not a host value supplied by the model.

Each public tool/slash/CLI invocation reloads the registration profile's
operator-owned network-atlas/config.yaml. Policy is an immutable invocation
snapshot. `ssh.enabled` and `ssh.hosts.<name>.inspect` must both be true; host
`alias` must validate. No default grants. Model proposals, shared device facts,
foreign profile alias associations and previous successful access do not grant
inspection. Inference associations cannot anchor a device. A device with several
eligible aliases requires the caller to select the configured alias explicitly.
An ambiguous alias association is refused before transport. Mapping is checked
again under the batch insertion lock; a concurrently invalidated device mapping
cannot silently reroute the attempt or partially insert it. Policy edits affect
the next invocation; V1 does not watch config mid-command or cancel an in-flight
inspection merely because the file changes.

Synthetic policy example (illustrative, not authorization to inspect a host):

    version: 1
    ssh:
      enabled: true
      hosts:
        fixture:
          alias: lab-router
          inspect: true

Existing SSH configuration, credentials and known_hosts remain operator-managed.
No private key, password, raw stderr or credential is stored in the atlas.
Existing local operator CLI association does not enlarge this permission:

    hermes network-atlas update --device-id <id> --field ssh_alias --value-json '"lab-router"'

Inspection and reconciliation are separate calls:

    hermes network-atlas inspect --target lab-router
    hermes network-atlas reconcile --batch-id <returned-batch-id>
    /network inspect lab-router
    /network inspect <device-id>
    /network reconcile <returned-batch-id>

Slash origin remains unattested on the inspected Hermes version; `/network update`
therefore still refuses operator writes. Neither query, map, registration nor
reconciliation performs inspection automatically. No scheduler/context injection.

## Code-owned probes and OpenSSH options

`inspection.PROBES` contains exactly seven sequential read-only commands:

    hostname
    hostnamectl --static
    cat /etc/os-release
    ip -j address
    ip -j link
    ip -j route
    ip -j neigh

There is no sudo, service enumeration, mutation, arbitrary shell wrapper,
Proxmox API, LLDP, privileged bridge command, or active neighbor expansion.
Missing commands produce per-probe failures rather than an installation attempt.
The local subprocess uses shell=False; the remote command is a single fixed
code-owned string. OpenSSH necessarily invokes the remote account's command
execution mechanism (normally its login shell); this is not a guarantee that
SSH uses a direct remote execve. No caller value is interpolated into that text.

`ssh_argv` refuses unknown code-owned commands even to native callers. Its argv
starts with `ssh -T -n -a -x`. Each option below is supplied explicitly with -o
before the validated alias; existing config cannot replace these first values:

    BatchMode=yes                 StrictHostKeyChecking=yes
    UpdateHostKeys=no              VerifyHostKeyDNS=no
    NoHostAuthenticationForLocalhost=no
    KnownHostsCommand=none
    RequestTTY=no                 StdinNull=yes
    PermitLocalCommand=no         LocalCommand=none
    ClearAllForwardings=yes       ForwardAgent=no
    ForwardX11=no                 ForwardX11Trusted=no
    Tunnel=no                     ControlMaster=no
    ControlPath=none              ControlPersist=no
    RemoteCommand=none            SessionType=default
    ForkAfterAuthentication=no     AddKeysToAgent=no
    ConnectionAttempts=1          LogLevel=ERROR
    ConnectTimeout=<configured host_timeout_seconds>

Unknown or changed host keys must fail; no accept-new, host-key prompt,
known_hosts auto-acceptance, key update, interactive credential prompt, PTY,
LocalCommand, port/agent/X11 forwarding or session multiplex reuse is allowed.
The localhost host-authentication exemption and dynamic KnownHostsCommand are
disabled, so neither can silently replace existing host-key trust.
Key/authentication errors are bounded `command_failed/nonzero_exit` evidence,
not fabricated precise diagnoses extracted from sensitive arbitrary stderr.
Existing agent credentials may still authenticate; they are not forwarded.
Older OpenSSH clients that reject these options fail usefully, not with a weaker
fallback. Reference: https://man.openbsd.org/ssh_config.

This is not an SSH-config sandbox. The operator's configuration, HostName/User/
Port, known_hosts files, executable resolution, remote account/executables,
ProxyJump/ProxyCommand and Match exec are trusted inputs. A deliberate jump path
can execute local commands or reach other machines. Network Atlas cannot claim
that PermitLocalCommand=no disables ProxyCommand or Match exec. The plugin
neither creates nor changes those paths; the operator must review them and may
use a restricted read-only remote account. Other same-UID Hermes tools/native
plugins are outside the Atlas model-tool boundary.

## Bounds, untrusted output and persistence

One monotonic operation deadline starts before target lookup; every read/lock,
probe, parser and final write shares it. A separate host-wide deadline bounds
ALL seven SSH commands together (default/hard ceiling 10 seconds), not seven
fresh host budgets. Each command also has its own timeout (ceiling 15 seconds),
clipped to the host/operation deadline. Sequential execution uses one child at
most, within the configured concurrency ceiling. A small bounded slice of the
operation budget is reserved for finalization. Limits may be lowered only via
operator config; a probe-count limit below seven refuses before any transport.

The existing POSIX owned-group runner streams combined stdout/stderr with the
configured cap (ceiling 1 MiB/command), null stdin, closed descriptors, and group
cleanup/direct-child reap on success, failure, output cap, timeout or interruption.
No subprocess executes while holding a DB write transaction. Cleanup is allowed
after expiry. This is a cooperative bound, not a hard real-time guarantee against
OS descheduling or blocked filesystem calls. Disconnect/group cleanup cannot
guarantee cancellation of all remote descendants; short non-daemon read-only
probes mitigate that limitation, they do not remove it.

Parsers enforce byte/record/observation/string bounds. Hostname is one UTF-8
scalar; os-release is decoded as bounded quoted/plain assignments, never sourced,
evaluated or expanded. Duplicate assignments/JSON keys, malformed JSON,
invalid addresses/prefixes/MACs and excessive records fail that probe. Quoted
shell-looking labels remain data. Each success receives a code-owned,
context-qualified alias marker, including an empty valid ip JSON result.
Aggregate overflow removes that probe's positives and records parse_failed.
Other valid probes can still contribute positives in a partial batch.

`store_batch` atomically saves immutable metadata, per-probe outcomes and parsed
observations plus batch_stored audit. Receipt includes persisted=true,
applied=false and every probe's outcome/diagnostic/count. Output receipt overflow,
SQL errors, interruptions or operation expiry roll back insertion. Every batch
uses source=ssh:<alias>, observed confidence and canonical UTC times. Raw command
output is discarded. Per-probe failed/unavailable/timeout/output_limit/parse_failed/not_started
results are retained when finalization fits the operation budget; an operation
that cannot atomically finalize refuses without a persisted batch.

The issue #2 shared-runner accounting fix applies here too without changing SSH
probes/permissions: not_started/operation_deadline_exceeded means no child launched
after budget exhaustion; timeout/deadline_exceeded is started work interrupted at
its effective deadline. Valid completed responses are not overwritten during
postprocessing; success/completed_at_boundary retains their evidence. Remaining
probes still cannot spawn late. The host/operation/atomic-finalization bounds above
remain unchanged; this adds no inspection capability.

The immutable SSH batch itself is attempt evidence. Query status exposes the
last local-context attempt immediately, before reconciliation. This also allows
an unsuccessful unassociated alias attempt to be remembered without fabricating
a device or migrating the schema. Success means at least one fixed probe returned
valid parsed output; completion=complete/partial/failed and all probe outcomes
are shown separately. It is neither proof that every capability works nor proof
of current reachability. Config authorization remains a separate answer.

## Identity, reconciliation and access answers

SSH batches must match current local policy and context even for exact replay.
Latest-unapplied selection includes eligible LAN and SSH batches, skipping revoked
scopes; pass a batch ID when choosing a particular attempt. Alias identity is
qualified by profile home. A successful unassociated alias creates an observed
UUID device only during reconciliation. It does not merge an existing device
merely because hostname/IP/MAC is the same. Operator names, descriptions, type
and retirement remain operator-owned. Failed unassociated attempts create no
canonical device. Failed mapped attempts preserve all existing facts and clocks.

The alias owns the inspected host. New stable remote interfaces may join it;
an existing unique stable MAC can resolve only an interface already owned by
that alias's device. A MAC owned by another host, distinct remote interface
names sharing a MAC, or randomized/zero/multicast/colliding MACs produce explicit
unresolved/conflicting evidence without overwriting ownership. Remote address
sets are additive IPv4/IPv6 assignments, never scan authorization, per-address
reachability, or evidence that other known addresses disappeared. Even an UP
interface or an address matching a hostname does not prove contact with that
address. Query preserves source/confidence/history and observed_in_batch, but
returns reachable_by_this_probe=false for SSH inventory, including DOWN and
IPv6 link-local addresses. Only a qualified exact-address ping_response can
set that flag; SSH success/failure remains alias-scoped access evidence.
Direct owned observations can refresh sighting clocks monotonically; failures
cannot. Retirement stays sticky.

Route and neighbor JSON is validated as capability metadata and discarded, apart
from the probe outcome and successful exact-target alias marker. Remote neighbor
entries are NOT interfaces/addresses owned by the inspected host, new reachable
hosts, routes_via/physical relationships, a complete inventory, or collection
permission. Detailed route/neighbor topology interpretation is deferred; this
V1 collector deliberately favors no topology over fabricated topology.

Reconciliation uses one atomic deadline-bound transaction for canonical copies,
alias mapping, interfaces/addresses, clocks, access_evidence, application result
and events. Ambiguous aliases remain explicit conflicts; failures never assert
absence. Access records are appended only when a device can be resolved. The raw
attempt remains queryable even when no device exists. Exact batch-ID replay adds
no rows/events and returns the original result. Deadline/audit/SQL/receipt failure
leaves the immutable batch retryable. Existing schema version 1 is retained.

Query `access_method=ssh` means authorized for Network Atlas inspection, NOT
administration/development access or currently connected. Device details expose
local association ambiguity, current policy authorization, and last inspection
success/failure/time/completion/probes separately. Foreign associations remain
knowledge without foreign access history being represented as local access.
Maps still use only stored supported relationships; no edges are fabricated.

## Offline verification and remaining gates

Use a compatible verifier and candidate-bound native fixture prepared separately
as documented in operator-guide.md:

    python3 -m unittest discover -s tests -p 'test_inspection*.py' -v
    python3 -m unittest discover -s tests -p test_runtime.py -v
    python3 scripts/verify.py

`tests/test_inspection.py` covers A03/A05/A08/A09/A12 exact schema/handler rejection,
fixed argv/host keys/config channels, alias/device resolution, partial/failure
preservation, malicious scalar/JSON/os-release parsing, provenance and replay.
`tests/test_inspection_extra.py` covers foreign/inferred/multi-alias identity,
MAC collisions/foreign ownership, failed unassociated attempts, concurrent
mapping changes, latest/revoked-policy selection, access-write rollback/retry,
actual scratch-child host deadlines/output cleanup and missing ssh without install.
`tests/test_inspection_remediation.py` covers A02/A05/A09 multi-interface UP/DOWN
and link-local inventory without per-address reachability, preserved alias success
and history, exact-address ping positive control, reopened/fresh-process queries
with network/process execution refused, and deterministic maps/fixed exports.
The canonical verifier discovers these regressions with the other module tests.
Existing Phase 2 tests exercise the shared runner/SQLite whole-operation boundary.

`tests/test_runtime.py` and `scripts/runtime_smoke.py` exercise actual native
Hermes registration/schema/tool/slash/CLI dispatch with six tools. Transport is
ONLY `scripts/offline_ssh.py`, a scratch-marker-guarded synthetic executable which
validates fixed argv and cannot run SSH. It simulates valid output and a client
refusal; a fresh native process replays/queries/maps with that executable removed
and a fixture-only PATH. No live host key or real reachability is claimed tested.

Supported PM-managed install/enable and three-alias cumulative V1 evidence are
indexed in acceptance-matrix.md. GitHub CI execution, other OS/OpenSSH/runtime
versions, integration/publication and live installation,
private seeding, scans/SSH or gateway restarts remain unperformed/downstream.
