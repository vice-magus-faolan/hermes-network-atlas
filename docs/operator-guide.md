# Operator guide and cumulative V1 verification

V1 phases 1–3 are implemented. Stock native directory-plugin registration,
synthetic collection and fresh-process persistence are tested. This does NOT
validate a real network, host key, deployment, gateway restart or provider chat.
Final independent approval, local target integration and publication have their
own gates. Do not infer permission from these examples.

## Supported installation (only after separate operator authorization)

Compatibility is Python >=3.11,<3.15 and Hermes >=0.21.4,<0.22. Use stock
NousResearch/hermes-agent; no fork, core patch or runtime monkeypatch is needed.
Docker and CI select its verified official release v0.21.6. Other releases and
platforms are not proven by that selection alone. The Linux arm64 CI job must
actually pass before it establishes portability. No live core update is implied.
Atlas itself needs only ruamel.yaml>=0.18.16,<0.19 beyond the standard library,
declared with the supported native plugin.yaml python_dependencies field.

The repository root is a native directory plugin. Choose a reviewed immutable
40-character commit and the intended profile explicitly. Do not run these on a
live profile merely to verify this repository:

    hermes plugins install https://github.com/vice-magus-faolan/hermes-network-atlas.git --ref <reviewed-40-character-SHA> --no-enable
    hermes plugins enable network-atlas
    hermes plugins show network-atlas

Install clones/scans the exact artifact; enable uses native PM member-union
resolution/publication, not a hand-edited enabled list. Retain security checks
and ordinary dependency/capability consent. Do not use force or disable scanning
for installation or CI. No runtime activation/restart of a
live gateway is authorized by these instructions. Native enable's restart hint
is advice for a separately authorized deployment, not an action this test runs.

Missing Python dependencies/PM toolchain or a resolver conflict is an installation
failure, not evidence that Atlas works. Prepare an isolated test environment or
follow Hermes's supported PM diagnosis/recovery; do not pip into production,
remove dependency declarations, substitute versions, fabricate lock/facts, or
relax security settings. Native enable can resolve upstream optional requirements
and revalidate URL dependencies even when a frozen core build is cached. Therefore
setup may need the network; the Atlas test process must not have it. An incomplete
package-intelligence warning is not a clean vulnerability verdict.

Active CI installs stock Hermes and its declared dependencies ONLINE while building
the image. Product execution is separate: normal validate, doctor and pytest run
with Docker's network disabled. No install/enable admission helper, force mode,
retained receipt or offline-enable core extension is used. The suite exercises real
directory-plugin registration and restart, not the PM install/enable lifecycle.
Source approval/local tests do not prove hosted acceptance or permit activation.

## Profile-local policy

See [endpoint checks](endpoint-checks.md) for opt-in TCP checks, durable recovery and shared queries.

Atlas reads `<get_hermes_home()>/network-atlas/config.yaml`, separate from Hermes's
plugin selector. No policy means empty allowlists. An existing empty/malformed file,
unknown keys, invalid numbers, noncanonical or overbroad scopes fail closed at
registration and every invocation. Invalid-policy CLI refusal returns exit 2 and
explicit applied=false/persisted=false before command dispatch or store changes.
Maintain this file as an operator in a 0700
directory with mode 0600; never let model tools edit it. A synthetic example:

```yaml
version: 1
networks:
  lab:
    cidr: 192.0.2.0/29
    discovery:
      passive: true
      ping: false
      icmp_echo: false
      tcp_ports: [80, 443]
ssh:
  enabled: false
  hosts:
    lab-a: {alias: lab-a, inspect: false}
    lab-b: {alias: lab-b, inspect: false}
    lab-c: {alias: lab-c, inspect: false}
retention:
  stale_after_days: 14
render:
  include_addresses: true
  include_interfaces: false
```

The reserved documentation range and disabled SSH/ping are intentional. This is
not an operational network authorization. Explicitly enable only real operator-
chosen modes and existing reviewed OpenSSH aliases during a later authorized
activation. IPv4 ping ranges have at most 256 addresses. Stored/passive IPv6 is
not permission for active IPv6 scanning. Numeric ceilings and selection precedence
are detailed in [contract-decisions.md](contract-decisions.md).

Issue #6 accepts network-local discovery.icmp_echo (default false) and
discovery.tcp_ports (default [80,443], at most four distinct integer ports;
4403 is forbidden). Nonlegacy ping uses bounded numeric-only echo datagrams and
TCP connects with no application traffic. Passive and legacy traffic are unchanged.
ICMP-only policy uses tcp_ports: []; ICMP requires ping: true. Socket permission
is diagnosed honestly: unavailable ICMP does not suppress a TCP positive (or vice
versa). A TCP refusal is positive host-response evidence, not a listening service.
The synthetic example [80,443,2222,22000] is not a default or service claim.
No helper, grants or fallback are enabled. Read
[host-discovery-policy.md](host-discovery-policy.md) before selecting methods;
old binaries reject the new keys. Query/status never opens a capability socket.
Method outcomes retain port, UTC times and contributing positives without a schema
migration. Status address_count/responding_address_count deduplicate hosts; total
probe/observation counts include method evidence, not extra devices. An excluded,
timed-out, unavailable or not-started method makes coverage absence-ineligible.
Network/broadcast addresses (except /31 and /32 host semantics), multicast,
loopback, unspecified and reserved destinations are excluded before transport.

Policy stays local even with an explicitly configured absolute
`store.shared_sqlite_path`. Another profile can read knowledge but cannot inherit
inspection authority, apply foreign batches, or reuse foreign alias anchors.
Exports stay profile-local. Same-UID processes, operator SSH config, executables,
ProxyJump/ProxyCommand/Match exec and local native plugins are trusted, not OS-
sandboxed. Keep DB/WAL/config/audit/exports private. See [SECURITY.md](../SECURITY.md),
[Atlas Core](atlas-core.md) and [SSH trust boundaries](authorized-ssh-inspection.md).

## Explicit commands and provenance

    /network help
    /network status
    /network discover lab passive
    /network inspect lab-a
    /network reconcile <returned-batch-id>
    /network show <stable-device-id>
    /network map markdown

Discover requires a configured name and mode; inspect requires an authorized alias
or uniquely mapped stable ID. Collection stores immutable batches only; reconcile
applies one eligible batch atomically and exact-ID retry returns the saved result.
Missing means not observed in that complete exact run, never deleted or offline.
Passive neighbors and failed/partial scans cannot prove absence. Age-based stale
status is distinct from latest scan absence. User retirement is sticky.

Status reports total known inventory, observed/stale subsets, configured scopes,
authorized aliases/device count, last discovery scope/completion/whole-batch evidence,
and separate last inspection success/failure. Neither configuration nor an old
successful attempt proves present reachability. SSH inventory does not prove every
stored IP is reachable. Only qualified exact-address ping evidence can say that.

Last discovery/collection `probe_summary` always counts the entire batch, including
the scope-coverage probe: total_count, outcome_counts, coverage_counts,
failure_count and absence_eligible_count. Inventory pagination cannot suppress
these aggregates, including after /24 or /25 discovery. `probes` is explicitly a
bounded sample (`detail_limit=limits.result_count`), with failures first and stable
ordering. Check returned_count, omitted_count and omitted_failure_count before
treating it as complete detail. Omitted failures remain in whole-batch outcome/
coverage totals. Status does not offer probe pagination, and device history is not
batch probe detail; collection returns the full bounded outcome/diagnostic receipt.
See [Atlas Core](atlas-core.md) for exact field semantics. Public status still obeys
the serialized output_bytes ceiling; a too-small ceiling refuses read-only.

Legacy ping discovery uses serial fixed 16-address chunks, preserving earlier completed
evidence when a later chunk fails. New address_count/address_outcome_counts exclude
the synthetic scope-coverage probe. not_started means the work had no child because
its budget expired; timeout means started transport exceeded its deadline; neither
means offline. success/completed_at_boundary retains valid finished work despite
postprocessing crossing the transport boundary. Chunk failures leave all their
addresses unknown, never absent. Legacy /24 and /25 records remain readable, but
old timeout diagnostics remain ambiguous; upgrade shared-store readers for the
additive outcome enum. See local-discovery.md for fixed argv, total concurrency/
average-rate bounds and limitations. Opt-in ICMP/nondefault-port policy instead
uses one shared socket scheduler; not_started then means no send/connect began,
not a missing child. A method name identifies requested policy, not proof of a
transmitted packet. Check its outcome and diagnostic; unavailable can occur before
or during transport. A timeout is an initiated attempt with no qualifying reply
before its bound, not proof of a filtered or offline host. No real-world completion
guarantee is made. See host-discovery-policy.md for response/check counts, helper
permissions, residual firewall blindness and the separately authorized live recipe.

The slash runtime cannot attest human origin, so `/network update` refuses.
Use the trusted local operator CLI for user-supplied knowledge:

    hermes network-atlas create --name "Synthetic workstation"
    hermes network-atlas update --device-id <returned-id> --field description --value-json '"Operator assertion"'
    hermes network-atlas update --device-id <returned-id> --field ssh_alias --value-json '"lab-a"'
    hermes network-atlas update --device-id <returned-id> --field retired --value-json true
    hermes network-atlas query --query-json '{"access_method":"ssh","limit":10}'
    hermes network-atlas query --query-json '{"view":"history","device_id":"<returned-id>","limit":10}'
    hermes network-atlas map --format mermaid --export

Alias association requires preexisting current permission; it never grants it.
Retired=false reactivates through the same operator path. The local CLI is a trust
convention, not cryptographic human attestation. Model `network_update` proposals
always retain inference/explanation; caller `source=user` and runtime origin flags
cannot promote them. Applying receipts say persisted=true; the compatibility
validate-update command still says applied=false/persisted=false.

Queries/maps read existing SQLite, never collect or schedule. Follow has_more
with bounded offset/limit; oversized entity evidence fails explicitly, with
history pagination available. Maps render stored supported relations only,
escape labels, and retain isolated/stale/uncertain nodes. Exports are fixed
profile-local exports/network_map.md and network_map.mmd, not authoritative.
An interruption between file replacements can leave mismatched exports; regenerate
both from SQLite. No service enumeration, full-atlas prompt hook or scheduler ships.

### When discovery found responses but inventory has zero devices

MAC-less ping response evidence correctly remains unidentified. It is not a
reason to fabricate canonical devices or assign an IP's previous owner. Read it
through `network_query` with `view=unresolved`, or the native query CLI:

    hermes network-atlas query --query-json '{"view":"unresolved","address":"192.0.2.10","limit":10}'
    hermes network-atlas query --query-json '{"view":"unresolved","batch_id":"<returned-batch-id>","limit":10,"offset":0}'

The response's evidence array is distinct from devices. Check identity_state,
historical_responder_evidence, freshness, origin/policy_context and batch/probe
coverage. Never-reconciled, reconciled-unresolved/conflicting and later-resolved
originals are explicitly distinguished; resolved historical originals remain
listed, not mislabeled. Fresh evidence still does not prove reachability now,
identity, ownership or inspection access. Foreign shared evidence remains visible
knowledge, not permission to apply it. See [the strict bounded evidence contract](unresolved-evidence.md)
for pagination, all output fields, lineage limits and partial/legacy batch handling.

Passive collection needs installed iproute2; legacy ping needs optional installed Nmap;
opt-in socket collection needs no Nmap or ping helper. ICMP requires already-
permitted Linux echo datagrams; a preinstalled privileged helper does not grant
Atlas permission and is not executed. No automated privilege changes are allowed.
SSH needs a supported OpenSSH client and existing operator-managed config/keys/
known_hosts plus remote Linux utilities. Missing executables/remote commands
produce bounded per-probe failures, never automatic installation or weaker SSH.
Older clients rejecting a safety option fail closed. Fixed argv, ARP/TCP behavior,
output/time limits and remote cancellation caveats are documented in the collector
guides. Inspect/query failures are not an excuse to discard the atlas.

## Reproduce the isolated acceptance

Tests require a stock supported Hermes runtime with its declared dependencies
and requirements-test.txt. In an owned development environment, install those
dependencies online. If Hermes is already importable, no source-root setting is
needed; otherwise set NETWORK_ATLAS_HERMES_ROOT to its stock checkout. Pytest
creates scratch homes automatically. No manual TMPDIR, receipts, Git metadata,
GitHub/ref, UID, container or architecture predicates are prerequisites. No live
config, atlas, credentials, homes or profile selections are copied.

    python3 -m pip install -r requirements-test.txt
    hermes plugins validate .
    hermes plugins doctor . --ci
    python3 -m pytest -q

For reproducible Docker setup and network-denied product execution:

    docker build -f docker/validation.Dockerfile -t hermes-network-atlas-tests:local .
    docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges hermes-network-atlas-tests:local

Build is online; the image contains unmodified official Hermes v0.21.6 and public
Atlas source only. Run is non-root and network-none, with no host mounts, Docker
socket, credentials or live state. The image command propagates validate, doctor
and pytest failures. `.github/workflows/ci.yml` runs this same path on x86_64 and
arm64 Linux runners. Configuring a job is not executed portability evidence;
publication owner must read back actual exact-head results after review.

The portable Python audit tripwire refuses connect/bind/DNS before plugin imports.
It is not inherited by arbitrary executable children; Docker supplies OS-level
network isolation. Native child tests install their own Python tripwire. Synthetic
transport executables never forward to real ip/Nmap/SSH. Tests do not mock Hermes
registry, schemas, dispatch or provenance. Package-manager install/enable, resolver
publication and provider chat remain distinct unperformed checks, not pytest setup.

`tests/test_acceptance.py::CumulativeAcceptanceTests` configures three synthetic
SSH aliases in a pytest-owned directory-plugin home, performs bounded
passive/ping discovery and all three fixed inspections, operator alias association,
new/changed/missing/conflict/unresolved reconciliation, operator/inference/direct
source separation, synthetic host-key refusal, query/status and escaped maps/exports.
A second fresh native process uses the same stock test interpreter and
re-queries/replays with transport binaries removed. It compares complete devices,
history, access evidence, status, maps/exports and SQLite row counts, without
rediscovery or audit growth. No LLM/provider response is fabricated or claimed.
Both processes also verify invalid ICMP/port/option policy refusal through native
tool/slash/CLI with explicit no-effects receipts and unchanged files/store counts.
The collection process exercises ICMP responses with filtered web ports, true
ICMP-only policy, 2222-only, 22000-only, mixed ICMP/four-port positives, denied
permission/unsupported ICMP with TCP positives and all-filtered outcomes through
non-forwarding sockets on all three routes; restart reads the same method evidence
without transport. The original fixture policy is restored.
Each test starts a new synthetic atlas in ordinary pytest scratch, never in a live
profile. No retained fixture receipt is required. Rebuild the image after source
changes so validation scans and tests cover the actual candidate bytes.

`docs/acceptance-matrix.md` indexes A01–A14 to exact tests and documentation;
A15 remains the delivery owner. No self approval, main advancement, push, release,
live activation, actual scan/SSH or gateway restart is proven by green tests.
