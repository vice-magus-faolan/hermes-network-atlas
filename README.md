# Network Atlas

A small Hermes-native plugin for durable, provenance-aware network knowledge.

**Status: V1 phases 1–3 implemented with cumulative synthetic acceptance;
independent final review, target delivery and release remain separately gated.**
Profile-aware SQLite, immutable provenance/history, interface-first identity,
audited operator/inference updates, bounded read-only query, and deterministic
maps/exports are implemented. Applying receipts report persisted=true; the
compatibility validate-update command still reports applied=false/persisted=false.
Explicit bounded passive/Nmap discovery, immutable evidence batches and
transactional idempotent reconciliation are implemented. Explicit current-policy
SSH inspection uses fixed read-only probes and immutable attempt evidence.
The bounded `network_query` unresolved view exposes original discovery evidence,
qualification/freshness and application/identity lineage separately from devices;
zero canonical devices can coexist with positive historical response evidence.
Collection alone never rewrites canonical inventory.
Legacy ping collection uses serial fixed 16-address chunks with bounded internal
parallelism/rate and distinct not-started/timeout/completed-at-boundary evidence;
hard ceilings are unchanged and real-world /24 completion is not guaranteed.
Issue #6 adds strict network-local ICMP/TCP policy, packet-free capability
diagnostics and bounded opt-in echo-datagram/TCP-connect collection. All methods
share one budget and retain contributing method/port/time evidence; address
counts are deduplicated. Legacy TCP 80/443 traffic is unchanged. Exact native
admission, independent review and delivery remain gates for each new artifact.
ICMP is disabled by default; extra ports such as 2222/optional 22000 require local
operator policy. TCP 4403 is refused. No raw sockets, helper fallback, privilege
grants, application payloads or service/identity conclusions are introduced.
Requested methods are not proof of transmitted packets; filtered/no-response
results remain uncertain. See the host-discovery contract for residual connection
effects, check/response counts and a future separately authorized live recipe.
Supported native scratch
install/enable and a three-alias fixture workflow/restart are exercised by the
canonical verifier. Passing synthetic checks does not establish live-network
readiness, reviewer approval, target integration or publication.

The corrected Docker harness awaits exact-head GitHub-hosted acceptance. The
public-only bootstrap uses standard unprivileged Docker provisioning defaults
for genuine apt/dpkg ownership and maintainer operations, with no-new-privileges
and default seccomp/AppArmor. Candidate acceptance remains non-root, cap-drop ALL,
read-only and network-none. No local Docker or heavyweight setup is authorized.
Primary setup failure/logs and missing success-stage evidence are retained by
the repaired exporter; synthetic exporter tests are not native acceptance.
APT now captures authenticated downloaded archives before normal package cache
cleanup, binds final installed versions to actual archives or the pinned base,
and exports incremental config/command/count diagnostics on failure. Native tool
archive hashes likewise precede PM cache release. Corrected hosted proof remains
pending; no real package/native success is inferred from local fixtures.
The subsequent observed native CLI flag refusal is repaired with supported named
`pm.cli install python uv` (no incompatible `--tools-only`, no enlarged default
closure). Actual pinned parser/dispatch/API regressions and bounded command-phase
diagnostics accompany [the full native PM audit](docs/native-pm-contract-audit.md).
Failed-command exceptions now carry exit summaries, not full child output in
tracebacks. Encoded started/terminal diagnostics share a 1 MiB cumulative budget
with pre-spawn terminal reservation; the 4 MiB child/export limits are unchanged.
Real near-limit and repeated hostile-output regressions retain primary evidence
under the actual aggregate exporter bound; they are not hosted acceptance.
Public-core Git reconstruction and both public setup wrappers now share that
same bounded command audit. All six fixed Git stages retain failed argv/exit/
output count/hash/head-tail in bootstrap.log rather than pointing to a missing
terminal audit. Real-child/export, tiny real-Git success, deadline/reaping and
pre-effect budget regressions cover this repair without executing Docker.
See [the complete bootstrap permission audit](docs/bootstrap-permission-contract.md).
Actual hosted run `37700249768` completed public APT/native tool/verifier/union
setup, then refused an unexported committed-image mismatch. Diagnostic successor
run `37704198046` retained actual inspect: only `Config.Cmd` failed, containing the
setup argv after Docker's empty-command merge. The corrected contract commits
exact exec-form `CMD ["/usr/bin/true"]`, empty entrypoint and unchanged UID/labels/
ancestry. Both setup paths check the existing root-owned no-op and audit its zero
output/exit before success; reuse and cleanup recheck the exact default. Candidate
acceptance still supplies its fixed Python/mode argv. Journals, bounded readback,
failure precedence and unverified-image cleanup refusal are preserved. Corrected
actual hosted/native/full/cold/complete-cleanup acceptance remains pending.
See [committed-image evidence and source-hypothesis limits](docs/committed-image-readback.md).
Hosted run `37707667589` verified that corrected base, then refused smoke-container
ownership before start without exporting container inspect. The historical precise
field remains unknown. Moby's create/merge source demonstrates that base labels
inherit; preflight now revalidates/fixes the full base provenance into one exact
11-label expectation, with create's immutable returned ID required across the
lifecycle. Bounded actual container readback is retained before predicates, with
precise field/label diagnostics and independent consumer retention on failures.
No extra-label subset, cleanup bypass or isolation change is permitted. See
[container identity evidence and limits](docs/container-identity-readback.md).
Corrected actual hosted/native/cold/full-canonical/complete-cleanup remains pending.
Actual hosted run `37712086262` cleared exact labels/ID/isolation and cleaned reached
containers/base, but Git refused runner-owned `/candidate` before early evidence.
The successor uses one exact process-local snapshot Git exception backed by the
controller's verified commit/tree and complete blob checks, forwards it only to
isolated children, and captures startup failures without unproven identity claims.
The adjacent 0733 export leaf could not be listed by a different UID; hosted-only
sticky 01777 on that empty leaf under unchanged private 0700 ancestors repairs
the POSIX layout, with files 0600 and bounded Docker archive readback. No historical
write PermissionError or corrected hosted/native success is inferred. See
[snapshot startup/layout contract](docs/snapshot-startup-contract.md).
Hosted run `37716278161` now passes startup, cross-UID exports and reached-mode
cleanup, but refuses complete-core identity before native scanner import. Its
historical member delta is unknown. The actual pinned named-Python dispatch
publishes project-local `.hermes/bin`; tiny real publication tests reproduce that
pollution. The hosted producer now reconstructs the entire authenticated public
source after PM setup, rechecks executable semantics after readability, and the
consumer exports full actual seed/copy manifests before refusing any drift.
Pins, complete-tree equality, scanner exclusions and isolation remain unchanged.
This is source/fixture evidence, not corrected hosted/native acceptance. See
[complete-core identity contract](docs/complete-core-identity.md).
Actual hosted run `37720941089` now passes complete source identity and full native
CAUTION scanning, but genuine installation reports EACCES executing fixture uv.
The precise historical permission cause is unknown. The diagnostics-only successor
retains bounded actual native tool/ancestor/hash/loader/kernel-mount evidence and
fixed version-attempt errno before installation, without changing permissions or
isolation. Actual corrected native/full/cold acceptance remains pending. See
[native-tool execution evidence](docs/native-tool-execution.md).
Actual hosted run `37724779987` now proves `/work` tmpfs noexec and both contained
native version attempts EACCES despite searchable mode0755/UID1000 tool paths.
The narrow correction adds explicit exec only to that private 2g `/work` tmpfs;
nosuid/nodev/UID/GID/mode bounds and `/tmp` noexec remain unchanged. Actual kernel
flags and both contained current-version results must pass before enable or any
acceptance claim; installer failure still takes precedence. This source correction
is not actual corrected hosted/native/full/cold acceptance, which remains pending.
Subsequent actual run `37729012087` passes the corrected kernel/tool predicates
and completes genuine native install, but fresh enable fails resolving the pinned
kittentts URL under network:none. Exact cache/key/freshness deficiency is unknown.
The diagnostics-only successor retains bounded actual producer/consumer source,
lock and cache readbacks, native resolver debug output, and enable logs/audit even
on failure, without changing pins, selection, resolver or isolation. It does not
claim cache closure or native-enabled/full/cold acceptance. See
[member-union cache evidence and limits](docs/native-union-cache-diagnostics.md).
Subsequent actual run `37734182194` retained stale direct-URL HTTP revalidation
and network-none DNS refusal; native enabled/full/cold acceptance still failed.
The current successor consumes independently source-reviewed/authenticated core
`5645275e50d66dca04c9565634f9b5207a38aef5` from the public fork and requests its
explicit native offline dependency policy only during network-none enable. The
default online setup, native fresh union/selection, scanning and consent remain.
This is not demonstrated cache closure or corrected hosted/native acceptance.
See [authenticated offline consumer and remaining gates](docs/native-offline-consumer.md).
Actual hosted run `37806326519` reached explicit offline uv but refused the pinned
Misaki Git fetch after genuine native install. Online static metadata success did
not establish source closure; the precise historical cache deficiency is unknown.
The narrow producer successor prepares only that immutable Git requirement with
supported pinned uv no-deps installation into disposable targets, requires an
independent empty-target offline replay and real origin/Git-object readback, then
disposes both targets before seed publication. No extras/selected state transfer,
opaque cache edits, consumer networking or core/tool pin changes are introduced.
Actual corrected full union/native/canonical/cold acceptance remains pending. See
[producer Git preparation and evidence limits](docs/producer-git-preparation.md).
Actual hosted run `37815273128` passed that genuine source preparation/offline
replay, disposal, online warm and complete core identity, then refused the retained
seed limit before image commit. Exact failed totals/clause remain unknown. The
producer-only successor packs the owned shallow CORE Git snapshot, preserving
every actual object and complete source; no uv cache edits or retention increase.
Bounded component totals/failure proof survive independently of success inventory.
Real corrected retained fit/native/full/cold/cleanup remains pending. See
[owned Git packing and retention accounting](docs/producer-retention.md).
Actual hosted run `37823927095` passed repack, verify-pack and both pre-prune
fscks, then the live observer raced legitimate loose-object removal during
`prune-packed`. This was not demonstrated object loss or retained-budget overflow.
The successor tolerates only disappearing loose objects/empty fanout directories
while that exact owned command is active, counts and reports incomplete samples,
and retains strict final source/object/component accounting and unchanged limits.
Tiny barrier-controlled real-child RED/GREEN is not corrected hosted acceptance;
retained fit/native/full/cold/cleanup and final review remain pending.
Actual hosted run `37831615760` resolved that observer race and completed full
object/source-preserving compaction, then strict final accounting measured the
seed 22,832,303 bytes over the unchanged 1 GiB ceiling. A tiny tuned comparison
does not establish full-core savings or impossibility. The current successor is
MEASUREMENT ONLY: exact source/ref/allowlist/hash validation routes a reviewed
feature push exclusively to two fixed bounded hosted native Git variants, never
the known failing acceptance pipeline. Production packing/cache/PM/pins/limits
remain unchanged. Immutable non-Git counters plus explicit reserve yield only a
projection; all measurement reports keep native/canonical/final acceptance false.
The host Git/zlib runtime differs from the producer and is recorded, not promoted
to runtime equivalence. See [hosted packing measurement](docs/hosted-packing-measurement.md).
The legacy metadata-plan build/acquisition/root setup remains disabled pending
authenticated dependency closure and a reviewed aggregate storage architecture. Strict
`linked_metadata_only` projections and declared budget estimates cannot enable
that gate. The current artifact still needs fresh ordinary native admission;
running the verifier in a predecessor interpreter is bootstrap evidence only.

Network Atlas observes and remembers infrastructure. It does not administer it.
The implementation uses local SQLite, bounded allowlisted discovery,
fixed read-only SSH probes, and deterministic Markdown/Mermaid exports. No
external database, web app, MCP server, or background service is required.

## Project documents

- [Original project specification](docs/project-specification.md)
- [Implementation addendum](docs/implementation-addendum.md) — controls conflicts
  with examples or ambiguous wording in the original specification.
- [Delivery plan](docs/delivery-plan.md)
- [Acceptance matrix](docs/acceptance-matrix.md)
- [Concrete contract decisions](docs/contract-decisions.md)
- [Operator installation, configuration and cumulative verification](docs/operator-guide.md)
- [Hosted-CI CAUTION exception and unchanged local consent](docs/native-caution-confirmation.md)
- [Disposable Docker acceptance and separate local/native/hosted gates](docs/docker-acceptance.md)
- [Fixed snapshot Git trust, cross-UID export and early failure evidence](docs/snapshot-startup-contract.md)
- [Complete authenticated public core across PM setup and contained copying](docs/complete-core-identity.md)
- [Bounded actual selected native-tool and kernel execution diagnostics](docs/native-tool-execution.md)
- [Bounded actual member-union source/cache and failure-log diagnostics](docs/native-union-cache-diagnostics.md)
- [Authenticated core prerequisite and explicit network-none offline enable](docs/native-offline-consumer.md)
- [Narrow immutable Git-source preparation, offline replay and disposal](docs/producer-git-preparation.md)
- [Owned shallow-core packing, complete object preservation and retained accounting](docs/producer-retention.md)
- [Legacy finite public Docker acquisition/peak plan and unresolved execution gates](docs/docker-acquisition-plan.md)
- [Atlas Core usage and verification](docs/atlas-core.md)
- [Bounded unresolved discovery evidence and identity lineage](docs/unresolved-evidence.md)
- [Local discovery, reconciliation and offline verification](docs/local-discovery.md)
- [Host-discovery policy, datagram-only transport and combined budgets](docs/host-discovery-policy.md)
- [Authorized SSH inspection, trust boundaries and offline verification](docs/authorized-ssh-inspection.md)
- [Historical scaffold compatibility and verification](docs/scaffold-verification.md)
- [Contributor instructions](CONTRIBUTING.md)
- [Security boundaries](SECURITY.md)

V1 encompasses Atlas Core, Local Discovery, and Authorized SSH Inspection.
Proxmox API, richer infrastructure integrations, and service enumeration are
later work, not prerequisites. Unknown topology stays unknown.

## Verification

```sh
python3 scripts/verify.py
```

This runs repository contracts, core persistence/identity/provenance/query/map,
offline LAN/SSH collection/reconciliation/bounds, and mandatory isolated native Hermes
runtime dispatch and restart tests, including the complete three-alias scenario.
A compatible verifier runtime, exact Hermes source, declared scratch directory and
candidate-bound native admission fixture are prerequisites; run the separate
online setup in docs/operator-guide.md first. Canonical tests and their children
are socket-denied. Missing Hermes is a failure, not a silent test skip; missing or
stale admission evidence also fails. The explicitly approved hosted-CI mode uses
supported native force for CAUTION only on fresh GitHub-hosted Ubuntu VMs, with
full scanning, DANGEROUS refusal, pinned source/actions and read-only permissions,
without supplied secrets or deployment access. Local/runtime force remains
prohibited; changed local candidates need fresh ordinary exact-byte consent.
No signing-controller provisioning is a CI gate. See docs/native-caution-confirmation.md.
CI uses the same setup/verifier path, but full hosted native acceptance remains
separately gated on the reviewed exact artifact; local workflow checks do not prove it.
Tests must use synthetic fixtures and isolated Hermes homes. They must not scan
a real LAN, inspect a real SSH host, or read the operator's live atlas.

## Installation

The repository root is a normal plugin.yaml/__init__.py native directory plugin.
The isolated setup uses real supported install/enable entrypoints, exact synthetic
candidate pinning, native security scanning and PM member-union admission, then
reads back installed bytes and selected dependency generations. Acceptance runs
separately with synthetic non-forwarding transports through real native discovery,
registration/tool/slash/CLI dispatch and fresh-process restart queries/maps.
See docs/operator-guide.md for reproducible setup, dependency failure handling,
shared-state trust boundaries and operator updates. It is not a released atlas.
Live installation/activation, LAN discovery, actual SSH and gateway restart remain
unperformed and require separate explicit authorization. Examples are not permission.

## License

Copyright (C) 2026 Network Atlas contributors.

This project is free software: you can redistribute it and/or modify it under
the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.
It is distributed without any warranty. See [LICENSE](LICENSE).

SPDX-License-Identifier: GPL-3.0-or-later
