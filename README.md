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
- [Inactive exact-artifact native CAUTION confirmation design](docs/native-caution-confirmation.md)
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
stale admission evidence also fails. The prospective externally signed ordinary
CAUTION confirmation route is inactive; default non-TTY CI setup still refuses
CAUTION until separately authorized outside-candidate trust provisioning and
exact-artifact local/CI consent. See docs/native-caution-confirmation.md. CI uses
the same setup/verifier path, but
GitHub CI execution has not been performed on this unpushed implementation.
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
