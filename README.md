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
counts are deduplicated. Legacy TCP 80/443 traffic is unchanged. Native validation,
independent review and delivery remain separate checks for each new artifact.
ICMP is disabled by default; extra ports such as 2222/optional 22000 require local
operator policy. TCP 4403 is refused. No raw sockets, helper fallback, privilege
grants, application payloads or service/identity conclusions are introduced.
Requested methods are not proof of transmitted packets; filtered/no-response
results remain uncertain. See the host-discovery contract for residual connection
effects, check/response counts and a future separately authorized live recipe.
Stock native directory-plugin registration and a three-alias fixture workflow/
restart are exercised by pytest. Passing synthetic checks does not establish live-network
readiness, reviewer approval, target integration or publication.

The narrow issue-1 endpoint slice adds separately enabled named-policy TCP checks
that persist, project and read back historical endpoint evidence in one operation.
Exact-batch resume never recollects. Shared readers can query endpoints even with
zero identified devices, without gaining collection or SSH permission. At most
four operator-selected TCP ports; 4403 remains excluded. No greeting reads,
service identification or application payloads. See [endpoint checks](docs/endpoint-checks.md).

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
- [Atlas Core usage and verification](docs/atlas-core.md)
- [Bounded unresolved discovery evidence and identity lineage](docs/unresolved-evidence.md)
- [Local discovery, reconciliation and offline verification](docs/local-discovery.md)
- [Host-discovery policy, datagram-only transport and combined budgets](docs/host-discovery-policy.md)
- [Durable native TCP endpoint checks, recovery and shared queries](docs/endpoint-checks.md)
- [Authorized SSH inspection, trust boundaries and offline verification](docs/authorized-ssh-inspection.md)
- [Historical scaffold compatibility and verification](docs/scaffold-verification.md)
- [Contributor instructions](CONTRIBUTING.md)
- [Security boundaries](SECURITY.md)

V1 encompasses Atlas Core, Local Discovery, and Authorized SSH Inspection.
Proxmox API, richer infrastructure integrations, and service enumeration are
later work, not prerequisites. Unknown topology stays unknown.
The endpoint slice records connect outcomes only; it is not general service enumeration.

## Verification

```sh
python3 -m pytest -q
```

Use a stock supported Hermes runtime and its declared dependencies, plus
requirements-test.txt. If Hermes is not importable, point
NETWORK_ATLAS_HERMES_ROOT at its source checkout. Pytest owns scratch fixtures;
no manual TMPDIR, native receipt, core identity or GitHub environment is required.
The suite covers persistence/identity/provenance/query/map, synthetic LAN/SSH
collection/reconciliation/bounds, real native registration/dispatch and restart,
including the three-alias scenario. Missing Hermes fails rather than skips.
For ordinary Docker validation, build dependencies online, then run product checks
with the network disabled:

```sh
docker build -f docker/validation.Dockerfile -t hermes-network-atlas-tests:local .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges hermes-network-atlas-tests:local
```

The image uses unmodified NousResearch/hermes-agent v0.21.6 and runs actual
`hermes plugins validate .`, `hermes plugins doctor . --ci` and pytest. CI uses
the same checks on Linux x86_64 and arm64 runners; a configured job is not proof
it has passed. The successor still needs exact-head hosted evidence and review.
Tests must use synthetic fixtures and isolated Hermes homes. They must not scan
a real LAN, inspect a real SSH host, or read the operator's live atlas.

## Installation

The repository root is a normal plugin.yaml/__init__.py native directory plugin.
Install a reviewed Atlas revision using stock Hermes's supported plugin commands.
Keep scanning, consent and dependency handling enabled. Tests use synthetic
directory-plugin homes and non-forwarding transports through real native discovery,
registration/tool/slash/CLI dispatch and fresh-process restart queries/maps; they
do not exercise the package manager's install/enable lifecycle.
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
