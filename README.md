# Network Atlas

A small Hermes-native plugin for durable, provenance-aware network knowledge.

**Status: Phase 1 Atlas Core implemented; Phase 2 Local Discovery implemented;
V1 is not complete or released.**
Profile-aware SQLite, immutable provenance/history, interface-first identity,
audited operator/inference updates, bounded read-only query, and deterministic
maps/exports are implemented. Applying receipts report persisted=true; the
compatibility validate-update command still reports applied=false/persisted=false.
Explicit bounded passive/Nmap discovery, immutable evidence batches and
transactional idempotent reconciliation are implemented. SSH transport remains
gated Phase 3 work. Discovery alone never rewrites canonical inventory.
Passing core checks does not establish V1 acceptance or live-network readiness.

Network Atlas observes and remembers infrastructure. It does not administer it.
The planned implementation uses local SQLite, bounded allowlisted discovery,
fixed read-only SSH probes, and deterministic Markdown/Mermaid exports. No
external database, web app, MCP server, or background service is required.

## Project documents

- [Original project specification](docs/project-specification.md)
- [Implementation addendum](docs/implementation-addendum.md) — controls conflicts
  with examples or ambiguous wording in the original specification.
- [Delivery plan](docs/delivery-plan.md)
- [Acceptance matrix](docs/acceptance-matrix.md)
- [Concrete contract decisions](docs/contract-decisions.md)
- [Atlas Core usage and verification](docs/atlas-core.md)
- [Local discovery, reconciliation and offline verification](docs/local-discovery.md)
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

This runs bootstrap contracts, core persistence/identity/provenance/query/map,
offline collection/reconciliation/bounds, and mandatory isolated native Hermes
runtime dispatch and restart tests. A compatible
Hermes source/dependency runtime and declared scratch directory are prerequisites;
see the verification guide. Missing Hermes is a failure, not a silent test skip.
The same command must expand with each implemented milestone.
Tests must use synthetic fixtures and isolated Hermes homes. They must not scan
a real LAN, inspect a real SSH host, or read the operator's live atlas.

## Installation

The repository root is a normal plugin.yaml/__init__.py native directory plugin.
Tests copy its source into an isolated scratch Hermes home and exercise opt-in
discovery/registration/dispatch and persistent native restart queries/maps. It
is not a released atlas. Full PM dependency admission/install-command and complete
V1 acceptance remain cumulative gates. Do not install into a live profile or treat examples as scan
authorization.

## License

Copyright (C) 2026 Network Atlas contributors.

This project is free software: you can redistribute it and/or modify it under
the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.
It is distributed without any warranty. See [LICENSE](LICENSE).

SPDX-License-Identifier: GPL-3.0-or-later
