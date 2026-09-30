# Network Atlas

A small Hermes-native plugin for durable, provenance-aware network knowledge.

**Status: native contract scaffold; the V1 atlas is not implemented or released yet.**
Policy validation, readiness, and separated inference/operator proposal validation
are implemented. Receipts explicitly report applied=false and persisted=false.
Persistence, querying inventory, maps, and collectors remain gated Phase 1–3 work.
Passing scaffold checks does not establish V1 acceptance or live-network readiness.

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
- [Scaffold compatibility and isolated verification](docs/scaffold-verification.md)
- [Contributor instructions](CONTRIBUTING.md)
- [Security boundaries](SECURITY.md)

V1 encompasses Atlas Core, Local Discovery, and Authorized SSH Inspection.
Proxmox API, richer infrastructure integrations, and service enumeration are
later work, not prerequisites. Unknown topology stays unknown.

## Verification

```sh
python3 scripts/verify.py
```

This runs honestly scoped bootstrap contracts, real config/provenance/handler
behavior, and mandatory isolated native Hermes runtime smoke tests. A compatible
Hermes source/dependency runtime and declared scratch directory are prerequisites;
see the verification guide. Missing Hermes is a failure, not a silent test skip.
The same command must expand with each implemented milestone.
Tests must use synthetic fixtures and isolated Hermes homes. They must not scan
a real LAN, inspect a real SSH host, or read the operator's live atlas.

## Installation

The repository root is a normal plugin.yaml/__init__.py native directory plugin.
Tests copy its source into an isolated scratch Hermes home and exercise opt-in
discovery/registration/dispatch. It is not a released atlas. Full dependency
admission/install-command and persistent restart acceptance remain later A01/A02
gates. Do not install this scaffold into a live profile or treat examples as scan
authorization.

## License

Copyright (C) 2026 Network Atlas contributors.

This project is free software: you can redistribute it and/or modify it under
the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.
It is distributed without any warranty. See [LICENSE](LICENSE).

SPDX-License-Identifier: GPL-3.0-or-later
