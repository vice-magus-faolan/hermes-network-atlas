# Network Atlas

A small Hermes-native plugin for durable, provenance-aware network knowledge.

**Status: project bootstrap; the plugin is not implemented or released yet.**
Passing bootstrap checks does not establish V1 acceptance or live-network readiness.

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
- [Contributor instructions](CONTRIBUTING.md)
- [Security boundaries](SECURITY.md)

V1 encompasses Atlas Core, Local Discovery, and Authorized SSH Inspection.
Proxmox API, richer infrastructure integrations, and service enumeration are
later work, not prerequisites. Unknown topology stays unknown.

## Verification

```sh
python3 scripts/verify.py
```

This currently runs the bootstrap contract tests only. Phase 1 must extend this
same command to execute the real plugin tests and integration smoke checks; it
must not remain a documentation-only green check as implementation grows.
Tests must use synthetic fixtures and isolated Hermes homes. They must not scan
a real LAN, inspect a real SSH host, or read the operator's live atlas.

## Installation

No installable plugin exists in this bootstrap. Supported installation and
configuration instructions will ship with the implementation after real Hermes
registration and restart/reopen verification. Do not install this planning
checkout into a live profile or enable discovery from its examples.

## License

Copyright (C) 2026 Network Atlas contributors.

This project is free software: you can redistribute it and/or modify it under
the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.
It is distributed without any warranty. See [LICENSE](LICENSE).

SPDX-License-Identifier: GPL-3.0-or-later
