# Network Atlas

Durable network knowledge for Hermes: devices, interfaces, addresses, relations,
and historical evidence in profile-aware SQLite. Query what is already known,
render Markdown/Mermaid maps, or explicitly collect bounded LAN, TCP endpoint,
and authorized SSH observations. Atlas observes and remembers; it does not
administer infrastructure. No external database or background service is needed.

## Installation

Requires Python >=3.11,<3.15 and stock Hermes >=0.21.4,<0.22. The repository's
validation uses unmodified NousResearch/hermes-agent v0.21.6 and synthetic,
network-isolated fixtures, including native directory-plugin registration and
restart. This does not establish package-manager install/enable, live-network,
latest-Hermes, or every-platform compatibility. See the
[operator guide](docs/operator-guide.md#installation-and-support) for details.

For an operator-approved installation, replace PROFILE and REVIEWED_SHA with
the intended existing profile and an immutable reviewed 40-character commit:

```sh
hermes -p PROFILE plugins install https://github.com/vice-magus-faolan/hermes-network-atlas.git --ref REVIEWED_SHA --no-enable
hermes -p PROFILE plugins enable network-atlas
hermes -p PROFILE plugins show network-atlas
```

Keep native security scanning and dependency/capability consent enabled. Enabling
affects the selected profile; restarting a running gateway is a separate operator
decision. These examples do not authorize installation, probing, or restart.

## Find policy and stored knowledge

Atlas uses the selected Hermes profile home, not the repository or working
directory. Its `network-atlas/config.yaml` is operator policy;
`network-atlas/atlas.sqlite3` is stored knowledge. The default profile home is
`~/.hermes`; named profiles normally use `~/.hermes/profiles/NAME`.
An explicit `HERMES_HOME` can override the home. See
[profile-local configuration](docs/operator-guide.md#profile-local-configuration)
before editing anything. An optional shared database never shares permissions.

A minimal policy for reading existing inventory (no collection grants) is:

```yaml
version: 1
networks: {}
ssh:
  enabled: false
  hosts: {}
retention:
  stale_after_days: 14
```

Keep policy private (0600 in a 0700 directory). A missing file grants nothing;
an existing empty, malformed, or unknown-key policy fails closed.

## Read existing inventory — no scan

With Atlas installed/enabled in PROFILE, these commands only read stored data:

```sh
hermes -p PROFILE network-atlas status
hermes -p PROFILE network-atlas query --query-json '{"limit":10,"offset":0}'
hermes -p PROFILE network-atlas map --format markdown
```

Equivalent model tools are `network_query` with `{"limit":10,"offset":0}` and
`network_map` with `{"format":"markdown","export":false}`. In that profile's
Hermes session, `/network status` and `/network map markdown` use the same core.
Query/map do not collect, schedule, initialize, or migrate the atlas. Map export
is a separate opt-in write. Empty inventory is not proof that no devices exist.

Read provenance and timestamps before interpreting results: operator assertions,
direct observations, and explained inference remain distinct. Stale is age-based;
unknown, partial, failed, or no-response evidence never means offline/deleted.
Even fresh historical evidence does not prove reachability now. Device identity
is not inferred from an IP or hostname alone; unknown topology stays unknown.
See the [read-only workflow](docs/operator-guide.md#read-existing-knowledge) for
pagination, unidentified responses, endpoint history, and shared-store queries.

## Collection and safety

Collection is explicit and policy-bound: `network_discover` selects a configured
network/mode, and `network_inspect` selects an authorized SSH alias/device.
They store immutable batches; `network_reconcile` applies eligible local batches
separately. `network_check_endpoints` has its own opt-in policy and durable
collect/project/readback route; it creates no device identity or service claim.

Active IPv4 scopes have at most 256 addresses; time, concurrency, output, and
pagination ceilings are code-enforced. No arbitrary ranges/commands, privilege
grants, raw-socket fallback, service enumeration, or automatic deletion. TCP
connects can consume slots and generate logs even without application payloads;
port 4403 is refused. SSH requires existing keys/config and strict host-key checks.
Same-UID code, installed executables, and operator SSH configuration are trusted,
not sandboxed. Never publish private policy, SQLite/WAL, exports, or credentials.

## Guides

- [Operator runbook: setup, querying, updates, recovery](docs/operator-guide.md)
- [Atlas Core: provenance, identity, queries, shared storage](docs/atlas-core.md)
- [Unidentified discovery evidence and lineage](docs/unresolved-evidence.md)
- [LAN collection and reconciliation](docs/local-discovery.md)
- [ICMP/TCP host-discovery policy and limitations](docs/host-discovery-policy.md)
- [TCP endpoint policy, recovery, and shared queries](docs/endpoint-checks.md)
- [Authorized SSH inspection and transport trust](docs/authorized-ssh-inspection.md)
- [Security boundaries](SECURITY.md) · [Contributing and tests](CONTRIBUTING.md)

## License

Copyright (C) 2026 Network Atlas contributors.

This project is free software: you can redistribute it and/or modify it under
the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.
It is distributed without any warranty. See [LICENSE](LICENSE).

SPDX-License-Identifier: GPL-3.0-or-later
