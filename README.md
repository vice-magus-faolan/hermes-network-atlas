# Network Atlas

Durable network knowledge for Hermes: devices, interfaces, addresses, relations,
and historical evidence in profile-aware SQLite. Query what is already known,
render Markdown/Mermaid maps, or explicitly collect bounded LAN, TCP endpoint,
and configured SSH observations. Atlas observes and remembers; it does not
administer infrastructure. No external database or background service is needed.

## Requirements and installation

Requires stock Hermes **>=0.21.4,<0.22** and Python >=3.11,<3.15.
Tested with Hermes v0.21.6 on Linux x86_64 and arm64. The current manifest refuses
Hermes 0.22.x, including v0.22.2, with:
`Plugin 'network-atlas' requires hermes >=0.21.4,<0.22, running 0.22.2`.
[Issue #15](https://github.com/vice-magus-faolan/hermes-network-atlas/issues/15)
tracks newer-Hermes compatibility and the CI runtime-version detection defect.

Replace PROFILE with your existing profile (`default` for the default profile)
and REVIEWED_SHA with the Atlas revision's immutable 40-character commit:

```sh
hermes -p PROFILE plugins install https://github.com/vice-magus-faolan/hermes-network-atlas.git --ref REVIEWED_SHA --no-enable
hermes -p PROFILE plugins enable network-atlas
hermes -p PROFILE plugins show network-atlas
```

Installation scans the plugin and resolves its declared dependency. Enabling
changes the selected profile's plugin selection. Hermes 0.21.6 can hot-reload a
responding gateway's commands; Atlas's Python tools appear in a new session.
If no gateway responds, follow the CLI's `hermes gateway restart` hint.

## Find policy and stored knowledge

Atlas uses the selected Hermes profile home, not the repository or working
directory. Its `network-atlas/config.yaml` is operator policy;
`network-atlas/atlas.sqlite3` is stored knowledge. The default profile home is
`~/.hermes`; named profiles normally use `~/.hermes/profiles/NAME`.
An explicit `HERMES_HOME` can override the home. See
[profile-local configuration](docs/operator-guide.md#profile-local-configuration)
before editing anything. An optional shared database never shares permissions.

Keep policy private (0600 in a 0700 directory). A missing file grants nothing;
an existing empty, malformed, or unknown-key policy fails closed.

## Read existing inventory — no scan

With Atlas installed and enabled in PROFILE, these commands only read stored data:

```sh
hermes -p PROFILE network-atlas status
hermes -p PROFILE network-atlas query --query-json '{"limit":10,"offset":0}'
hermes -p PROFILE network-atlas map --format markdown
```

In that profile's Hermes session, `/network status` and `/network map markdown`
read the same knowledge. Model-tool examples are listed below.
Query and map do not collect, schedule, initialize, or migrate the atlas. Map export
is a separate opt-in write. Empty inventory is not proof that no devices exist.

Read provenance and timestamps before interpreting results: operator assertions,
direct observations, and explained inference remain distinct. Stale is age-based;
unknown, partial, failed, or no-response evidence never means offline or deleted.
Even fresh historical evidence does not prove reachability now. Device identity
is not inferred from an IP or hostname alone; unknown topology stays unknown.
See the [read-only workflow](docs/operator-guide.md#read-existing-knowledge) for
pagination, unidentified responses, endpoint history, and shared-store queries.

## Collect your LAN, reconcile, then map

Install iproute2 (the `ip` utility) for passive collection. In the selected home's
`network-atlas/config.yaml`, use this policy, replacing `192.168.1.0/24` with your
actual LAN's canonical network. It enables passive collection only, not scanning:

```yaml
version: 1
networks:
  home:
    cidr: 192.168.1.0/24
    discovery:
      passive: true
      ping: false
ssh:
  enabled: false
  hosts: {}
```

```sh
hermes -p PROFILE network-atlas discover --network home --mode passive
hermes -p PROFILE network-atlas reconcile --batch-id BATCH_ID
hermes -p PROFILE network-atlas map --format markdown
```

Replace BATCH_ID with the returned `batch_id`. Discovery stores evidence;
reconciliation applies it to inventory. Neighbor caches can be empty or partial,
not a complete LAN census. IPs alone never establish device identity.

## Model tools

Replace DEVICE_ID and BATCH_ID with returned IDs; collection examples require
matching local policy (the quick start enables only passive discovery).

- `network_query` — read stored inventory, status or history; never discover.
  Example: `{"limit":10,"offset":0}`.
- `network_map` — render stored relations; export is an optional file write.
  Example: `{"format":"markdown","export":false}`.
- `network_discover` — store a bounded LAN observation batch without applying it.
  Example: `{"network":"home","mode":"passive"}`.
- `network_reconcile` — apply an eligible local LAN or SSH batch, with safe retries.
  Example: `{"batch_id":"BATCH_ID"}`.
- `network_inspect` — collect fixed Linux inventory from a configured SSH alias.
  Example: `{"target":"lab-a"}`.
- `network_check_endpoints` — collect and persist separately enabled TCP evidence.
  Example: `{"network":"home"}`; no device or service identity is created.
- `network_update` — persist explained inference, never operator facts or access.
  Example: `{"device_id":"DEVICE_ID","field":"description","value":"Possible NAS","explanation":"Name suggests storage; unconfirmed"}`.

## Security boundaries

- Local subprocesses use fixed argv without a shell or caller commands; no sudo.
- Time and output limits terminate and reap owned local process groups.
- SSH uses existing keys and strict host-key checks, BatchMode, no PTY, forwarding,
  LocalCommand or multiplex reuse. Local cleanup cannot guarantee remote cleanup.
- Configured IPv4 scopes have at most 256 addresses; budgets are code-enforced.
  No raw-socket fallback, service enumeration or absence-based deletion.
- TCP connects can consume slots and generate logs without application payloads;
  port 4403 is refused. Same-UID code, executables and SSH config are trusted.
- Keep policy, SQLite, WAL, exports and credentials private; use a consistent SQLite
  backup before upgrades. See the runbook for recovery without deleting history.

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
