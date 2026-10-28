# Network Atlas

Durable network knowledge for Hermes: devices, interfaces, addresses, relations,
and historical evidence in profile-aware SQLite. Query what is already known,
render Markdown/Mermaid maps, or explicitly collect bounded LAN, TCP/UDP endpoint,
and configured SSH observations. Atlas observes and remembers; it does not
administer infrastructure. No external database or background service is needed.

## Requirements and installation

Requires stock Hermes **>=0.21.7** and its supported Python runtime (>=3.11).
As of 2026-10-26, CI targets Hermes v0.21.7 (oldest tested stable release) and
v0.22.5 (latest stable release checked that date) on Linux x86_64 and arm64.
The manifest follows Hermes's additive plugin contract without an upper bound;
other releases are not individually verified.

Replace PROFILE with your existing profile (`default` for the default profile).
Use the first column from `git ls-remote` below as COMMIT_SHA, or copy the full
40-character commit from the revision you reviewed on GitHub:

```sh
git ls-remote https://github.com/vice-magus-faolan/hermes-network-atlas.git refs/heads/main
hermes -p PROFILE plugins install https://github.com/vice-magus-faolan/hermes-network-atlas.git --ref COMMIT_SHA --no-enable
hermes -p PROFILE plugins enable network-atlas
hermes -p PROFILE plugins show network-atlas
```

Installation scans the plugin and resolves its declared dependency. Enabling
changes the selected profile's plugin selection. Hermes can hot-reload a
responding gateway's commands; Atlas's Python tools appear in a new session.
If no gateway responds, follow the CLI's `hermes gateway restart` hint.

## Find policy and stored knowledge

Atlas uses the selected Hermes profile home, not the repository or working
directory. Native `plugins.entries.network-atlas.settings.policy` is operator policy;
`plugin-data/network-atlas/atlas.sqlite3` is the new default knowledge store. The default profile home is
`~/.hermes`; named profiles normally use `~/.hermes/profiles/NAME`.
An explicit `HERMES_HOME` can override the home. See
[profile-local configuration](docs/operator-guide.md#profile-local-configuration)
before editing anything. Profiles can share a database; each keeps its own policy.

Keep the profile and its native config private. Missing settings grant nothing;
Atlas validates the policy returned by Hermes. Hermes owns settings caching,
fallback and worker snapshots. Existing users must explicitly
[convert legacy policy and storage](docs/operator-guide.md#convert-legacy-policy-and-storage)
before using the new default; registration and reads never move a database.

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
Status includes bounded `guidance`: eligible unapplied batches, currently authorized
inspection/discovery choices, historical unresolved identity and missing relationships.
These are suggestions, never automatic collection or permission changes. See the
[status guidance fields](docs/operator-guide.md#status-guidance).

Read provenance and timestamps before interpreting results: operator assertions,
direct observations, and explained inference remain distinct. Stale is age-based;
unknown, partial, failed, or no-response evidence never means offline or deleted.
Even fresh historical evidence does not prove reachability now. Device identity
is not inferred from an IP or hostname alone; unknown topology stays unknown.
See the [read-only workflow](docs/operator-guide.md#read-existing-knowledge) for
pagination, unidentified responses, endpoint history, and shared-store queries.

## Collect your LAN, reconcile, then map

Install iproute2 (the `ip` utility) for passive collection. Set the selected profile's
native policy, replacing `192.168.1.0/24` with your
actual LAN's canonical network. It enables passive collection only, not scanning:

```sh
hermes -p PROFILE config set plugins.entries.network-atlas.settings.policy '{"networks":{"home":{"cidr":"192.168.1.0/24","discovery":{"passive":true}}}}'
```

```sh
hermes -p PROFILE network-atlas discover --network home --mode passive
hermes -p PROFILE network-atlas reconcile --batch-id BATCH_ID
hermes -p PROFILE network-atlas map --format markdown
```

Replace BATCH_ID with the returned `batch_id`. Discovery stores evidence;
reconciliation applies it to inventory. Neighbor caches can be empty or partial,
not a complete LAN census.

## Machine inventory from an authorized SSH alias

If the selected profile already authorizes an existing OpenSSH alias, inspection
can bootstrap inventory without a pre-existing device ID:

```sh
hermes -p PROFILE network-atlas inspect --target lab-a
hermes -p PROFILE network-atlas reconcile --batch-id BATCH_ID
hermes -p PROFILE network-atlas query --query-json '{"device_id":"DEVICE_ID"}'
hermes -p PROFILE network-atlas map --format markdown
```

Use inspection's returned BATCH_ID and reconciliation's returned DEVICE_ID.
Successful fixed Linux probes supply hostname, OS, owned interfaces and addresses;
partial/failed probes retain their actual outcomes. Endpoint responses and IP-only
discovery are not substitutes for device identity. Retained SSH routes/neighbors
can support inferred configured-next-hop relationships to already identified peers,
not physical links or current reachability. Query `{"view":"topology"}` for evidence
and unresolved reasons. See [logical topology](docs/authorized-ssh-inspection.md#logical-topology).

## Model tools

Replace DEVICE_ID and BATCH_ID with returned IDs; collection examples require
matching local policy (the quick start enables only passive discovery).

- `network_query` — read stored inventory, status/guidance or history; never discover.
  Example: `{"limit":10,"offset":0}`.
- `network_map` — render stored relations; export is an optional file write.
  Example: `{"format":"markdown","export":false}`.
- `network_discover` — store a bounded LAN observation batch without applying it.
  Example: `{"network":"home","mode":"passive"}`.
- `network_reconcile` — apply an eligible local LAN or SSH batch, with safe retries.
  Example: `{"batch_id":"BATCH_ID"}`.
- `network_inspect` — collect hostname/OS/interface/address inventory from an
  authorized SSH alias, even without an existing device. Reconcile its returned
  batch, then query/map the device. Example: `{"target":"lab-a"}`.
- `network_check_endpoints` — collect and persist explicitly configured TCP/UDP evidence.
  Example: `{"network":"home"}`; no device or service identity is created.
  For unfinished work, preview with `{"preview_batch_id":"BATCH_ID"}`, then
  explicitly make new subset checks with `{"continue_batch_id":"BATCH_ID"}`.
  [Continuation](docs/endpoint-checks.md#continue-unfinished-work--new-traffic) is
  distinct from no-contact resume and preserves original history.
- `network_update` — persist explained inference, never operator facts or access.
  Example: `{"device_id":"DEVICE_ID","field":"description","value":"Possible NAS","explanation":"Name suggests storage; unconfirmed"}`.

## Security boundaries

- Local subprocesses use fixed argv without a shell or caller commands; no sudo.
- Time and output limits terminate and reap owned local process groups.
- SSH uses existing keys and strict host-key checks, BatchMode, no PTY, forwarding,
  LocalCommand or multiplex reuse. Local cleanup cannot guarantee remote cleanup.
- Configured IPv4 scopes have at most 256 addresses; budgets are code-enforced.
  Active collection defaults to RFC1918/private and IPv4 link-local ranges;
  other scopes need [per-network public opt-in](docs/operator-guide.md#collection-grants-and-limits).
  No raw-socket fallback, service enumeration or absence-based deletion.
- TCP connects can consume slots and generate logs without application payloads;
  port 4403 is refused. Same-UID code, executables and SSH config are trusted.
- UDP sends one empty unicast datagram per selected tuple; local send success or
  silence is inconclusive. No QUIC or broadcast/multicast discovery is performed.
- Keep policy, SQLite, WAL, exports and credentials private; use a consistent SQLite
  backup before upgrades. See the runbook for recovery without deleting history.

## Guides

- [Operator runbook: setup, querying, updates, recovery](docs/operator-guide.md)
- [Atlas Core: provenance, identity, queries, shared storage](docs/atlas-core.md)
- [Unidentified discovery evidence and lineage](docs/unresolved-evidence.md)
- [LAN collection and reconciliation](docs/local-discovery.md)
- [ICMP/TCP host-discovery policy and limitations](docs/host-discovery-policy.md)
- [TCP/UDP endpoint policy, recovery, and shared queries](docs/endpoint-checks.md)
- [Authorized SSH inspection and transport trust](docs/authorized-ssh-inspection.md)
- [Security boundaries](SECURITY.md) · [Contributing and tests](CONTRIBUTING.md)

## License

Copyright (C) 2026 Network Atlas contributors.

This project is free software: you can redistribute it and/or modify it under
the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.
It is distributed without any warranty. See [LICENSE](LICENSE).

SPDX-License-Identifier: GPL-3.0-or-later
