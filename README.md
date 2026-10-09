# Network Atlas

A small Hermes-native plugin for durable, provenance-aware network knowledge.
Network Atlas observes infrastructure; it does not administer it.

V1 phases 1–3 implemented with cumulative synthetic acceptance. Independent
exact-artifact review, hosted native validation, publication and live activation
are separately gated. Issue #6 host-discovery code is implemented; the corrected
disposable Docker CI path still needs an actual exact-head hosted result.
Source approval and local unit tests are not feature delivery.
The first hosted attempt installed/enabled natively, but canonical tests failed;
its green provider status masked that failure through tee and is not acceptance.

## What it does

- Profile-aware SQLite, immutable observation history and explicit provenance.
- Bounded allowlisted discovery and transactional, idempotent reconciliation.
- Fixed read-only SSH probes for explicitly authorized aliases.
- Read-only queries and deterministic text/Markdown/Mermaid maps; no invented links.
- Operator facts remain distinct from inference. Missing devices are not deleted.

Collection alone never rewrites canonical inventory. Applying receipts report
persisted=true; the compatibility validate-update command retains
applied=false/persisted=false. Unknown identity stays unresolved.

## Issue #6: opt-in host discovery

Legacy policies retain TCP 80/443 Nmap discovery and do not gain ICMP or extra ports.
An operator may configure the following network-local policy (synthetic example,
not authorization to scan):

```yaml
version: 1
networks:
  lab:
    cidr: 192.0.2.0/29
    discovery:
      passive: true
      ping: true
      icmp_echo: true
      tcp_ports: [80, 443, 2222, 22000]
```

`icmp_echo` defaults to false. TCP ports default to [80, 443], must be at most
four distinct strict integers in 1..65535, and cannot include 4403. An empty list
allows ICMP-only policy. Active discovery requires `ping: true`; tools only select
a configured network and mode, never targets, methods, ports or flags.

ICMP uses already-permitted Linux echo datagram sockets, not raw sockets or an
external helper. Permission/protocol failures are reported without fallback,
sudo, capability grants, kernel changes or firewall changes. TCP sends no
application payloads; connection attempts can still cause logs/client contention.
TCP refusal is address-response evidence, not proof of a listening service.

All methods share the existing deadline, concurrency, rate, output and observation
budgets. Stored method/port/time evidence is retained while address responses are
deduplicated. Successful checks are not response counts. Partial/unavailable/
timed-out/not-started coverage never proves a host offline, service identity,
SSH authority or topology. Foreign shared-store evidence grants no local permission.

See [host-discovery policy](docs/host-discovery-policy.md) for exclusions, exact
accounting, residual blind spots and the separately authorized future live recipe.

## Installation and use

The root is a normal `plugin.yaml`/`__init__.py` Hermes directory plugin. Supported
native install/enable, operator policy, tools and commands are documented in
[the operator guide](docs/operator-guide.md). `/network status`, `/network show`,
`/network map`, and `network_query` read existing state; collection is explicit.
No external database, web app, MCP server or persistent service is required.

Live installation/activation, LAN scans, actual SSH, private seeding and gateway
restarts require separate explicit authorization. No new methods are automatically
enabled after installation. No live validation has been performed by this harness.

## Validation

```sh
python3 scripts/verify.py
```

The canonical verifier is packet-denied and includes product safety regressions,
native registration/tool/slash/CLI dispatch, the cumulative three-alias issue #6
scenario, persistence and fresh-process restart. Missing Hermes is a failure;
missing or stale candidate-bound native admission is also a failure, never a skip.
Prepare the separate online isolated setup first, as described in the operator guide.
Local/runtime CAUTION admission still requires ordinary exact-byte consent.

All feature/main/PR CI events use one GitHub-hosted disposable Docker path:
ordinary public image provisioning, one online non-root native install AND enable,
then full canonical tests and a cold selected-generation consumer with network:none,
cap-drop ALL/no-new-privileges and read-only source. The candidate-owned volume is
destroyed after the run, never shared with another candidate. Hosted admission permits
CAUTION only after full native scanning; DANGEROUS always refuses. No credentials,
host-home mounts, local Docker, force-enabled live homes or secondary offline install.
Explicit bash pipefail preserves container failures through logged pipelines.
Canonical imports bind to the pinned core before temporary scanner fixtures run;
missing canonical success proof refuses the cold consumer before execution.
See [disposable validation](docs/disposable-validation.md) and the
[acceptance checklist](docs/acceptance-matrix.md). The old retention/measurement
harness is superseded, preserved with its unchanged validators and historical failures.

## Project contracts

- [Project specification](docs/project-specification.md)
- [Implementation addendum](docs/implementation-addendum.md) — controls conflicts
- [Delivery plan](docs/delivery-plan.md)
- [Security boundaries](SECURITY.md)
- [Contributor instructions](CONTRIBUTING.md)

V1 includes Atlas Core, Local Discovery and Authorized SSH Inspection. Proxmox API,
service inventory and richer integrations remain later work.

## License

Copyright (C) 2026 Network Atlas contributors. GNU General Public License,
version 3 or (at your option) any later version; no warranty. See [LICENSE](LICENSE).
SPDX-License-Identifier: GPL-3.0-or-later