# Contributing

This project is licensed GPL-3.0-or-later. Read [README.md](README.md),
[SECURITY.md](SECURITY.md), and the relevant feature guide before changing behavior.

Run `python3 -m pytest -q` as a non-root user with official Hermes v0.21.7 or v0.22.2,
its installed `hermes` CLI on PATH, and requirements-test.txt. The native installer
tests need network for dependency resolution; Atlas application fixtures refuse
Python network connections. Docker adds network isolation for application-test
children. Add behavioral tests for changed behavior; regression tests should prove
the prior failure where practical. Tests never use live network/device/config/
credential data. If Hermes is not importable, `NETWORK_ATLAS_HERMES_ROOT` can point
to its stock checkout. Never modify a production Hermes environment for tests.

## Reproduce verification with Docker

From the repository root, with Docker available:

```sh
docker build --file docker/validation.Dockerfile --tag hermes-network-atlas-tests:local .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges hermes-network-atlas-tests:local
```

The build runs tests/test_compatibility.py online. The container runs everything
else without network. The default is Hermes v0.22.2; use
`--build-arg HERMES_REF=v0.21.7` to test the oldest supported release in the CI matrix.

## Style and changes

Install the pinned tools with `python3 -m pip install -r requirements-test.txt`,
then run `ruff check .` from the repository root. The same check runs in the
ordinary Docker/CI verification path. Ruff checks E/F errors, Bugbear warnings
and production assertions, with a 120-column line limit to accommodate SQL and
structured fixtures. Intentional assertions are allowed only under `tests/`.
This is a lint check, not a required formatter pass.

Prefer simple standard-library Python, small typed boundaries, and focused
Conventional Commits. Explain non-obvious intent and failure behavior. Avoid
abstractions for hypothetical integrations. Soft-warn on cyclomatic complexity
near 10; justify or refactor above 15. Keep documentation aligned with behavior.

Do not publish live atlas/config/exports, credentials, host-specific policy,
logs, or scratch state. Keep ignores surgical; future docs, fixtures, and
schemas must stay visible. Fixtures and example files are explicitly synthetic.
Do not add persistent services, arbitrary command/range interfaces, privilege
escalation, unnecessary dependencies, or fabricated topology.
