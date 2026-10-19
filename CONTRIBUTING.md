# Contributing

This project is licensed GPL-3.0-or-later. Read the original specification and
implementation addendum together before coding; the addendum resolves conflicts.
Keep V1 limited to phases 1–3. Prefer simple standard-library Python and small,
typed boundaries. Explain non-obvious intent and failure behavior.

Run `python3 -m pytest -q` as a non-root user with official Hermes v0.21.7 or v0.22.2,
its installed `hermes` CLI on PATH, and requirements-test.txt. The native installer
tests need network for dependency resolution; Atlas application fixtures refuse
Python network connections. Docker adds network isolation for application-test
children. Add behavioral tests when adding real plugin behavior so
that every delivered module is tested. A bootstrap green check is
not implementation acceptance. Regression tests should prove the prior failure
where practical. Tests never use live network/device/config/credential data.

## Reproduce verification with Docker

From the repository root, with Docker available:

```sh
docker build --file docker/validation.Dockerfile --tag hermes-network-atlas-tests:local .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges hermes-network-atlas-tests:local
```

The build runs tests/test_compatibility.py online. The container runs everything
else without network. The default is Hermes v0.22.2; use
`--build-arg HERMES_REF=v0.21.7` to check the supported minimum API line.

## Changes and review

Use focused Conventional Commits on the declared lane, not main. Verify branch,
full SHA, clean state, and no competing writer before edits or review. Soft-warn
on cyclomatic complexity near 10; justify or refactor above 15. A builder cannot
approve its own artifact. Request native same-card review with the exact committed
SHA, tests, changed files, and residual risk; remediation stays on that card/lane.

Do not publish live atlas/config/exports, credentials, host-specific policy,
worker logs, or scratch state. Keep ignores surgical; future docs, fixtures, and
schemas must stay visible. Fixtures and example files are explicitly synthetic.
Do not add persistent services, arbitrary command/range interfaces, privilege
escalation, unreviewed dependencies, or fabricated topology.

Kanban coordinates component acceptance separately from local target integration,
public push/release, and runtime deployment. Do not push, merge main directly,
install/enable in a live Hermes home, scan real networks, inspect real SSH hosts,
change profiles, restart gateways, force-clean worktrees, or delete branches
without the corresponding explicit effect authorization.
