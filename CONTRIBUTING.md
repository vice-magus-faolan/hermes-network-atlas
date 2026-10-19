# Contributing

This project is licensed GPL-3.0-or-later. Read the original specification and
implementation addendum together before coding; the addendum resolves conflicts.
Keep V1 limited to phases 1–3. Prefer simple standard-library Python and small,
typed boundaries. Explain non-obvious intent and failure behavior.

Run `python3 -m pytest -q` as a non-root user with official Hermes v0.22.2,
its installed `hermes` CLI on PATH, and requirements-test.txt. The native installer
tests need network for dependency resolution; Atlas application fixtures refuse
Python network connections. Docker adds network isolation for application-test
children. Add behavioral tests when adding real plugin behavior so
that every delivered module is tested. A bootstrap green check is
not implementation acceptance. Regression tests should prove the prior failure
where practical. Tests never use live network/device/config/credential data.

## Reproduce verification with Docker

From the repository root, with Docker available, build and check native installers
online, then run the Atlas application/security checks without network, as CI does:

```sh
set -eu
docker build --file docker/validation.Dockerfile --tag hermes-network-atlas-tests:local .
name=atlas-tests-$(date +%s%N)
cleanup() {
  rc=$?; trap - EXIT; failed=0
  if docker container inspect "$name" >/dev/null 2>&1; then
    docker stop --time 10 "$name" || failed=1
  fi
  remaining=$(docker container ls -aq --filter "label=atlas.test-run=$name") || failed=1
  test -z "$remaining" || failed=1
  for kind in volume network; do
    remaining=$(docker "$kind" ls -q --filter "label=atlas.test-run=$name") || failed=1
    test -z "$remaining" || failed=1
  done
  if [ "$failed" -ne 0 ]; then
    printf 'Owned-resource cleanup failed\n' >&2
    [ "$rc" -ne 0 ] || rc=1
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
docker run --rm --name "$name" --label "atlas.test-run=$name" --network none --cap-drop ALL --security-opt no-new-privileges hermes-network-atlas-tests:local
```

The image uses Hermes's committed dependency lock through its native PM frozen
build and editable development install; it does not install every optional extra.
Both phases run as `atlas`, with source ownership allowing Git to resolve the real
release version. The required build-time `tests/test_compatibility.py` runs once:
fresh synthetic homes exercise actual native enable/empty status and rejection
of the shipped pre-#15 manifest on v0.22.2 without activating it. Build output
shows the real version, both gate outcomes and empty Atlas status. The container
then runs Validate, Doctor and every remaining pytest module with network denied;
only that already-executed installer module is excluded. Both phases must pass.
Offline installation is not supported by this verification path. This is not a
production installation or live-network test.

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
