# Authenticated native offline consumer

## Source-only prerequisite, not native acceptance

The current acceptance core is the narrowly reviewed public fork artifact from
`vice-magus-faolan/hermes-agent`:

- Commit `5645275e50d66dca04c9565634f9b5207a38aef5`.
- Tree `85282aca9d246911005dba7adbdf3ca3ddd04df5`.
- Parent `f42f579cf8bac4918ac9599bece71618afadd846` (no upstream rebase).
- Complete path/type/content/executable/symlink source digest
  `6c136cc4cf643181091c0077b85ff1fc86615cd841425e91ae1269f951137c79`.

Both independent core reviews approved PRE_CI_CORE_SOURCE_ONLY and each exercised
171 normal/optimized packet-denied tests with engine/tool realization intercepted.
The coordinator authenticated all 16871 public archive leaves against native Git
archive and reviewed source, including Git's tracked PS1 CRLF archive projection.
The authentication receipt SHA-256 is
`75c28137dd9c6212c956f3021e0259310abafb3eac833ae5464825fbef0bca1e`.
This is authenticated source, not actual cache closure or full-core acceptance.

Both CI jobs use the existing commit-pinned checkout action, this exact fork/SHA,
and `persist-credentials: false`. Current acceptance/dependency/label/tree/digest
pins agree. Historical JSON fixtures and failed-run identities remain unchanged;
they are not evidence of success under the new core. Python, uv, image, APT,
source URLs within the native locks, quarantine/cutoff and scanner pins remain
unchanged. No live runtime or source checkout is promoted or edited by this phase.

## Explicit consumer policy

`scripts/native_install.py --offline-enable` is an enable-only setup flag. Scan
or install with it fails before mode selection or filesystem effects. The marked,
contained synthetic home/source checks remain mandatory. The flag calls actual
`plugins_cmd.cmd_enable('network-atlas', offline=True)`; without it, the original
no-keyword call remains online by default. Ordinary `prepare_acceptance.py` setup
and public producer warming are unchanged and do not request this flag.

Only the two existing Docker network-none consumer enable paths (ordinary
interactive `accept` and contained `hosted-accept`) supply `--offline-enable`.
Hosted installation still uses its separate CAUTION-only admission boundary;
ordinary Docker installation/enable still require their real terminal consent.
No ambient `UV_OFFLINE` setting is inserted or trusted. The pinned native PM
sanitizers continue stripping it.

Current supported core coordinates are:

- `hermes_cli/plugins_cmd.py:639-692`: `cmd_enable`, catalog/removal check,
  ordinary activation and capability/override consent; explicit offline policy.
- `hermes_cli/plugins_cmd.py:542-555,590-603,469-503`: activation delta, expected
  config version and the same native admission transaction, now forwarding policy.
- `hermes_cli/plugins_admission.py:50-84`: actual proposed `Selection`, explicit
  sync and unchanged refusal/conflict translation, not an application-built lock.
- `pm/client.py:205-242`: strict boolean policy into direct native sync or the
  authenticated worker request; default false, no ambient-policy shortcut.
- `pm/packages.py:392-451`: fresh candidate generation, managed engine policy,
  genuine lock-and-sync, unchanged native facts/seed selection and failure cleanup.
- `pm/environment.py` and `pm/workspace.py`: the existing engine's explicit
  offline argv is used during fresh member resolution and subsequent sync;
  quarantine and fresh workspace generation remain native, not rewritten here.

Offline is a dependency resolver/sync policy, NOT an admission decision or OS
sandbox. It does not promise every build/tool/Git dependency is already cached.
Actual non-root, read-only, capability-drop ALL, no-new-privileges, network:none,
resource bounds and inherited hosted socket denial remain independent enforcement.
No online fallback, frozen-resolution request, source mutation, replacement lock,
preselected generation/facts or fabricated cache freshness is introduced.

## Executable source evidence

Nine additive mandatory `tests/test_docker_offline.py::OfflineConsumerTests` IDs
exercise production argument parsing/native signature, effect-free flag refusals,
unchanged default, both contained callers and consent boundaries, actual native
activation/Selection/worker payload and refusal propagation, real fresh member
workspace plus engine offline lock/sync argv, exact current pin/workflow agreement,
and refusal of historical base/image identities under the current pin. The uv
subprocess, worker publication, install and readback effects are intercepted;
these are not actual resolution/install/enable or native acceptance receipts.

Behavioral RED uses the literal predecessor caller/entry code: the old parser
rejects the flag and the old network-none call omits it. GREEN exercises the same
boundaries with the successor. Normal and actual Python -O are required. All
inherited canonical/required/focused IDs remain mandatory; the local lightweight
selection does not replace the full canonical verifier.

Minimal inherited test changes are explicit, not an all-byte-identical claim:

- `test_docker_pm.py`: only the exact core tree guard literal changes.
- `test_docker_core_identity.py`: only two current commit literals change;
  archive digest/complete-source/mutation/publication assertions remain.
- `docker_plan_fixture.py`: only the current core repository URL changes.
- `test_docker_container_readback.py`: two historical replay methods add scoped
  original commit/tree decorators; every original method body remains unchanged.
- `test_docker_default_command.py`: its historical replay method adds the same
  scoped original commit/tree decorators; every original body remains unchanged.

The historical fixtures themselves are byte-identical. Scoped historical replay
is NOT current-base approval: the new current-policy test explicitly requires
old successful-base labels and the old failed image to be refused. Exact per-file
and changed-body hashes/diffs accompany the implementation handoff.

## Remaining gates

A full tracked-source native default-scope scan and complete-workflow actionlint
are required before the source handoff. Their success cannot certify the hosted
runner. Missing current native admission remains a failure, never a skip or fake
canonical green. Fresh exact independent Atlas source/workflow review precedes
Faolan's meaningful non-force feature-only hosted continuation. Actual fresh
native install/enable, selected generation, full canonical/cold/restart/all-mode
cleanup, then final same-card Gilfoyle approval remain required before PR handoff.
Another concrete cache-closure gap must retain real failure evidence; offline
plumbing is not proof that all dependencies resolve. No local Docker, acquisition,
new environment/native fixture, runtime/profile/store/service/LAN effect, main
advancement, publication or retained-evidence retirement belongs to this builder.
