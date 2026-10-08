# Fixed snapshot Git trust and early failure evidence

SUPERSEDED retained-harness layout; see [disposable-validation.md](disposable-validation.md).

## Observed hosted failure versus adjacent source defect

Actual hosted run `37712086262`, attempt 1, job `113100062402`, at
`3340b5549da631bb561e964d6f58a24293cf64f1` passed the committed-image and
initial acceptance-container identity/isolation guards. All eleven labels and
the immutable returned container ID were verified from actual inspect. The
smoke container started, then exited 1, non-OOM. Its actual log says Git refused
`/candidate` as dubious ownership, exit 128, while constructing `started.json`
before the entrypoint's exception boundary. Missing exported evidence was
secondary. Bootstrap/smoke container and owned base removal/absence readbacks
succeeded for reached resources; native/canonical/cold/all-mode acceptance did
not execute. Earlier unexported container mismatches remain unknown.

The source's hosted incoming leaf was mode 0733: a different UID could create
files, but could not list the directory. `BoundedDirectory` enumerates existing
members before every bounded write. This is a concrete POSIX layout defect for
runner UID 1001 versus container UID 1000, not an observed historical
PermissionError. The historical run stopped earlier at Git.

## Exact public snapshot, not arbitrary Git trust

The host controller reconstructs only the complete committed public archive,
verifies its tree, restores the exact public commit object/shallow boundary and
checks clean status. It then writes a deterministic inert `.git/config` and
`.git/atlas-snapshot.json` containing only that verified commit/tree. The latter
is mode 0444, outside the committed tree. It is controller metadata, not a
candidate-provided trust path or a native admission receipt. Host checkout Git
metadata/config/homes are never mounted. The whole snapshot is read-only at
one fixed `/candidate` path; external container identity/isolation validation
still gates start and cleanup.

`scripts/docker_snapshot.py` grants only a process-local `safe.directory` entry
for this exact literal path. No wildcard, parent-wide exception, host/global
config write, ownership change or mutable candidate mount is introduced.
The fixed root, ordinary `.git` directory, bounded regular controller record
and exact inert config are required before supplying Git settings. Actual
Git commit/tree/root must match. Startup validates all committed blob bytes and
executable modes, not just index stat caches, and rejects dirty/untracked files,
links/special files, external object alternates and escaping tree paths. Git
storage/tree traversal is bounded to 100000 entries/256 MiB; Git subprocesses
use the existing owned-child timeout/output/reaping reader (30 seconds/4 MiB).
These finite checks are not a new OS quota or a peak-fit claim.

Git subprocess environments do not inherit HOME, Git redirection/config,
credentials, proxies or Python paths. System/global Git config is disabled and
hooks resolve to the inert `/dev/null` path. The fixture environment revalidates
the immutable snapshot, then forwards only these exact Git settings while
retaining its own isolated HOME/HERMES_HOME. Thus native scan/origin/PM/verification
children can inspect `/candidate`; owned contained copies under `/work` need no
extra trust. Other repositories retain Git ownership refusal. The exception is
not authorization to install, enable, scan a LAN or execute candidate Git hooks.

This remains a trusted-controller/read-only-bind contract, not a sandbox against
a compromised same-UID host process or arbitrary Docker-capable caller. The
controller's independently verified snapshot and external exact artifact/image/
container guards supply provenance; a JSON string alone cannot prove isolation.

## Private cross-UID evidence layout

Only hosted export prepares the one newly created empty `incoming` leaf with
sticky mode 01777. Its literal controller root, `evidence` parent and exact attempt
remain owned private mode 0700; symlink/escaped roots, wrong ownership/modes and
nonempty/reused leaves refuse before container creation. Docker binds only the
leaf at `/export`, not any parent. A different container UID can therefore list
and perform the existing bounded writer's create/replace operations. Sticky mode
prevents another owner replacing its files. Every published file stays mode
0600 and all existing per-file/count/aggregate/transient/archive bounds remain.

This is a narrowly scoped ephemeral-runner leaf permission, not host-wide public
evidence, an ACL/UID grant, host chown, privilege escalation or a production
permission change. Private ancestors prevent unrelated host UIDs traversing to
the leaf. Same-UID controller code and privileged Docker remain trusted. The
controller continues using the bounded Docker archive API after actual owned
container readback; it does not assume it can read UID1000 mode0600 files directly.
Local export remains private 0700. Isolation argv/mount identities, network-none,
UID1000, cap-drop ALL, read-only source/rootfs, NNP, budgets and cleanup guards
are unchanged.

## Early failure and verification limits

Argument/identity/hosted-policy/foreground/started-write failures now occur
inside the entrypoint's exception boundary. Bounded `error.json` contains actual
exception type/message and `native_acceptance=false`, never unproven commit/tree
or fabricated started/result/admission receipts. Actual stderr/traceback/exit
remain in the unchanged bounded container log. Error/native-export failures add
secondary notes and cannot replace the original exception. External exact
container cleanup does not depend on a candidate success receipt.

Seven mandatory `tests/test_docker_startup.py::StartupTests` IDs cover actual tiny
Git reconstruction and Git's own different-owner test seam, exact path/metadata/
config/commit/tree/blob/symlink/escape/drift refusals, sanitized native-child Git
calls and other-repository refusal, actual bounded evidence writes with POSIX
cross-UID mode analysis, early real Git exit128 and diagnostic-error precedence,
and all six unchanged isolation argv. They run normal and optimized, socket-denied,
without Docker, chown/UID switching, downloads or native admission. The different
Git owner seam is not a real container UID switch; mode analysis plus actual
same-UID bounded writes is not actual hosted cross-UID acceptance.

All inherited test bodies/fixtures/mandatory IDs remain. Full native scan retains
default exclusions and exact tracked source scope. Whole-workflow actionlint
retains actual argv/version/hash/exit evidence. Local absent-admission failures
remain honest. This successor is PRE_CI_SOURCE_REVIEW only; actual corrected
hosted install/enable, selected-generation, full canonical, cold/restart,
all-mode cleanup and final independent same-card Gilfoyle acceptance remain
publisher-owned gates before feature/PR handoff. No local Docker or heavyweight
fixtures are authorized.
