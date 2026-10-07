# Hosted-first Docker continuation

## Authority and current stop

Current source-only repair stops at `BOOTSTRAP_CONTRACT_AUTHORITY_REQUIRED`.
The complete [bootstrap permission audit](bootstrap-permission-contract.md)
found a package-maintainer ownership requirement incompatible with the unchanged
capability-dropped bootstrap. Controller/setup/direct apt entrypoints refuse
before effects; no CLI/environment override exists. Historical attempts and
their consumed approvals remain retained, not replayable. No new branch update,
hosted attempt, capability grant or changed provisioning architecture is enabled.
The staged construction below describes intended behavior, not a working recipe
or current permission. Independent exact-source/workflow review of the repair
is separate from a future authority decision and final feature acceptance.

This is the staged hosted-first successor, not approval or a fit claim. The
external operator-approved continuation supersedes the former requirement to
prove guaranteed aggregate setup fit and obtain new local native admission
before the FIRST hosted trigger. That exception does not enable local Docker,
download/install/admission, force, daemon/storage/profile changes or publication.
The builder stops at a committed exact-code/workflow independent-review handoff.
Only the delivery owner may separately authorize and perform one non-force
feature-branch update and one initial hosted attempt. No retries are authorized.
Missing current-artifact native acceptance remains FAILED, not skipped or green.

A hosted bootstrap failed before public setup began because Docker's default
`local` log compression cannot be combined with `max-file=1`. The repair sets
`compress=false` explicitly for both bootstrap and acceptance, retaining exactly
`max-size=4m` and `max-file=1` and matching strict inspected-config predicates.
Normal/optimized packet-denied regressions cover production argv, missing/true/
extra options, increased size/file limits and retained stopped-state errors when
log export fails. These tests are not proof that a successor hosted run started
or completed. The failed attempt and its consumed trigger remain immutable; a
new attempt requires separately recorded authority, fresh exact-source/workflow
and one-use invocation/evidence-control review. Code repair alone is not retry
permission or final acceptance, and never enables local Docker or native setup.

The old schema-2 metadata-plan build/acquire/setup path remains permanently
execution-disabled. Its `prewarm` executable dispatcher now refuses before PM
import/call, including optimized Python. No CLI/plan/environment rearm enables it.
This continuation uses a distinct reviewed hosted-only executable and public
setup recipe. Helper-only board rearm approval is not code/workflow approval.

## One supported invocation

The `hosted-docker` job in `.github/workflows/verify.yml` selects the FIRST push
checkout of `feat/6-host-discovery` on a standard `ubuntu-24.04` x64 GitHub-hosted
VM, 60-minute job deadline, no matrix/dispatch/retry/cache/self-hosted/slim runner.
Its checked-out full SHA/tree are recorded. Checkout and upload actions are
commit-pinned, contents permission is read-only and checkout does not persist
credentials. No repository secrets, PATs, deployment credentials, tunnels or
runtime policy/config are supplied. A rerun (`GITHUB_RUN_ATTEMPT != 1`) refuses.
Main/PR regression jobs are distinct and do not consume the first-attempt lane.

Step-scope `runner.temp` creates scratch and persists its literal path via
`GITHUB_ENV`; it is not referenced in invalid workflow/job-level expression
contexts. Actual hosted VM permissions and isolation are the trust boundary.
GITHUB/RUNNER environment strings and `/.dockerenv` are diagnostic guardrails,
NOT proof or sandboxing against Docker-capable/same-UID code. Never forge these
on the server to test the hosted route. The Docker socket is host-controller
only and never enters either container; the controller remains Docker-capable.

The host entrypoint checks diagnostics before resource/daemon effects and
requires a clean committed candidate, exact public Hermes source, one literal
scratch namespace, exclusive lane lease and no preexisting owned resources.
It refuses unsupported/unknown Docker storage backends. It does not relocate
DockerRootDir/containerd, prune global objects, replace storage, create privileged
helpers, hide residue or delete retained fixtures to gain capacity.

## Public prerequisite phase

The controller transfers only these public fixed inputs into a read-only
`/opt/inputs` bind: exact Hermes archive/commit object; dependency and Docker
recipe; acquisition support; legacy setup utility functions; hosted setup and
hosted diagnostic/offline guard modules. Candidate code/tests, live data, profile
homes/config, host Git metadata, credentials and Docker configuration are absent.
The public input hashes bind the owned base identity. Source reconstruction
checks the unchanged exact Hermes commit/tree before native PM imports.

A UID0 bootstrap container is private on the ephemeral VM. It has bridge egress
ONLY for public prerequisites, no host PID/IPC/UTS namespace, host devices, daemon
socket, privileges, published ports or ambient secret environment. Capability
drop/no-new-privileges, finite CPU/memory/PID/deadline/log bounds remain. Root is
needed for the private stopped-rootfs apt/tool setup, not candidate execution.
Apt uses the fixed Debian snapshot and the packaged Debian archive keyring;
its acquisition UID stays root within this capability-dropped private container
(no `_apt` UID switch requiring SETUID/SETGID grants). This is not host privilege
or a native candidate security-policy override.
Root acquisition does not fix a foreign-owned existing apt partial directory
or make dpkg/SSH group-ownership operations compatible with CapDrop ALL. That
complete contract is now blocked, not patched by a speculative cache chmod.
Signatures/index-package hashes stay enabled. Actual index/package hashes,
installed dpkg identities and command output are retained, not fabricated plan
projections. Old metadata-only expansion declarations are NOT presented as fit.

Verifier resolution is binary-only public PyPI dry-run. Its genuine pip report
is cross-checked against public package-index wheel URL/hash/size/type records;
bounded exact-length/hash downloads precede native PM's offline verifier build.
There are no guessed transitive versions/URLs/hashes or source-build fallback.
Native PM performs its ordinary literal-lock Python/uv tool installation and
real member-union resolution/prewarm. Actual tool-cache bytes are hash-checked
against the unchanged public lock. The real union lock and distribution inventory
are retained. Native PM/resolver verification is not replaced by mocked receipts
or hand-written facts/selections. Only PUBLIC core/tools/cache/verifier inputs
survive; setup home/member generations/selectors are not reused as admission.

The committed base is a genuine stopped, inspected rootfs, UID1000, not a
placeholder or image smoke result. Exact daemon/container/image/labels/platform,
upstream immutable image/rootfs layer lineage and stopped successful non-OOM
state are checked. Hosted invocation environment values are cleared on commit.
Actual public seed byte/member diagnostics and image/rootfs facts are recorded.

## Native acceptance phase

Real smoke/fail/interrupt/refusal canaries precede exactly one native acceptance.
Canaries are cleanup evidence, NOT admission. Each acceptance container has
UID1000, read-only base/candidate, all capabilities dropped, no-new-privileges,
private PID/IPC/UTS, finite work/tmp tmpfs, no devices/socket/ports/secrets and
Docker `network=none`. Native acceptance installs inherited syscall packet denial
BEFORE fresh fixture PM/install/enable resolution and keeps it through all tests.
The readonly candidate snapshot root has public search permission. The narrow
owned export directory grants container writing only; Docker's bounded archive
API reads exact owned exports when the hosted runner UID differs, without sudo,
host chown or permission changes to unrelated directories.

Fresh isolated HOME/HERMES_HOME/TMPDIR, complete public core and complete clean
candidate snapshots precede native scan/install/enable. Explicit hosted-only
`hosted-ci-caution` diagnostics map the real read-only candidate bind to
`/candidate`; the source SHA stays exact. SAFE uses no force. CAUTION alone may
use the existing reviewed supported native force policy. DANGEROUS always
refuses. Native scan/catalog/kill-list/source trust/default exclusions stay intact.
No old receipt, subset scan, fixture-selection reuse, blanket yes, disabled
scanner or signature-controller substitute is allowed. Only the ordinary narrow
PM dependency prompt gets its supported one-time answer. Real native install,
installed tree, enable, selected generation, runtime facts and receipts are
read back before the actual canonical verifier. Cold consumer revalidates native
selection with caches/socket attempt denial; it cannot invoke resolver/network.

The canonical result enumerates every actual unittest ID/status, both reported
and discovered counts, failures/errors/skips and actual exit. The exact candidate
native installed-tree identity and cold generation proof remain mandatory.
Missing/stale admission, resource exhaustion, OOM, deadline, network/cache miss,
scan refusal, output/export failure or teardown failure is FAILED. No fallback,
retry, stale green receipt or claim that mocked seams executed native setup.

## Resource truth, cleanup and retained evidence

The ephemeral VM is the aggregate lifecycle boundary, NOT a demonstrated hard
per-job filesystem quota. Opaque apt/native PM/uv writes are not precisely bounded
by sampled free-space diagnostics or final image Size. Fresh Docker/containerd
roots, actual mount/filesystem/free-inode/free-byte values, sampled setup storage
and before/after diagnostics are retained. Sampled values may miss instantaneous
peaks. Fit and real peak remain UNKNOWN until observed; even a successful run does
not turn sampling into a hard aggregate quota. Exhaustion is a failed attempt.

Owned container teardown uses exact immutable ID/labels/daemon readback and
removes no unrelated containers/images/volumes. Passing, failing and interrupted
paths retain original failure and separate export/cleanup failure. The verified
owned base is removed after all consumers stop; label/image drift refuses blind
removal and preserves evidence. Digest-pulled public upstream is explicitly left
for VM disposal, not silently globally pruned. If the hosted service kills the
job at its deadline before `finally` finishes, VM disposal is the last boundary;
missing cleanup proof is not success.

Primary stopped-state failure is interpreted before success-only copies. The
exporter revalidates immutable ownership after stop and retains state/logs,
then independently records all four inventory/provenance members as present,
missing (exact absent-file response only), or export error. Missing files on a
failed setup cannot mask its exit/OOM/start error or claim success; on success
every member is mandatory. Secondary cleanup/export/final diagnostic errors
cannot replace the primary exception. See bootstrap-permission-contract.md.

The always-run export includes only bounded summary, owned bootstrap provenance,
registry and compact native export/metadata directories. No contexts, tools,
opaque uv cache, profiles or fixture homes are uploaded. A maximum 128 MiB/256
regular-member tar contains per-member SHA256 and size manifest; symlinks,
missing proof, changed members and overflow refuse. Pinned artifact upload keeps
that exact file seven days and fails when absent. Logs/findings/state snapshots
are actual public/synthetic job evidence, never live operator data. The delivery
owner retrieves/archives/verifies the exact artifact's source identity, hashes,
real native scan/install/enable/canonical/cold and cleanup evidence independently
before any hosted/publication gate is called green.

## Local implementation-only verification

`python3 scripts/check_docker.py` and `python3 -O scripts/check_docker.py` run
network-denied fixtures/mocks only. Regression coverage includes the ACTUAL
legacy and hosted executable dispatchers, pre-PM refusal in normal/optimized
children, exact hosted scope/readback, no local effects, public index/tool hash
checks, bounded evidence, no retry and failure/interruption cleanup. Mocked
lifecycle results are not hosted execution. Complete workflow compilation uses
recorded pinned/checksummed actionlint separately. Canonical local checks still
include real scanner and admission requirements; absent new admission is an
honest failure. No build/install/download is needed or authorized to test seams.
