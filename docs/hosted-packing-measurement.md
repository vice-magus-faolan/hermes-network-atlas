# Hosted exact-core Git packing measurement — not acceptance

This phase is a prerequisite measurement under the existing coordinator-owned
hosted continuation. It changes no production packing, cache, PM, tool/core/image
pins, source exclusions, retention limits or consumer isolation. Faolan first
obtains exact independent source/workflow review, then publishes this feature-only
candidate. The builder performs no push, dispatch, Docker execution, acquisition,
new environment or full-core fixture locally.

## Why this phase exists

Authenticated hosted run `37831615760` completed object/source-preserving packing
and strict final accounting. Its seed was 1,096,574,127 bytes against the unchanged
1,073,741,824-byte ceiling: 22,832,303 bytes over, before final metadata/headroom.
The actual Git component was 84,408,010 bytes; the remaining source, native tools,
uv cache and diagnostic components must not be trimmed speculatively. Tiny native
packing saved 373 bytes but could neither establish full-core savings nor prove
packing impossible. `docker/measurement-anchor.json` preserves every measured
component counter with the original diagnosis SHA-256
`c112dafe6354f0093a64d602326b705c6f925f32d0e7127c50d75c379e367ac1`.
Its complete compact record is independently hash-bound by the measurement code.

## Reachable, fail-closed routing

The existing push/PR workflow remains the only trigger. No feature-only dispatch
workflow, default-branch change, commit-message directive or environment skip is
used. The new `feature-phase` job runs on a feature push and checks:

- Exact checkout SHA and the one-parent successor of Atlas
  `2049396385def5af70e87bf5f67b994835b96d1a`.
- A bounded, unique-key, literal `docker/measurement-phase.json` source marker.
- SHA-256 of every explicitly allowed changed source/workflow/test/doc/anchor file.
- The entire base-to-head changed path set, not just the latest commit, against
  the measurement-only allowlist. Any production change, extra path, tracked
  drift, link, malformed marker, wrong parent or mismatched hash refuses the job.

The marker describes source; it is not independent review, consent or acceptance.
The reviewed feature push routes exclusively to `packing-measurement`. The known
failing full producer/native acceptance job cannot run in parallel on this phase.
With no committed marker, an ordinary feature successor routes to the unchanged
hosted native path. A production successor MUST remove the marker in its commit;
an uncommitted deletion is rejected, and leaving the marker on another parent
fails closed. Main pushes and PR merge artifacts retain the existing canonical
path and cannot promote a measurement into acceptance. The workflow check/report
names and artifact names explicitly distinguish measurement from native proof.
The repository-wide `network-atlas-issue-6-ci` concurrency group still serializes
both paths, with no automatic retries.

The two inherited expectation seams are the `hosted-docker` job condition in
`tests/test_hosted_docker.py` (original event/ref predicates plus validated acceptance
output), and the core-checkout loop in `tests/test_docker_offline.py` (only the
source-routing gate, which never consumes core, is excluded). Every actual core
consumer, including the new measurement job, still satisfies all original exact
core repository/ref/credential assertions. New tests require the gate's sole
candidate checkout and prohibit core acquisition there. All other assertions/IDs
and historical JSON fixtures remain. Exact before/after hashes and diff belong
in the implementation handoff, not an assertion that these changed files are identical.

## Genuine source-only native operations

Standard disposable `ubuntu-24.04` acquires only the existing pinned public core
via credential-free pinned checkout. The measurement never imports or executes
that core, installs packages, warms tools/caches, constructs native environments,
installs/enables Atlas, admits a candidate or runs consumer acceptance. It uses
host Git/Python, not Docker. Read-only contents permission, no supplied secrets,
no privileged events, current pinned actions and a 15-minute job timeout remain.

Authenticate exact public commit `5645275e50d66dca04c9565634f9b5207a38aef5`, tree
`85282aca9d246911005dba7adbdf3ca3ddd04df5`, all 16,871 source leaves/modes/links
and complete source digest
`6c136cc4cf643181091c0077b85ff1fc86615cd841425e91ae1269f951137c79`.
Each of TWO serial fixed variants uses its own exclusively created directory,
native Git archive and the production six-stage literal reconstruction algorithm:
init, add-all, tree equality, original commit hashing, literal shallow boundary,
HEAD publication and clean index/source check. No archive normalization, source
filtering, parent synthesis, alternates or opaque object/cache edits are allowed.
Full bounded archive/commit hashes are captured before owned archive disposal.

Recipes are fixed, with no search or automatic retry:

- Current: one thread, `pack.windowMemory=16m`, `repack -a -n
  --no-write-bitmap-index`.
- Tuned: the same operation and limits, adding `pack.compression=9`,
  `--window=250`, `--depth=50`.

Both run full fsck, exact commit/tree, complete batch-all-objects before/after
(including unreachable objects), native verify-pack, second fsck, duplicate-loose
prune only after verified pack, original shallow equality, clean index and full
source-manifest equality. Full raw bounded object lists, hashes/counts and native
argv/exit/output-hash/duration rows are retained. The native object-set digest
must agree across variants. No `gc`, expiration, destructive repack or missing
source/object tolerance is introduced. Each full-core result must additionally
match the authenticated Run95 complete 17,895-object digest; a mismatch stops
before another variant or projection rather than masking platform representation
drift. No
object drift is accepted. Active prune observation alone uses the
existing narrow race tolerance; every final inventory is strictly complete.

Native packing uses the unchanged shared 120-second deadline, 60-second child
cap, 4 MiB raw-output cap, 2 GiB transient Git-object cap, one thread/16 MiB window,
100,000-entry/10-second accounting bounds, 40,000-object parser cap and owned
process-group reaping. Reconstruction children are separately bounded to 60
seconds; archive expansion is bounded to 256 MiB/100,000 members. An additional
2 GiB address-space ceiling applies to the measurement process and children.
An empty private Git HOME avoids operator/global config. Existing 1 GiB/100,000
retained bounds are not increased: completed measured Git must satisfy them.
As elsewhere, polled byte/peak observations are cooperative lower bounds, not a
filesystem quota or guaranteed storage fit. The Git peak and complete prepared
storage are reported separately, without inventing an unsampled true disk peak.

The first native refusal stops the sequence. Started/failed command audit rows
are flushed incrementally under a separate 1 MiB budget for each serial variant.
Per-variant reports retain failure and actual scoped cleanup even when packing
fails. Only exclusively created direct variant directories are disposed after
owner/path readback and absence verification. Public checkout and compact evidence
are never removed. A failed export/cleanup remains explicit; original failure
wins. On reached source/setup failures, bounded outcome/export still runs, and
artifact upload uses `always()`/missing-file error. No evidence is fabricated when
checkout, process termination or an early guard prevents a report.

## Interpretation and remaining gates

The VM's Git executable hash/build output, linked libraries, Git/zlib package
versions, Python/zlib versions, platform and kernel are recorded. This is NOT the
pinned producer runtime. Source/object equivalence does not establish Git/zlib
runtime equivalence; comparative source-only results remain a projection.

Projection uses actual full-core tuned Git bytes plus the immutable Run95 non-Git
component sum and an explicit 8 MiB metadata/headroom reserve. That reserve covers
the existing maximum 512 KiB final inventory, bounded retention diagnostics and
additional small metadata/slack; it is not a guarantee against arbitrary runtime
variation or future dependency growth. Reports give `insufficient`,
`sufficient-for-projected-prerequisite`, or `unknown` after a failed/unmeasured
variant. Neither a positive delta nor a sufficient projection proves current
whole-seed fit. A later separately reviewed minimal production repair must
establish actual retained fit in genuine acceptance on the producer runtime.

Every measurement outcome/projection has `native_acceptance=false`,
`full_canonical=false`, `final_approval=false`. Exit zero means only both fixed
measurements completed and their projection was recorded; even an insufficient
projection can be a successfully executed measurement. It is never Verify/native
acceptance. Faolan decides the next supported production remedy or a genuinely
new-scope retention architecture decision based on the hosted evidence. Native
fresh union/selection, install/enable, full canonical, cold/restart, complete
lifecycle cleanup, final same-card Gilfoyle approval and PR/human handoff remain
pending. Protected main and the live runtime remain unchanged.

## Local regression evidence

Mandatory `tests/test_docker_measurement.py::MeasurementTests` uses packet denial
and tiny genuine Git fixtures only. It covers predecessor feature-routing RED,
mutually exclusive workflow paths, main/PR/ordinary feature controls, real exact
marker/parent/hash/path validation and mixed/dirty/malformed/link refusal, pre-effect
local-hosted refusal, two genuine serial native variants with all source/object/
shallow checks and owned disposal, unreachable-object preservation/source drift,
failure/audit/cleanup precedence, nonacceptance projections/reserve and inherited
resource/evidence boundaries. Normal AND explicit `-O` executions are required.
These tests do not acquire or reconstruct the full core locally. Full canonical
and native-admission prerequisites remain mandatory and honestly absent locally.
