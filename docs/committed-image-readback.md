# Committed-image failure readback

SUPERSEDED historical controller; see [disposable-validation.md](disposable-validation.md).

## Observed failure and limits

GitHub push run `37700249768`, attempt 1, job `113061710647`, exercised exact
candidate `522b5116d0c1dfa50297129f376da2fe5f7ed6f0`. Public provisioning exited 0,
without OOM: authenticated APT proof had 27 archives, two indexes and 124 installed
identities; named native Python/uv installation, verifier preparation and union
warming completed. All eleven shared phase commands exited 0 and all five success
proof members were exported. This is actual prerequisite success, not candidate
admission, enable, canonical, cold or complete cleanup acceptance.

Docker commit returned
`sha256:0e4ee6499d306734273a7ee7716e9db6e455129e4f39e561b657780197522502`.
The final combined labels/config/nonroot/rootfs predicate refused it. Its image
inspect output was not retained, so the actual differing field remains UNKNOWN.
The owned bootstrap container was removed; committed-image cleanup refused absent
verified identity. Full owned cleanup was not proven. Historical logs/reviews and
verdicts remain immutable.

## Historical diagnostic-only successor, not a guessed compatibility fix

That successor deliberately preserved `CMD []`, `ENTRYPOINT []`, exact owner/core/
plan/daemon labels, UID/GID 1000:1000, `/work`, volume/port refusal and exact pulled
upstream layer ancestry. It does not admit a bootstrap script as a base command,
accept arbitrary labels, change public pins or bypass image validation. Both the
hosted path and the permanently disabled legacy plan builder share the readback
boundary. A returned digest must also match the inspected `Id`; layer digests must
be well-formed, bounded and extend the exact observed upstream with one new layer.

This was a meaningful diagnostics-only correction for independent pre-CI review
and a targeted hosted attempt under standing authority. It was NOT a demonstrated
repair of the run's unknown config mismatch or a promise that CI will pass.

Primary source exposed a plausible compatibility problem:
[Moby v28.0.4 `daemon/commit.go`](https://github.com/moby/moby/blob/v28.0.4/daemon/commit.go)
`CreateImageFromContainer` applies `BuildFromConfig` changes, then calls `merge`
against `container.Config`. `merge` restores the container `Cmd` when both changed
`Entrypoint` and `Cmd` have length zero. The captured stopped container's command
was `python3 /opt/inputs/hosted_setup.py`. Replaying precisely this source rule
against the production commit argv makes the unchanged guard refuse `Config.Cmd`.
At that point it was a SOURCE-DERIVED hypothesis and a small executable regression, not actual
committed-image evidence or proof of the hosted daemon's version/behavior.
[The Docker CLI contract](https://docs.docker.com/reference/cli/docker/container/commit/)
confirms changes apply Dockerfile instructions and mounted inputs are not committed.
Do not turn this source rule into a fabricated historical image inspect. Any
compatibility change had to follow the next actual field readback and exact review.

## Actual successor failure and narrow default-command correction

Run `37704198046`, attempt 1, job `113074558156`, exercised diagnostic candidate
`3ac37933e53c52fee23d1fdbaf7d02b3d353a79c`. Public setup again exited 0/non-OOM,
with all five setup proofs. Actual parsed committed-image inspect is 3773 bytes,
SHA256 `b5249049e14b59f1a13a58d74ea79eca3d7a8e1bc7923c33dfa3a4bc1695d33a`;
actual stopped data is 7864 bytes, SHA256
`25a313646c2905e086f120bdb589b7c88881d4901b635aeced0323292cd34049`.
Both are retained unchanged in `tests/fixtures/run37704198046-*.json`, from compact
verified public CI evidence, not live Atlas/operator homes. The image reports Docker
28.0.4 and the EXACT stopped setup argv as `Config.Cmd`. All other safety fields
pass; image-validation identifies only `Config.Cmd`. These are observed facts for
this run, not backfilled image proof for the earlier unexported failure.

The correction uses one shared immutable `BASE_COMMAND = ("/usr/bin/true",)` in
`docker/acquisition_support.py`. Both production `commit_command` callers emit
exec-form `CMD ["/usr/bin/true"]` and `ENTRYPOINT []`. A nonempty Cmd avoids the
Moby v28.0.4 merge fallback without admitting inherited setup, a shell, PATH lookup
or arbitrary argv. GNU Coreutils documents
[true as doing nothing successfully](https://www.gnu.org/software/coreutils/manual/html_node/true-invocation.html).
Actual retained APT inventory reports `coreutils:amd64` version `9.1-1` installed
both before and after provisioning. That package identity is not a file/execution
proof: both real setup entrypoints now require `check_default_command()` before
success inventory. It checks the existing absolute file with lstat: regular,
UID0-owned, executable by other users, no group/other writes or setuid/setgid bits;
then the existing bounded/shared audited runner must observe exit0 and no output.
Missing/unusable/failed/noisy files refuse; no acquisition/replacement/fallback is
added. Actual pinned-image availability remains for the corrected hosted run.
The extra no-op row uses the unchanged shared command/count/byte/resource budget.

Consumers agree on the precise default:

- `scripts/docker_builder.py::image_validation` requires exact Cmd list and exports
  that expected value; `verify_final_image`/`read_final_image` bind receipt identity.
- Both `scripts/hosted_docker.py::build` and disabled legacy `build_owned` share the
  same commit/readback. The legacy execution gate stays disabled.
- `scripts/docker_acceptance.py::validate_base` requires the same default on every
  receipt recovery/reuse before creating an acceptance container.
- `scripts/hosted_docker.py::cleanup_image` requires it before verified-image
  consumer checks/removal. `finish_image` still refuses absent receipt and preserves
  the primary failure. This grants no deletion authority for historical residue.
- `scripts/docker_contract.py::create_command`/`validate_container` are unchanged:
  all six modes explicitly use `python3 /candidate/scripts/docker_inside.py MODE`,
  never the base default. Cold/restart runs remain inside that controlled container.

Exact labels, UID1000:1000, /work, empty entrypoint, ports/volumes absence, returned
digest and observed upstream-plus-one-layer validation are unchanged. The executed
merge regression is expressly a source-rule MODEL, not an actual corrected Docker
commit. Fresh exact independent pre-CI review and actual hosted acceptance follow;
native/install/enable/full canonical/cold/complete cleanup and same-card Gilfoyle
approval are still pending. No local Docker, native setup or publication is inferred.

## Narrow inherited test-body updates

All inherited canonical/required/focused IDs remain. Three inherited test files
need coherent contract updates; no safety assertion is removed:

- `tests/test_docker_builder.py`: stopped-commit assertion changes `CMD []` to the
  precise inert command; base-drift and synthetic-daemon successful image fixtures
  set only Cmd to that command. All identity/containment/state/cleanup checks remain.
- `tests/test_docker_image_readback.py`: successful `image_data` fixture sets only
  Cmd to the inert command; the existing empty-merge test checks current production
  argv but explicitly restores empty Cmd before modeling the historical fallback,
  retaining bootstrap-command refusal; the expected diagnostic changes from
  `"empty"` to the exact inert list. All journal/bounds/error/cleanup assertions remain.
- `tests/test_docker_bootstrap_repair.py`: hosted success fixture changes only Cmd
  to the exact inert list; process-proof, missing-proof, export/receipt and owned
  container cleanup assertions remain untouched.

The new mandatory default-command tests add stricter empty/missing/wrong/shell/
bootstrap/default-argument refusals to initial, recovery and cleanup consumers,
actual historical fixture replay, modeled proposed merge, guarded availability
and a real local no-op audit. They do not waive hosted execution.

## Evidence and failure precedence

After commit returns, before inspect/validation, `image-commit.json` journals the
returned image, immutable bootstrap labels, upstream identity and evidence path.
The existing registry `bootstrap.json` journals the same awaiting-readback state.
The returned identity is also retained in the phase outcome if later writes fail.
No unverified image gets a `base.json` receipt or deletion authority.

`committed-image.json` retains the ACTUAL parsed Docker inspect array before any
shape/config predicate. It is serialized normally; it is not raw CLI byte-for-byte
output or an inferred config. `image-validation.json` records stage, returned image,
daemon, serialized readback length/SHA256, expected and observed safety fields,
precise mismatch names, validation result and bounded failure text. Inspect-command,
shape and over-bound failures retain the returned-image journal and failure stage;
a missing readback is not reported as an observed empty config. Both original
success and failure exports include these fixed flat files through the unchanged
compact evidence selection/manifest/hash path.

Readback has a stricter 512 KiB serialized ceiling inside the existing bounded CLI
reader. Files share the unchanged 32 MiB/64-member bootstrap directory and 1 MiB/
eight-member registry budgets; no aggregate/export quota is increased. Diagnostic
writes are attempted independently. On actual inspect/validation failure their
errors become bounded notes on that original exception, never replace it. On valid
identity but failed diagnostic persistence the phase fails rather than issuing a
success receipt. Bootstrap proof/log export and owned container cleanup retain
existing primary precedence. Image cleanup still requires verified immutable
readback and no consumers; residue is never blindly removed or broadly pruned.
Cooperative limits are not OS quotas or peak-fit guarantees.

## Mandatory offline evidence

Seven inherited `tests/test_docker_image_readback.py::ImageReadbackTests` IDs and
five new `tests/test_docker_default_command.py::DefaultCommandTests` IDs are required by
`scripts/verify.py`, in normal and optimized Python. They exercise the actual
production validator/readback, journal-before-inspect ordering, all config/identity/
rootfs refusals, malformed/oversized/failed inspection, export errors, compact pack
readback, cleanup refusal and full hosted-controller failure/proof retention seams.
A source-rule model retains historical empty-command refusal and predicts the
precise proposed inert command without claiming actual corrected hosted commit.
External daemon/provisioning seams are synthetic; no Docker, packages, network,
native admission or production homes are exercised locally. All inherited tests
remain mandatory; hosted-only native/full/cold/cleanup evidence and final same-card
Gilfoyle approval still precede feature/PR completion.
