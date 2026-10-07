# Committed-image failure readback

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

## Diagnostic-only successor, not a guessed compatibility fix

The successor deliberately preserves `CMD []`, `ENTRYPOINT []`, exact owner/core/
plan/daemon labels, UID/GID 1000:1000, `/work`, volume/port refusal and exact pulled
upstream layer ancestry. It does not admit a bootstrap script as a base command,
accept arbitrary labels, change public pins or bypass image validation. Both the
hosted path and the permanently disabled legacy plan builder share the readback
boundary. A returned digest must also match the inspected `Id`; layer digests must
be well-formed, bounded and extend the exact observed upstream with one new layer.

This is a meaningful diagnostics-only correction for independent pre-CI review
and a targeted hosted attempt under standing authority. It is NOT a demonstrated
repair of the run's unknown config mismatch or a promise that CI will pass.

Primary source exposes a plausible compatibility problem:
[Moby v28.0.4 `daemon/commit.go`](https://github.com/moby/moby/blob/v28.0.4/daemon/commit.go)
`CreateImageFromContainer` applies `BuildFromConfig` changes, then calls `merge`
against `container.Config`. `merge` restores the container `Cmd` when both changed
`Entrypoint` and `Cmd` have length zero. The captured stopped container's command
was `python3 /opt/inputs/hosted_setup.py`. Replaying precisely this source rule
against the production commit argv makes the unchanged guard refuse `Config.Cmd`.
That is a SOURCE-DERIVED hypothesis and a small executable regression, not actual
committed-image evidence or proof of the hosted daemon's version/behavior.
[The Docker CLI contract](https://docs.docker.com/reference/cli/docker/container/commit/)
confirms changes apply Dockerfile instructions and mounted inputs are not committed.
Do not turn this source rule into a fabricated historical image inspect. Any
compatibility change must follow the next actual field readback and exact review.

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

Seven `tests/test_docker_image_readback.py::ImageReadbackTests` IDs are required by
`scripts/verify.py`, in normal and optimized Python. They exercise the actual
production validator/readback, journal-before-inspect ordering, all config/identity/
rootfs refusals, malformed/oversized/failed inspection, export errors, compact pack
readback, cleanup refusal and full hosted-controller failure/proof retention seams.
A source-rule model keeps the realistic empty-command merge concern explicit.
External daemon/provisioning seams are synthetic; no Docker, packages, network,
native admission or production homes are exercised locally. All inherited tests
remain mandatory; hosted-only native/full/cold/cleanup evidence and final same-card
Gilfoyle approval still precede feature/PR completion.
