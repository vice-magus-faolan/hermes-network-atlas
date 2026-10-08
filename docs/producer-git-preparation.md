# Producer-only immutable Misaki Git preparation

## Observed failure and limits

Hosted run `37806326519`, exact Atlas `5397c8bcea475bdd3512400f7c9992e02dc5f212`,
completed genuine native installation. The explicit offline enable reached uv
and refused the Misaki Git commit fetch with `GIT_ALLOW_PROTOCOL=file` under
network:none. This is distinct from the older KittenTTS HTTP revalidation error.
The complete failed enable log is 13082 bytes, SHA-256
`aa26e54ce6c64e78f7e02d806b5070321ce0cbf36ea9cde8d24c6ee19e0ee8e4`.

Online warming exited zero and its bounded log explicitly used GitHub's static
metadata fast path for Misaki. The truncated producer log does not prove that a
checkout never happened; the historical precise key/entry deficiency remains
unknown. Bucket totals and online metadata success are not offline Git closure.
The coordinator's diagnosis is bound by SHA-256
`52f005c6aa53450e8b53780dafe284509360ab6a8ea6df5b4de6fddd44de133b`.

## Narrow meaningful preparation

After existing pinned tools and verifier setup, before native online union warm,
`docker/hosted_setup.py` runs its `prepare-git` mode using the existing verifier
interpreter. Both dispatcher and helper refuse direct local execution before PM
imports/filesystem/acquisition. The reviewed complete core, tools, URLs, cutoff,
consumer offline policy and admission/selection behavior remain unchanged.

`docker/hosted_git.py` checks the exact original core declaration and lock:

- Repository `https://github.com/NousResearch/misaki.git`.
- Immutable commit `f03fd2be7346952a83d3d4845c217fc7667f322d`.
- Locked version `0.9.4`; the existing `misaki[en]` declaration/markers stay intact.

The existing native `_toolchain(realize=False)` selects already-installed pinned
Python/uv inside `/opt/seed/tools`; no extra/default/browser tool acquisition is
requested. The pinned uv CLI executes `pip install --no-deps --no-config` for
only the bare literal Misaki Git requirement into the exclusively created
`/opt/seed/git-preparation/online` target. It does not install into the core,
verifier, system, selected venv or consumer. `--no-python-downloads` and explicit
Python/cache/target paths apply; `--link-mode copy` prevents temporary target
links from becoming reusable seed inputs. No `en` extras or runtime dependencies
are installed. Necessary isolated build-backend requirements may be acquired by
normal uv source preparation; maintainer/build execution is not disabled.

A second independent, initially empty `offline` target runs the same pinned
requirement with explicit `--offline`, the same genuine uv cache, and no deps.
Both targets must yield exactly one Misaki distribution with the original version
and uv-authored PEP 610 URL/requested revision/actual commit. Real bounded Git
`cat-file commit` reads authenticate the immutable commit object and retain its
tree/SHA-256. Cache databases use the actual retained uv layout
`git-v0/db/<opaque-key>/.git`; keys are enumerated, never derived or edited.
That layout was observed in the existing disposable public-tool cache, not in
this hosted failure's missing precise Git readback. No historical Misaki cache
identity is inferred from it.

Only uv writes its cache. No opaque metadata/freshness edits, lock/facts/selection
fabrication, frozen resolution, consumer installer, wrapper or online fallback
is introduced. The full native producer warm remains online/default and fresh
consumer core-plus-member resolution remains explicit offline under actual
network:none. The narrow replay is not the fresh full union and cannot certify
later resolve/sync/build dependencies or native acceptance.

## Evidence, bounds and cleanup

Actual commands use the inherited 1 MiB cumulative encoded audit/32-command
budget and owned-process-group reaping. Preparation has a 240-second aggregate
sampled deadline, at most 120 seconds/1 MiB output per child, a polled 2 GiB/
100000-entry shared cache ceiling and 64 MiB/4096 entries per installed target.
Polled disk bounds are cooperative, not a filesystem quota or proven overall fit.
Sampling can overshoot between intervals; the existing container resource limits
and disposable hosted VM remain the outer boundary. The 4 MiB bootstrap aggregate
export, default Docker provisioning capabilities and stricter candidate isolation
are unchanged. Ambient UV/Python settings are sanitized by the pinned native
engine's existing `_base_environment`; no ambient offline policy is forwarded.

`git-preparation.json` is incrementally written privately under a 32 KiB bound,
including failed command stage, before/after measured cache usage, exact source
contract hashes, both PEP 610/metadata readbacks, real Git object and owned cleanup.
The exclusively created two-target directory is disposed on success, failure or
interruption before the reusable seed can be published. Preexisting directories
are refused and never claimed for cleanup. Cleanup/export failure cannot replace
the primary source/install/replay error; on success it refuses completion.

The controller independently exports this file before image commit and again
on failure after exact stopped-container ownership/isolation checks. Missing,
oversized, incomplete, malformed or flags-only success provenance refuses.
A successful inventory also contains the complete actual preparation report.
No temporary installation, plugin config, admission receipt, selected generation
or producer environment is transferred as consumer admission.

## Source regressions and preserved assertions

Ten additive mandatory `tests/test_docker_git_preparation.py::GitPreparationTests`
IDs cover actual producer command ordering RED/GREEN, original core declaration/
lock and drift, actual pinned uv help/parser and nonrealizing PM selection,
substituted online/independent offline commands and cleanup, actual-file PEP 610
refusals, tiny real Git object/hash and missing/forged-object refusal, pre-effect
local/missing-tool/preexisting-root refusal, real child deadline/output/reaping
and primary-error precedence, no-warm-after-preparation-failure, and independent
strict/bounded ownership-first export. Normal and actual Python -O are required.
The installer boundary and source acquisition are substituted locally; tiny
Git fixtures/help execution are not real Misaki acquisition or native acceptance.

All inherited test IDs/assertions and historical fixtures remain. Only two old
controller seam methods gain a scoped decorator substituting the new preparation
export boundary, to retain their original process-capability and failed-image
behavior under their intentionally minimal inventories:

- `test_docker_bootstrap_repair.py::BootstrapRepairTests::test_hosted_build_success_crosschecks_process_proof_before_commit_and_owned_cleanup`.
- `test_docker_image_readback.py::ImageReadbackTests::test_hosted_failed_image_retains_proofs_and_never_registers_or_deletes_base`.

Their original bodies/assertions are byte-identical; exact before/after file/body
hashes and diffs accompany the handoff. The new export boundary is separately
mandatory and cannot be skipped by the real controller.

## Delivery gate

Subsequent actual hosted run `37815273128` passed the genuine narrow preparation,
independent offline replay, PEP 610/Git objects and target disposal. Online native
warm and final complete source identity passed too. Its new first failure was
retained seed inventory, before image commit or consumers; this does not establish
full fresh offline native enable or exact failed retained totals. The meaningful
producer-only compaction/accounting successor is documented in
[producer-retention.md](producer-retention.md); the original uv cache is untouched.

This is PRE_CI_SOURCE_REVIEW only. Full tracked native default-scope scanning,
pinned whole-workflow actionlint, preserved canonical IDs and packet-denied
normal/-O checks accompany the committed successor. Missing local admission
remains failed. Faolan owns independent exact-source/workflow review and one
meaningful corrected feature-only hosted run. Actual source preparation, offline
fresh native enable/selection, full canonical, cold/restart and successful cleanup,
then final same-card Gilfoyle review remain required before PR/human handoff.
No local acquisition/Docker/new environment/native admission, builder push/CI/PR,
live core/profile/store/service/LAN or main/merge/deployment effect is authorized.
