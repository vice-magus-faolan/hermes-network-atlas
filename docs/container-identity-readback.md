# Acceptance container identity and before-refusal readback

## Observed evidence versus source-derived cause

Actual GitHub-hosted run `37707667589`, attempt 1, at
`29ca4638784a56a9d31f62f0eb442a0157da2080` successfully provisioned and verified
base image `sha256:0cc61b2164ba8798e003012dc84be78693a1146f5751004362393a03dfd5baf0`.
Its exact inert `/usr/bin/true` command, empty entrypoint, UID1000, full eight
provenance labels and rootfs guards passed. The smoke container then failed the
combined ownership predicate before start. Its actual container inspect was
NOT exported. Which historical Name/Image/Id/Labels field differed remains
UNKNOWN; no test fixture purports to be that missing container observation.

The compact public image inspect is retained byte-for-byte in
`tests/fixtures/run37707667589-committed-image.json`: 3740 bytes, SHA256
`69ed2298c400e69c89f8c2fcbe134f957a37362f8531a7d973364fd46d10296f`.
`tests/fixtures/run37707667589-base-identity.json` is a clearly named identity-only
projection of the actual registry receipt, not a complete native inventory.
Its SHA256 is `3064177868f2ccd6cb1ecb057846529d986cf1b4d52953cc591a91c2f606d2ec`.
Original receipt SHA256 is
`08d3389adbfcfc6a1e8a208ca1147c751b9c5bb74e8855c6c8bd9ec984e8df9b`.
Historical ZIP artifact 11520012986 SHA256 is
`932aa5c148e78b949b77674cebb83662847b6adc14163ec09ab5ec76efbc3038`.
The receipt's omitted dependency inventory/consumer paths are never synthesized
as historical facts, and these fixtures grant no admission/cleanup authority.

Primary source establishes the conventional compatibility defect:

- [Moby v28.0.4 daemon/create.go](https://github.com/moby/moby/blob/v28.0.4/daemon/create.go):
  `create` calls `mergeAndVerifyConfig`, which calls `merge(config, img.Config)`.
- [Moby v28.0.4 daemon/commit.go](https://github.com/moby/moby/blob/v28.0.4/daemon/commit.go):
  `merge` adds each image label absent from explicit user labels. Explicit labels
  win on collisions; supplying some labels does NOT discard image provenance.

The predecessor explicitly supplied five attempt labels, but expected exact
five-label equality on inspect. With the real verified eight-label base,
Docker's source-defined merge produces eleven labels: owner and daemon overlap
with equal values; six remaining base provenance keys survive; commit/tree/image
are attempt keys. Packet-denied predecessor RED executes that production guard
against this modeled composition. This is demonstrated source/contract behavior,
NOT proof of the unexported historical container's precise field or a successful
corrected daemon/native run.

## Exact authority and lifecycle contract

`docker_acceptance.validate_base` reconstructs `BootstrapIdentity` from the
bounded registry receipt and reuses the full `verify_final_image` guard. It
checks exact base-key, plan hash, core commit/tree, upstream digest, daemon,
image, all eight labels, inert command/entrypoint/user/working directory/empty
volumes/ports and recorded rootfs layers. Changing both receipt and inspect to
include extra labels, wrong pinned provenance or unsafe config still refuses.
The receipt is trusted local controller state, not candidate/tool-supplied policy.
Initial image validation already bound the exact upstream layer ancestry.

Preflight freezes the revalidated base label pairs in the immutable `Identity`.
`Identity.labels()` remains the original five attempt values; the new
`container_labels()` composes one exact full map. Create explicitly supplies all
of it. Initial validation, wait, export, interrupt stop, cleanup and durable
consumer records use that same map. There is no subset, wildcard, arbitrary
extra-label allowance, owner-only deletion or inspect-derived authority.
All acceptance argv remain `python3 /candidate/scripts/docker_inside.py MODE`.
User, mounts, network-none, read-only, capability-drop ALL, NNP and resource/log
limits are unchanged. Bootstrap/public setup/inert-command contracts are untouched.

Production run binds the exact lowercase 64-hex ID returned by create before
initial inspection. Raw name lookup never grants ownership. An inspect with a
matching name/image/full label map but a different syntactically valid ID refuses
before start and in subsequent export/stop/remove. Missing/invalid create output
cannot authorize deleting a container left behind by a failed create. Pre-existing
resources still refuse before effects; no suffix/replacement/prune recovery.

Legacy pure contract fixtures can still construct four-field identities to test
the pre-existing stateless guard. Real preflight always carries validated base
provenance, for which a returned ID is mandatory before any ownership-authorized
operation. Once a stateless lifecycle fixture reads a valid ID, subsequent checks
bind that ID too. This compatibility does not provide a CLI/tool bypass.

Consumer records add the exact composed labels and returned container ID and
recheck frozen base provenance on each write. The original active consumer is
registered before create, remains on failures and changes to retained-awaiting-review
without a duplicate row. Consumer persistence is attempted independently of
outcome export so an evidence failure cannot conceal the live resource consumer.
Registry failure is an explicit failed outcome, not cleanup success. Existing
live consumers continue to prevent owned base deletion; no unsafe image cleanup
or historical fixture retirement is introduced.

## Bounded diagnostic contract

`read_container` reads only the fixed owned name and persists the actual parsed
object before ownership/isolation predicates. The existing Docker list/inspect
adapter distinguishes absence from daemon errors; name lookup bypasses no identity
predicate. Missing Id is allowed to reach diagnostic persistence, not mutation.
Each fixed stage emits `STAGE.json` and `STAGE-validation.json` within the existing
metadata export group. Stages are created, export, stopped, interrupt (when used),
cleanup, cleanup-stopped and cleanup-absent. The audit includes expected/observed
Name/Image/Id/full Labels, exact mismatched fields and label keys, candidate
commit/tree, expected daemon/image/base provenance, returned container ID, stage,
actual parsed JSON byte count/hash, absence and diagnostic errors. Oversized or
failed reads retain a bounded error audit, not an invented object. Absence proves
only an absent named container, never actual native success.

Parsed readback has a stricter 512 KiB ceiling. Existing command deadlines/output,
4 MiB log read, per-file/count/aggregate/transient metadata bounds, registry and
128 MiB/256-member compact export ceilings are not enlarged. Diagnostic writes
use `BoundedDirectory`. A failing actual inspect/predicate remains primary even
if raw/audit persistence also fails, with bounded secondary notes. A valid
ownership/isolation result with failed required persistence fails before effects.
Exporter and cleanup apply the same evidence-before-refusal ordering and exact
ID/full-label guard. No log/copy/stop/remove is attempted on an unverified target.
Final snapshot/outcome errors are secondary, and registry retention is independent.

## Mandatory executable evidence and remaining gates

Ten added `test_docker_container_readback.ContainerReadbackTests` IDs are required
by the canonical manifest. They cover actual base proof/model separation,
preflight/composition/all six mode argv and unchanged isolation, coherent base
receipt/inspect drift refusal, every label/name/image/returned-ID refusal and raw
compact export, stop/reinspect drift, malformed/oversized/absent/daemon reads,
diagnostic primary precedence, failed/malformed create residue without deletion,
consumer retention despite outcome failure, and a complete production smoke
sequence through synthetic Docker seams. All inherited test/fixture files and
all 368 canonical/182 required/122 focused IDs are retained byte-for-byte or as
exact inherited IDs; no negative is removed. Normal and optimized Python are
both required. The new synthetic smoke is NOT an actual container canary or native
admission; no real Docker/package/native effects occur locally.

Fresh independent exact-source/workflow review precedes Faolan's meaningful
feature-only hosted continuation under standing authority. Actual exact-head
native install/enable, full canonical/cold/restart and complete owned cleanup,
then final same-card Gilfoyle approval, remain pending. Historical failed runs,
reviews, receipts and immutable graph are preserved. No main/PR/runtime effects,
new per-attempt human gate or heavyweight local fixtures are introduced.
