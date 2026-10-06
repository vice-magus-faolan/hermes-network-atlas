# Finite Docker acquisition and peak plan

This document specifies the fail-closed input contract. It is NOT a resolved
acquisition lock, measured build result, first-setup permission or native receipt.
Read `docs/docker-acceptance.md` for the separate exact-byte review/authority gates.

## Required resolved metadata

`--plan` is a bounded JSON file (at most 1 MiB), schema 1, status `resolved`, with
no unknowns. It must bind the exact public core commit/tree, linux/amd64 platform,
upstream manifest/config image and rootfs diff IDs, every fixed public input hash,
and complete apt/PM/verifier/member-union closures. Each artifact needs:

- category: upstream-layer, apt-index, apt-package, pm-tool, verifier-wheel,
  union-wheel or core-archive;
- actual name/version, literal filename, fixed public HTTPS URL and SHA256;
- exact positive compressed length, independently defensible unpacked byte
  ceiling and archive/filesystem member ceiling;
- reviewed source metadata connecting that artifact to the pinned closure.

Public origin validation, literal filenames, lengths, hashes, finite counts and
closure completeness are code-enforced. Schema assertions alone do not establish
metadata authenticity: independent review must verify source metadata and the
complete closure. Duplicate filenames, missing categories, unknown/null/boolean
lengths, floating versions and unbounded source builds refuse before effects.
A resolved manifest must preserve literal source identifiers; do not repair a
masked or otherwise nonresolving PM lock token into a different pin.

Acquisition downloads only planned artifacts inside the private bootstrap rootfs.
It verifies lengths/hashes and archive expansion metadata before native extraction.
Debian data/control archives and compressed apt indexes are bounded too. Package
installation, tool installation and dependency prewarming are then packet-denied.
Native PM still verifies/install its own public tools and builds environments;
there is no mocked installer/resolver, synthesized native state or online fallback.
Offline member-union resolution/cache reuse remains unproved until real execution.

## Peak overlap, not final Size

The preflight calculation currently uses the conservative declared envelope:

    peak = 3 * sum(compressed_bytes)
           + 4 * sum(unpacked_bytes)
           + 8192 * sum(member_ceiling)
           + 128 MiB controller/log/metadata overhead

    required_free = peak + 512 MiB untouched reserve

Compressed duplication includes acquisition/native-PM partial/final staging.
Unpacked overlap includes parent extraction, setup/staging, commit blobs and the
retained committed snapshot. Member overhead conservatively covers filesystem
metadata/block tails. Every individual ceiling still needs defensible metadata;
unknown expansion or arbitrary package-script/resolver writes invalidate the
bound. This formula is deliberately NOT evidence that arbitrary unknown inputs fit.

Compare to FRESH free space on `/var/lib/containerd`, not DockerRootDir or /home.
If complete bounds exceed that budget, preflight reports the exact additional
bytes required and refuses before mutation. If metadata is incomplete, the gap
is UNKNOWN: do not replace it with a guessed deficit or a final image.Size.
Sampled free-space minima/abort checks during a future approved build add
observability, not a filesystem quota. Export binds have cooperative application
bounds, not hard host disk limits. First-build resource success is unproved.

## Public metadata presently established and missing

Read-only tag/release/lock metadata has established the requested platform digest,
a reported aggregate upstream compressed size, PM Python/uv artifact hashes and
lengths, and six verifier wheel versions/hashes/lengths. These are PARTIAL metadata.
The recorded compressed sums must be derived from enumerated artifacts; an
aggregate that accidentally omits the verifier wheels is not accepted.

Still unresolved: OCI per-layer/config/diff-ID metadata and unpacked ceilings;
Debian snapshot index hashes/lengths and complete versioned package closure;
Python/uv/wheel expansions/member counts; actual core/member-union offline closure;
package-script/cache/staging duplication and commit/snapshot peaks. No artifact
binaries were acquired and no container/native setup was run to manufacture those
answers. The present partial metadata CANNOT be passed as `--plan`; preflight
refuses it before Docker effects. Complete this metadata and independent review
before requesting first setup or quantifying additional root storage.

## Evidence and implementation-only verification

`python3 scripts/check_docker.py` and its `python3 -O` form exercise synthetic,
inherited-packet-denied lifecycle/ownership/bounds/cold-selection regressions,
never a real Docker daemon or native admission. Use the recorded existing
receipt-selected bootstrap interpreter where that is the implementation lane's
contract; its old native receipt does NOT admit these changed bytes.

`python3 scripts/test_result_report.py <real-log> --exit-code <actual-code>`
enumerates every unittest ID/status, including standalone statuses after native
stdout, and validates discovery/reported totals. Missing fresh admission must
remain canonical failures, not skipped tests or a promoted old green receipt.

Genuine stopped-rootfs construction, nonroot runtime passing/failing/interrupted
teardown, new ordinary native scan/install/enable, cold selected-generation
consumer, full canonical acceptance and cumulative independent review remain
separate required evidence before publication. No retained fixture/controller,
registry, image or predecessor is deleted merely to satisfy a capacity threshold.
