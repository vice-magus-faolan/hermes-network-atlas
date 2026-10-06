# Finite Docker acquisition and peak plan

This remains the DISABLED legacy metadata-plan path. See the approved staged
[hosted-first successor](hosted-first-docker.md) for its distinct private PUBLIC
prerequisite resolution/real native PM and network-none acceptance architecture.
The successor does not promote projections to resolved/fit evidence and does not
authorize any local execution. Exact code/workflow review precedes the owner's
one future hosted attempt; current-artifact native acceptance is still required
afterward. The actual legacy `prewarm` dispatcher also refuses before PM effects.

This document specifies the fail-closed input contract. It is NOT a resolved
acquisition lock, measured build result, first-setup permission or native receipt.
Read `docs/docker-acceptance.md` for the separate exact-byte review/authority gates.

## Mechanical linkage, not resolved execution authority

The former schema-1 `resolved` plan and Boolean `closures` are refused. The
replacement bounded JSON (at most 1 MiB) uses schema 2 and explicit status
`linked_metadata_only`. This name is deliberate: validation is NOT authenticated
resolution, an expansion proof, storage fit, operator consent or build authority.
Duplicate JSON keys and unknown/missing schema fields refuse. No real resolved
plan exists yet; `build`, direct `build_owned`, `acquire` and root setup all fail
closed through `require_execution_ready()` before effects. There is no plan,
environment, foreground or command-line switch that enables that gate.

The mechanical contract binds exact public core commit/tree, linux/amd64,
upstream manifest/config and ordered diff IDs, every fixed input hash, and
source-linked apt/PM/verifier/member closure projections. Each artifact needs:

- category: upstream-layer, apt-index, apt-package, pm-tool, verifier-wheel,
  union-wheel or core-archive;
- actual name/version, literal filename, fixed public HTTPS URL and SHA256;
- exact positive compressed length, independently defensible unpacked byte
  ceiling and archive/filesystem member ceiling;
- `source` and `record` identifying exactly one retained metadata record.

Retained OCI manifest/config TEXT hashes must match the pinned upstream and its
config descriptor; config size/platform/diff IDs, compressed layer descriptors
and artifact rows correspond one-for-one in order. PM python/uv rows retain the
literal linux-x64 lock version/URL/hash/basename. Before context writes, those
lock bytes, recipe dependency bytes and core uv.lock hash must match actual
committed PUBLIC inputs, not caller-declared hashes. No native pin is repaired.

Apt/verifier/member source documents are strict hashed closure PROJECTIONS with
kind, source pin, explicit roots and exact records (identity/category, requires
and metadata_sha256). Code traverses edges and rejects missing, disconnected,
extra or duplicate members, category/source mismatches and changed identities.
Apt roots are ca-certificates/git/openssh-client; selected package references bind
to a selected snapshot index digest. Verifier roots/versions and member roots/
numeric bounds bind to recipe requirements; member metadata binds to core uv.lock.
Unsupported requirement syntax refuses rather than implicitly resolving it.

These projections do not authenticate Debian signatures, prove index-to-paragraph
membership, solve Debian alternatives/versions against base installed state, or
establish the actual native union resolver closure. A caller could invent a
self-consistent projection. Therefore it is explicitly NOT an acquisition lock;
independent provenance review AND real authenticated resolution remain required,
and the live gate stays disabled. Declared expansion/member/PM-size ceilings are
not measured/authenticated by linkage checks. Never promote these estimates to
proof. Tiny mock documents and mocked lifecycle gates are tests, not permission.

The proposed future acquisition would download only planned artifacts inside
the private bootstrap rootfs; it is currently disabled, not exercised.
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
The calculation returns planning_only=true and fit_proven=false even when the
declared envelope fits. Its arithmetic gap is only the gap in that DECLARED
estimate, not actual additional storage required. The real gap remains UNKNOWN:
do not replace it with a guessed deficit or a final image.Size.
Sampled free-space minima/abort checks during a future approved build add
observability, not a filesystem quota. Export binds have cooperative application
bounds, not hard host disk limits. First-build resource success is unproved.

## Public metadata presently established and missing

Read-only tag/release/lock metadata has established the requested platform digest,
a reported aggregate upstream compressed size, PM Python/uv artifact hashes and
lengths, and six verifier wheel versions/hashes/lengths. These are PARTIAL metadata.
The recorded compressed sums must be derived from enumerated artifacts; an
aggregate that accidentally omits the verifier wheels is not accepted.

Read-only independent metadata inspection subsequently established exact OCI
manifest/config/layer descriptors and ordered diff IDs, plus Debian snapshot
index lengths/hashes. It did NOT establish OCI expansion or authenticate Debian
InRelease signatures and index/paragraph membership. The exact complete public
core archive is an UNCOMPRESSED tar: 215183360 archive bytes, SHA256
2b49c565f1f70fb09d237df4e3919857d71ba93622e63c8ecdf01b3c6be2aa96,
18083 members and 201194738 regular-file payload bytes. The generic
compressed_bytes accounting field for that local core input means archive FILE
length, not compressed tar length. Prior compressed labels are not reused.
The core-archive URL denotes the pinned public SOURCE repository, not an invented
downloadable tar endpoint; `base_context` creates the archive from the exact Git
commit and checks its hash. No core payload is downloaded by linkage validation.
The on-disk native PM lock contains no literal asterisks; masked display output
is not a source defect. Literal source values must not be normalized or repaired.

Still unresolved: OCI unpacked ceilings; authenticated Debian package closure;
Python/uv/wheel expansions/member counts; actual core/member-union offline closure;
package-script/cache/staging duplication and commit/snapshot peaks. No artifact
binaries were acquired and no container/native setup was run to manufacture those
answers. The present partial metadata CANNOT be passed as `--plan`; preflight
refuses it before Docker effects. Complete this metadata and independent review
before requesting first setup or quantifying additional root storage.

The real architecture decision is how to enforce an aggregate storage boundary
for image content/snapshots AND opaque dpkg/PM/uv setup/staging/commit writes,
or replace that setup with a separately reviewed bounded architecture. Metadata
alone cannot bound arbitrary maintainer-script/resolver writes. No aggregate quota
has been demonstrated. Per-file RLIMIT, CPU/RAM/PID/log limits and sampled reserve
monitoring are not an aggregate disk limit. This phase authorizes no storage,
daemon, privilege or installation change to solve that decision.

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
