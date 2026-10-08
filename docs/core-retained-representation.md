# Versioned retained CORE and complete consumer materialization

SUPERSEDED active representation requirement. Historical source/fixtures and
numeric validators are unchanged; see [disposable-validation.md](disposable-validation.md).

## Decision and evidence boundary

The coordinator explicitly selects `atlas-core-git-only-v1` for the hosted public
prerequisite image. This changes the physical at-rest representation, not any
numeric limit, public pin, source scope, object history, cache/tool/PM behavior,
scanner scope or admission rule. Source implementation and tiny native Git tests
are PRE_CI_SOURCE_REVIEW only. Corrected hosted fit/native/canonical/cold/restart/
all-mode cleanup and final same-card independent review remain pending.

Actual earlier run `37831615760` measured the expanded seed at 1096574127 bytes,
22832303 above the unchanged 1073741824 ceiling. Its expanded CORE worktree was
201212061 bytes, in addition to complete Git metadata. Removing that duplicate
conditionally projects 895362066 retained bytes; adding an explicit 8388608
metadata/headroom reserve projects 903750674, leaving 169991150. These are
historical arithmetic projections, NOT this successor's actual measured fit.
The logical expanded source is still declared; it is not silently excluded from
an expanded-format budget.

Run `37843978698`'s measurement-only current recipe succeeded; its tuned recipe
hit the unchanged child deadline. No third recipe, parameter search, object
pruning, cache edits, repinning or raised ceilings is introduced. The committed
measurement marker is retired in this separately authorized production successor.
The existing validated feature route now selects ordinary hosted acceptance;
measurement scripts, workflow guards and all regression IDs remain.

## Fixed identity and format

The new `scripts/core_representation.py` contract fixes:

- CORE commit `5645275e50d66dca04c9565634f9b5207a38aef5`.
- Tree `85282aca9d246911005dba7adbdf3ca3ddd04df5`.
- Complete source digest
  `6c136cc4cf643181091c0077b85ff1fc86615cd841425e91ae1269f951137c79`.
- Format `atlas-core-git-only-v1`, private `/opt/seed/core-git/.git` and
  `/opt/seed/core-representation.json`, plus the unchanged complete
  `core-source-manifest.json`.

The exact record includes actual full object count/digest, complete metadata
file/entry count and byte/content digest, source member count, expanded regular
source bytes, and `native_acceptance=false`. Unknown fields, versions, mixed
expanded roots, missing/partial records, Boolean counts, wrong pins and malformed
ledgers fail closed. No automatic fallback or reuse of partial staging occurs.
The explicitly disabled legacy acquisition-plan/BASE_FILES path is unchanged;
its strict expanded tests are not authority to build or consume a new image.
The hosted PUBLIC_FILES key includes every new representation helper and its
actual standalone dependencies, so changed helper bytes change the image key.

## Producer ownership and failure

The actual hosted dispatcher runs the unchanged complete source publication and
object-preserving compaction first. Before moving Git, it authenticates every
source/test/doc byte, executable bit and symlink, config/shallow/metadata, full
fsck, literal commit/tree and ALL objects including unreachable objects. It
exclusively creates the fixed sibling `core-git` and moves the entire `.git`
without deleting any object, changing shallow boundaries or copying host Git.
Metadata bytes are checked again after the move. Only after another source and
literal root/UID check may this bootstrap's duplicate expanded root be retired.
A preexisting destination refuses; nothing searches for or cleans other roots.

Git storage cannot be linked or special, have alternates, HTTP alternates,
grafts, replace refs, external gitdir/commondir, local `info/attributes`, active
hooks or a changed inert reconstructed config. Producer diagnostics incrementally
record authentication, move and completion/failure in a bounded 32 KiB file.
Failure preserves the primary error and private moved/source state, with no
reusable image publication or automatic rollback/retry. Diagnostic errors are
secondary. Exact stopped-container ownership is checked before independent
export of both record and diagnostics, including on failed setup.

## Consumer before scanner/native imports

`docker_inside.prepare` first checks actual complete physical seed/verifier totals
against the self-inclusive final inventory. It creates the fixed UID/GID1000
contained `/work/fixture/hermes-source` exclusively, copies ALL Git state and
checks the complete metadata and object ledger with genuine Git before running
one literal `git archive --format=tar <pinned-commit>`. Global/system Git config,
hooks, external attributes, prompts, ambient Git/proxy state and custom formats
are not inherited. No shell, helper, filter command, network or elevated
capability is used.

The binary archive streams to a spool INSIDE the exclusively owned destination.
It has the existing 256 MiB source-artifact ceiling, not the 4 MiB text-log limit.
Stderr still has the unchanged 4 MiB cap and bounded head/tail/hash audit. The
source stream contributes only byte/hash metadata to the ordinary cumulative
1 MiB/32-command audit. Children retain 60-second/120-second aggregate bounds
and owned process-group termination/reaping. Extraction checks member/count,
path, duplicate, ancestor-link, expansion and deadline bounds. Hardlinks, special
files, `.git` payloads, absolute/traversal paths and escaping links refuse.
Each regular-file block checks the deadline before a bounded write.

Native Git archive preserves the required PS1 CRLF semantics; raw blob extraction
would not. Tiny genuine CRLF/executable/symlink cases execute this behavior in
normal and actual Python -O. No hand-written newline normalization is used.
Every complete restored source path, mode and link must match the original full
manifest/digest; Git metadata must be unchanged afterward. Export-ignore or
export-subst cannot turn omitted/changed bytes into success. No original source,
test or documentation member is removed from identity or native scanning.

Only after these checks are tools/cache/candidate copied and genuine fresh native
scan/install/enable/union/generation selection run. Producer selections, source
facts, admission and environments are never reused. The base stays read-only;
acceptance stays non-root, cap-drop ALL, NNP and network-none. On any copy/archive/
extraction/identity/deadline/ENOSPC failure, the exclusively created partial source
and its spool are disposed, primary error retained and bounded failure evidence
exported. An existing consumer destination is never removed or reused.

## Honest accounting

The numeric bounds stay 1 GiB retained regular-file apparent bytes, 100000 visited
entries/files, 256 MiB source/archive/metadata reads and 2 GiB `/work`. Whole-root
regular-file semantics continue to count hardlink paths and not follow/count
symlink target bytes, just as the prior guard did. Actual filesystem-used bytes
are separately observed; apparent bytes are not allocated-block or image-layer
sizes. The controller must not call the old expanded logical total a physical
1 GiB success.

`seal_inventory` reaches a finite measured fixed point for BOTH inventory JSON
files, their own sizes, the representation/source manifests and all metadata.
Actual atomic-report/inventory overwrite overlap is guarded before writing;
no estimated reserve substitutes for final totals. Logical expanded seed bytes
are declared as actual represented physical seed plus complete expanded source.
Verifier totals remain separate under their original accounting. Consumers
re-stat both complete roots before accepting that inventory.

During materialization, complete copied Git, partial/full source and the binary
spool all count in actual `/work` measurements. Periodic cooperative samples
retain byte/filesystem peaks. A forced whole-root measurement while BOTH complete
spool and complete source exist captures the owned monotonic materialization
high-water boundary, even for sub-second fixtures. The spool is then removed
before identity/native work; all remaining consumer/fresh PM generation state
still counts under the existing private tmpfs quota and before/after usage.
Sampled metrics do not prove every later native-phase peak or overall fit. The
real hosted tmpfs/memory/output/deadline boundary remains the enforcement layer;
real complete source/union performance and fit are still unproven.

The independent controller checks representation record/diagnostic against the
complete inventory before image commit. For materializing successful modes it
requires actual restored full manifest and matching complete object/metadata,
source/expanded byte, pin and peak proofs, not just an inventory Boolean. Existing
intentional fail/interrupt modes do not materialize source; old fixture-only
controller tests retain their explicitly separate legacy behavior. Current
`prepare` cannot accept a legacy base. No smoke result becomes native acceptance.

## Mandatory regressions and narrowly changed seams

All fourteen `tests/test_docker_representation.py::RepresentationTests` methods
are required by the canonical verifier. They actually publish, fsck, preserve
unreachable objects/absent parents, stream/archive/extract, authenticate CRLF/
mode/link/full identity and seal/read back self-inclusive inventories on tiny
packet-denied native Git fixtures. Negative tests cover old/mixed/partial/count/
ledger formats, source/object/config/hooks/alternates/attributes/path/type drift,
real child deadline/output/nonzero/reaping, spool/physical budgets, simulated
ENOSPC/secondary export, primary cleanup precedence, retained producer failure,
no reuse, and independent controller export/whole proof refusal.

Two inherited method AST bodies change only their structural expectation:

- `RetentionTests.test_actual_producer_reduces_before_unchanged_inventory_guard`
  checks compaction then `seal_inventory`, which still invokes the original
  strict `retained_inventory`, rather than a direct call in `main`.
- `DefaultCommandTests.test_default_executable_availability_is_guarded_audited_and_output_free`
  recognizes the self-inclusive `seal_inventory` as the hosted success export;
  the original single no-op/availability/order assertions remain.

Two intentionally minimal daemon fixtures retain their ENTIRE method bodies and
assertions, adding only decorators substituting NEW representation inventory/
export/comparison boundaries: the bootstrap process-proof success test and the
historical failed-image readback test. The new actual-file/controller tests cover
those boundaries separately; their tiny mocked old inventories are not v1 proof.
Exact before/after bodies, hashes/diffs, all inherited IDs/required IDs/fixtures
and full tracked-tree native-default scan are retained in the review packet.

Local execution uses the existing interpreter/Git only. No whole-core fixture,
Docker, downloads, admission, live homes, opaque-cache edits, service effects or
publication is performed. Faolan owns exact independent source/workflow review,
one meaningful reviewed hosted continuation and final acceptance routing.
