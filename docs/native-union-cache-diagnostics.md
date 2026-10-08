# Native member-union cache diagnosis

## Observed failure and scope

Hosted run `37729012087` executed exact candidate
`68723f85638206214e3a1e88242a8ff41fd2e23f`. Its actual `/work` kernel flags
permitted execution and both selected native tool version probes passed. Genuine
native install completed and published Network Atlas with `enabled:false`.
Native enable then failed during fresh core-plus-member resolution: uv reported
removal of global exclude-newer, attempted the pinned kittentts 0.8.1 direct URL,
and failed DNS under actual network:none. Canonical/cold/enabled acceptance was
not reached. Public warm exiting zero is not proof of fresh-consumer cache closure.

The exact cache-entry/key/freshness deficiency remains UNKNOWN. This successor
is diagnostics-only, explicitly permitted by the current implementation card;
it does not claim a cache repair or a corrected native success. No optional engine,
model, browser or GPU installation, pin change, alternate installer, source
mutation or admission/selection fabrication is introduced.

## Pinned production trace

Coordinates refer to unchanged public Hermes
`f42f579cf8bac4918ac9599bece71618afadd846`, not current upstream:

- `pm/client.py:205-232` routes explicit Members and proposed Selection through
  the genuine native worker. Producer warm uses the former; enable uses the latter.
- `pm/packages.py:406-438` creates a fresh generation and selects prior union lock
  only when native facts actually contain one; otherwise it seeds core's lock.
  The fresh consumer receives tools/cache, never producer facts/generation selection.
- `pm/workspace.py:112-168,350-382` copies inputs into a writable workspace,
  generates members and moves global exclude-newer into registry-package-specific
  quarantine. This is normal pinned producer AND consumer behavior, not a newly
  demonstrated core defect. `pm/environment.py:337-386` locks that fresh member
  workspace before sync; sync's frozen installation follows genuine resolution.
- `pm/environment.py:196-210,271-318` strips non-allowlisted UV settings and sets
  actual cache/interpreter/destination from the engine. `pm/index_config.py:24-44`
  does not forward UV_OFFLINE; `pm/runtime.py:21-31` uses the same sanitizer.
  Outer `UV_OFFLINE=1` is therefore NOT native offline enforcement. Actual Docker
  network:none plus inherited socket syscall denial remain enforcement.
- `pm/progress.py:40-48` supports HERMES_VERBOSE. `pm/environment.py:297-304`
  streams actual uv verbose output and preserves an explicitly supplied RUST_LOG.
  Producer warm and the hosted enable child now use HERMES_VERBOSE=1 and
  RUST_LOG=uv=debug, within unchanged command deadlines/output bounds. These are
  diagnostic settings, not new resolver flags, index redirects or install consent.

Executed pinned-engine tests capture the REAL `_run` argv/environment at its
subprocess boundary, prove UV_OFFLINE stripping in both sanitizers, and bind the
actual sync signature (no offline parameter). A tiny real workspace uses the
unchanged member/quarantine generator and lock-and-sync path; only subprocess
execution is intercepted. These contracts are NOT actual dependency resolution,
cache sufficiency, native worker installation or full acceptance.

## Evidence retained on the next hosted attempt

`native_union_diagnostics.py` only reads disposable public inputs/cache:

- Actual pyproject/lock byte counts and SHA-256, literal global cutoff/span,
  package-quarantine count/hash, and literal pinned kittentts requirements/source.
- Actual member declaration file identities. Producer diagnostics additionally
  include the actual selected workspace inputs, but only if native facts supply
  its contained lock path. No replacement/generated lock is written by diagnostics.
- Deterministic whole-cache entry ledger hash, bucket/count/size summary, actual
  statvfs flags, and bounded matching kittentts entry identities. Traversal does
  not follow symlinks. Small matching files retain hashes and opaque base64
  prefixes; omissions and prefix incompleteness are explicit. Opaque HTTP/cache
  bytes are NOT decoded authentication/freshness proof.

Each compact report is capped at 8 KiB. Traversal retains the existing 100000-entry/
2 GiB ceilings, adds a 10-second read deadline and 64-bucket ceiling, and records
at most eight matching details/1024 aggregate prefix bytes. Small metadata reads
are capped at 128 KiB; regular source lock reads use the existing 8 MiB evidence
ceiling. Oversized, malformed or special inputs refuse with bounded diagnostics,
never empty-cache success or manufactured facts. Same-UID cache mutation remains
outside a transactional snapshot guarantee; observed metadata describes the
read interval, not an immutable uv cache or completed closure.

Producer before/after-warm reports are atomically captured in private mode0600
`/opt/seed/union-diagnostics.json`, independently of inventory success. Only the
fixed initial/terminal phases are allowed, with a 32 KiB aggregate ceiling and
no replay/repeated phase. The successful inventory binds its actual hash. Existing
final public-seed readability later makes this public-only provenance mode0644;
no credentials or production homes are inputs. Consumer/PTY exports remain mode0600.
`hosted_docker.export_union_diagnostics` rechecks stopped immutable ownership and
full bootstrap isolation before copying that exact file, prior to ordinary owned
cleanup. Missing early-failure evidence is explicit; missing evidence after
successful setup fails. Separate export status cannot replace a primary error.
The legacy five-member provenance contract/assertions remain unchanged.

Consumer `before-enable.json` and `after-enable.json` survive in the bounded export.
Actual native enable output survives exceptions as `enable.log`; its private
`enable-command.json` retains actual argv, exit/error, elapsed time, observed
completion and retained byte count/hash. The PTY drains to actual EOF, answers
only the inherited narrow PM prompt once, enforces the unchanged 4 MiB/900-second
bounds and reaps only its owned process group. Exceptions contain bounded exit
summaries rather than repeating raw logs into traceback/container.log. If output
or deadline bounds stop collection, the audit explicitly marks it incomplete.
A whole-container kill can still prevent final PTY evidence persistence; already
exported source/cache reports remain separate. Diagnostic/export errors cannot
replace a native failure, and block acceptance on an otherwise successful enable.

Consumer reports are read-only source/cache snapshots before/after the actual
operation, NOT a saved failed generation: pinned PM removes failed workspaces.
Actual resolver/cache decisions are in enable.log; declared pinned source
contracts are not presented as a trace of an unobserved resolver argv. Config
rollback was reported by the predecessor's native failure, not independently
parsed/exported there; this successor makes no retrospective rollback claim.

## Required regressions and final gates

Eleven additive mandatory `UnionDiagnosticsTests` cover literal predecessor RED/
successor GREEN with a real failed child, exact failure export and primary error,
real PTY success/failure audit, near-cap output without duplicate exception text,
deadline/owned reaping, metadata hashes/symlinks/count/report/malformed refusals,
read-only actual source/member/lock settings, actual pinned PM environment/argv/
signatures and workspace quarantine, producer failure persistence, independently
bounded/ownership-guarded export and secondary-error precedence. They run normal
and -O; all inherited test bodies/fixtures and canonical IDs remain unchanged.

PRE_CI_SOURCE_REVIEW is implementation-phase completion only. Faolan owns exact
independent source/workflow review and meaningful feature-only hosted continuation.
Actual fresh enable, selected generation, full canonical/cold/restart/all-mode
cleanup and final same-card Gilfoyle review remain mandatory before feature/PR
acceptance. No builder push, local Docker/acquisition/native force, live/runtime/
profile/service/store/network effects, main advancement or fixture retirement.
