# Complete public core identity across hosted provisioning

## Observed failure and source-derived repair

Hosted run `37716278161` at `3fa9734ba7b396aa6d05935182c9123d70605387`
passed smoke/fail/interrupt startup and reached-mode owned cleanup. Refusal's
scan child failed at `caution_confirmation.verify_core`, before scanner import
and native installation consent. The actual manifest delta was not exported.
It was not a DANGEROUS scanner verdict or a successful ordinary refusal.
The historical differing member(s) remain unknown.

The pinned public core's normal named install has a concrete pollution path:
`pm/cli.py:238-257` calls `publish_launchers(repo_root(), create=False)` after
Python installation. `hermes_cli/venv_sync.py:68-95` still calls
`ensure_install_launchers` for that project. `hermes_cli/_launchers.py:391-406`
writes `.hermes/bin` there. `create=False` limits PATH convenience publication;
it does not disable project-local launchers. HERMES_HOME does not relocate these
project files. A tiny executed regression uses the actual pinned named dispatch
and launcher writer, replacing only acquisition/operation and external PATH
exposure boundaries. It produces two real launcher files and the predecessor's
complete source authentication refuses them. This proves the normal source
mechanism, not the unexported historical manifest or actual package installation.

## Producer, not consumer, reconstruction

After genuine public PM setup and contained build-state retirement, the hosted
producer creates one exclusive `/opt/seed/authenticated-core` from the original
public `/opt/inputs/hermes.tar`. It reconstructs the complete Git tree and literal
commit object, and authenticates the complete source manifest against the
unchanged public digest before replacing its exclusively created PM work tree.
It does not select/delete a list of unwanted source members or exclude launchers
from authentication. A bad archive/tree/commit/manifest fails before replacement.
No core pin changes, private installer, PM bypass or consumer normalization occur.
The legacy metadata-plan build remains disabled.

The producer records its actual pre-reconstruction manifest digest and up to 64
differing member identities in the existing cumulative command audit. It then
records and verifies the post-readability manifest and writes
`/opt/seed/core-source-manifest.json`. The success inventory carries both phase
reports and that manifest's digest. The final whole-seed readability pass is
followed by another complete authentication before success/commit. No candidate
selection, admission, facts, home or generation is baked into the reusable core.
Public tool/cache prerequisites remain separate and native consumers select
fresh contained state.

The extra reconstruction temporarily retains one additional complete public
source plus its Git objects, only on the disposable hosted VM. Streaming the
actual public Git archive locally yielded 16,870 authenticated leaves,
201,194,738 source bytes, and 2,200,165 canonical manifest bytes without extracting
or retaining the archive. These are source measurements, not an aggregate disk
fit guarantee. Existing container/tmpfs/export/retained inventory limits remain;
exhaustion is a real failure, never permission for a new local fixture family.

## Consumer authentication and evidence

Before copying the public seed, and again after `copytree(..., symlinks=True)`,
the non-root contained consumer authenticates the entire source against the
unchanged pinned digest. The seed manifest is only diagnostic comparison input:
it too must match that digest, so it cannot authorize polluted bytes.
Each phase exports an actual full hash/type/executable/symlink manifest and a
bounded exact difference report before rethrowing an identity failure:

- `consumer-seed-manifest.json` / `consumer-seed-identity.json`
- `consumer-copy-manifest.json` / `consumer-copy-identity.json`

These use the existing bounded flat export/archive/compact-evidence path.
Diagnostic export errors are secondary notes on the original authentication
failure. Evidence contains public paths/hashes, not source payloads or secrets.
No scan/import/install authority is inferred from a diagnostic file. The ordinary
native scanner also uses the shared complete manifest implementation, with its
unchanged error, digest and only `.git` / `__pycache__` exclusions.

Authentication bounds are 100,000 traversed members, 4,096 encoded path bytes,
256 MiB aggregate source bytes and 4 MiB canonical manifest bytes. Only regular
files, directories and symlinks are accepted; executable drift and symlink
retargeting count. Consumer manifests retain existing 8 MiB per-file / 32 MiB
aggregate export bounds. Difference reports retain true total/omitted counts
and at most 64 paths. No child, log, package or Docker isolation budget increases.

## Executable evidence and remaining gates

Six new mandatory `test_docker_core_identity.CoreIdentityTests` IDs cover actual
pinned named-dispatch launcher pollution; complete producer reconstruction and
bad-archive/local-guard refusals; mutation/addition/removal/mode/symlink drift;
actual consumer manifests before seed/copy refusal; member/byte/manifest/type
bounds and primary-error precedence; and streamed exact public archive identity.
Normal and optimized processes are required. All inherited tests/fixtures and
canonical IDs remain unchanged; no native core-copy fixture is allocated locally.

This is PRE_CI_SOURCE_REVIEW implementation evidence only. Actual corrected
exact-head hosted ordinary refusal, native install/enable/selected generation,
full canonical verification, cold/restart and all-mode owned cleanup remain
pending. Faolan owns fresh independent source/workflow review and meaningful
feature-only hosted continuation. Final same-card Gilfoyle and PR/human review
remain separate. No local Docker, acquisition, native force/admission, push/CI,
main integration, live installation, profile/service/storage or LAN effects are
performed by this implementation phase.
