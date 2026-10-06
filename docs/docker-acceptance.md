# Disposable Docker acceptance

This is a local, opt-in acceptance harness, not a runtime deployment or hosted
GitHub runner. Its new Docker/native path must be exercised and independently
reviewed on the exact committed artifact before it is accepted. Packet-free
contract tests alone are not Docker, native admission, or full canonical proof.

Current blocker: the proposed legacy build path is not established as compatible
with the actual containerd image store. `preflight` and `build` now refuse that
backend before Docker mutations. A reviewed compatible bounded builder/cache
lifecycle is still required. Do not switch to the shared BuildKit cache or a
privileged/unconfined helper to bypass this refusal. This implementation is
incomplete, not an exercised Docker deliverable or feature approval.

## Authority and admission

Use the existing feature lane and one `atlas-docker` directory under the declared
`TMPDIR`. Do not allocate another heavyweight host admission root. A clean
committed candidate is required; candidate changes invalidate prior acceptance.
Before the first canary, independently review the exact host lifecycle bytes,
including endpoint, construction, mounts, labels, exports and cleanup. This
pre-canary review is not the later independent cumulative feature review.

Local Docker has ordinary native scanning/consent only. `accept` refuses a
non-TTY operator before container creation. A real foreground terminal carries
native prompts; no answer, local force flag, changed-byte consent, or hosted
diagnostic is synthesized. `refusal` runs the real noninteractive native
installer and must leave installation absent. DANGEROUS remains unconditional
refusal. Review the exact full scan and new container context before providing
any ordinary CAUTION confirmation. Old host fixture approval does not apply.

## Public inputs and reusable base

`docker/Dockerfile` pins the real linux/amd64 Python 3.14.7 manifest digest.
`docker/dependencies.json` declares public dependency inputs. The complete
public Hermes archive is pinned to
`f42f579cf8bac4918ac9599bece71618afadd846`; its PM lock pins Python and uv
artifacts and checksums. Apt uses a dated Debian snapshot. Python union
resolution still uses the pinned native PM and its actual public inputs; this
is not claimed to be a fully reproducible dependency build.

The context contains only the three committed recipe files and a public core
archive. It contains no candidate code, host `.git`, host environment, home,
profile, credential, or venv. The base retains public tools/core/cache and a
verifier environment, not a plugin installation, facts, selected native union,
CAUTION receipt, or previous admission. The base key depends on recipe/core/
dependency bytes, not candidate SHA. `base.json` records the actual image ID,
upstream digest, core commit and dependency inputs; actual package/cache
inventory is exported by the first genuine canary, not guessed from a recipe.

## Commands and modes

After exact-byte safety review and committing a clean candidate:

```sh
python3 scripts/docker_acceptance.py build --daemon <expected-local-daemon-ID> \
  --hermes-source <complete-public-pinned-core-checkout>
python3 scripts/docker_acceptance.py run --daemon <expected-local-daemon-ID> \
  --image sha256:<actual-owned-base-ID> --mode smoke
```

`build` is a separate public prerequisite acquisition phase. Runtime is always
Docker `network none`; the canonical verifier additionally uses its inherited
packet-denial layer. Other run modes are `fail`, `interrupt`, `refusal`, and
`accept`. Passing/failing/interrupted modes must be exercised on real Docker;
their expected exit codes are checked against actual exported outcomes.
`smoke` is explicitly not native admission or full canonical acceptance.
`accept` must yield fresh genuine native installation/enable/PM-selected UUID
generation, validate containment and run the unchanged complete canonical
verifier. Counts are parsed from actual discovery/result lines, with nonzero
exit, missing totals, disagreement and skips refused.

## Runtime layout and limits

The host binds a complete committed public candidate snapshot read-only at
`/candidate`; its small public shallow commit object is reconstructed locally,
not a mount of the host Git common directory. The separate private evidence
export directory is writable at `/export`. This bind preserves evidence when
Docker stops a container; a stopped container's tmpfs is not a durable export.
All fresh native home/config/plugins/install-state/UV cache and selected
interpreter/core paths reside inside the marked `/work/fixture`.

Native setup children use `TMPDIR=/work/fixture`. Canonical receipt validation
and fixture-root checks use `TMPDIR=/work`, with the marked fixture strictly
below it. The selected interpreter must resolve inside that fixture; an external
`/opt` symlink does not qualify. Tools/core/cache are copied to valid contained
paths, then native PM creates/selects its fresh union. Cache reuse does not
establish that union duplication disappeared; real usage must be exported.

Runtime UID/GID are 1000:1000, cap-drop ALL, no-new-privileges, init, read-only
root, private IPC, network none, no ports/socket/devices/host namespaces or
unconfined flags. The declared scratch is 2 GiB `/work` tmpfs plus 64 MiB `/tmp`.
Memory/swap limits both equal 3 GiB (no extra container swap), CPU is 2, PID limit
256, logs 4 MiB, operation deadline 900 seconds. Export parsing limits flat files
to 64 members/32 MiB. Export write-side bounds and peak usage need genuine
canary verification; do not infer a filesystem quota from a parsing limit.
Tmpfs consumes real RAM and can cause OOM; it is not free storage.

The local daemon is rootful: host daemon access is effectively powerful. This
wrapper is not an OS sandbox against a malicious agent holding that access.
Explicit unix endpoint and expected daemon ID are checked; ambient Docker
redirection is refused, and no host Docker credential/config is inherited.

## Storage and teardown

Budget conservatively against `/var/lib/containerd`, not the larger
DockerRootDir filesystem: external containerd/snapshotter image storage uses
the former here. The preliminary build preflight requires 2 GiB construction
headroom plus a 512 MiB unrelated-host reserve. This is an envelope to verify,
not measured proof that all build peaks fit. The recipe refuses public
prerequisites above 1 GiB. Storage mapping, actual peak and failure residue
must be verified before claiming the bounded build works. Do not migrate or
restart daemons, grant privilege, or prune unrelated resources to make it fit.

One active attempt is enforced by a nonblocking lease and stable name. Exact
commit/tree/image/daemon/ownership labels and immutable IDs are read back before
cleanup; mismatches are preserved and refused. Cleanup runs on success,
failure, interruption and export error. Original errors are retained, cleanup
failure is separately surfaced, and container absence is read back.

Retain compact identity/inspection/scan/receipt/log/hash/outcome evidence before
removal, and a consistent synthetic SQLite backup when produced. At most eight
attempt evidence directories and 256 MiB retained evidence are admitted; cap
exhaustion refuses another attempt, never erases audits automatically. Retained
review/publication consumers must end before explicit owned retirement. The
current implementation refuses a second owned base; predecessor rotation and
build-residue retirement require verified consumer/ID handling, not global
prune or blind deletion. Inspect all owned build residue on failure.

## Distinct gates

Docker smoke/refusal/contract evidence does not replace the complete native
canonical result. Container policy also does not prove the host kernel's ICMP
ping-socket permission: keep any required minimal packet-free host check
explicit, without live packets/helper/raw socket/capability grants. Historical
accepted host checks are historical evidence, not new-artifact admission.

Final cumulative independent review, publisher-owned actual exact-head hosted
CI and PR review remain separate gates. No builder push, integration to main,
profile modification, live enable/reload, LAN/SSH scan or deployment is implied.
