# Disposable Docker acceptance

This is a local, opt-in acceptance harness, not a runtime deployment or hosted
GitHub runner. Its new Docker/native path must be exercised and independently
reviewed on the exact committed artifact before it is accepted. Packet-free
contract tests alone are not Docker, native admission, or full canonical proof.

Code-only remediation replaces the legacy builder with one owned bootstrap
container and stopped-rootfs commit. No Dockerfile builder, BuildKit, cache
fallback or provisioning change is selected. First execution is still blocked:
the public artifact metadata is incomplete, so no finite expansion/peak fit is
proved, and exact-byte pre-canary review plus explicit root-inside-container
setup authority are still required. Contract tests are not those permissions.
This is not an exercised Docker deliverable or feature approval.

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

`docker/Dockerfile` is a declarative upstream identity anchor, not an executable
build recipe or fallback. It pins the linux/amd64 Python 3.14.7 manifest digest.
`docker/dependencies.json` declares public dependency inputs. The complete
public Hermes archive is pinned to
`f42f579cf8bac4918ac9599bece71618afadd846`; its PM lock pins Python and uv
artifacts and checksums. Apt package/index closure must be resolved from the
dated Debian snapshot before effects. Only fixed length/hash public artifacts
may be acquired; redirects are checked, proxies are not inherited, and every
download is deadline/length/hash bounded. Package installation and native PM
run only after inherited syscall network denial. The offline resolver must
really succeed; no mocked resolution, fabricated cache or fallback is allowed.

The context contains the seven fixed committed public recipe/guard/core archive
inputs declared in `scripts/docker_builder.py`, plus their reviewed acquisition
plan. It contains no candidate code, host `.git`, host environment, home,
profile, credential, or venv. The base retains public tools/core/cache and a
verifier environment, not a plugin installation, candidate/source-scoped facts,
selected native union, CAUTION receipt or previous admission. Authentic public
tool-entry manifests are prerequisites, not native admission evidence. The base
key depends on recipe/core/dependency/acquisition-plan bytes, not candidate SHA.
The public archive and its literal public commit object reconstruct a one-commit
core Git identity; no host Git common directory is copied or mounted.
The input bind at `/opt/inputs` stays read-only: Docker commit excludes it, while
retained core/tools/cache/verifier and inventory are in ordinary rootfs. No
privileged unmount or mutable mount configuration is used. Exact stopped-state
inventory, labels/config/rootfs and immutable image readback are mandatory.

## Commands and modes

Proposed invocation ONLY after a resolved reviewed acquisition plan, exact-byte
pre-canary safety review and separate foreground setup permission:

```sh
python3 scripts/docker_acceptance.py build --daemon <expected-local-daemon-ID> \
  --hermes-source <complete-public-pinned-core-checkout> \
  --plan <reviewed-complete-public-acquisition-plan> \
  --registry <durable-default-profile-registry>
python3 scripts/docker_acceptance.py run --daemon <expected-local-daemon-ID> \
  --image sha256:<actual-owned-base-ID> --mode smoke \
  --registry <durable-default-profile-registry>
```

`build` refuses nonforeground operation before daemon access. Bootstrap has
stable name `network-atlas-bootstrap`, UID/GID 0:0 inside its private container,
bridge egress only for bounded public acquisition, cap-drop ALL, no-new-privileges,
default seccomp/AppArmor, no ports/devices/socket/host namespace/restart or added
capabilities. CPU/memory/PID/log limits match runtime; setup deadline is 1800s.
Apt/dpkg under those constraints is unproven. A permission/syscall failure stops
for a narrow decision; it never relaxes capability or security flags. Its rootfs
must be stopped and successful before commit; final USER is 1000:1000.

Runtime is always
Docker `network none`; the canonical verifier additionally uses its inherited
packet-denial layer. Other run modes are `fail`, `interrupt`, `refusal`, and
`accept`. Passing/failing/interrupted modes must be exercised on real Docker;
their expected exit codes are checked against actual exported outcomes.
`smoke` is explicitly not native admission or full canonical acceptance.
`accept` must yield fresh genuine native installation/enable/PM-selected UUID
generation, validate containment and run the complete canonical
verifier. Counts are parsed from actual discovery/result lines, with nonzero
exit, missing totals, disagreement and skips refused. Before canonical tests,
`scripts/docker_cold.py` starts a fresh selected-generation consumer and binds
interpreter prefix, source facts, installed complete commit/tree, enabled config
and actual host-inspected image. It registers native tools/slash/CLI without
collection. Old fixtures/interpreters can bootstrap synthetic tests only.

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
256, logs 4 MiB, operation deadline 900 seconds. Flat evidence is capped at 64
members, 8 MiB per file and 32 MiB aggregate including tar block padding.
Write-side bounds cover exact serialized bytes, copies, overwrite overlap,
logs and consistent synthetic SQLite backups BEFORE writes. SQLite reserves its
full file ceiling, aborts on growth and publishes atomically. Export errors are
separate from original errors. These are cooperative application bounds, not a
quota on the writable host bind or a sandbox against malicious test code.
Tmpfs consumes real RAM and can cause OOM; it is not free storage.

The local daemon is rootful: host daemon access is effectively powerful. This
wrapper is not an OS sandbox against a malicious agent holding that access.
Explicit unix endpoint and expected daemon ID are checked; ambient Docker
redirection is refused, and no host Docker credential/config is inherited.

## Storage and teardown

Budget conservatively against `/var/lib/containerd`, not the larger
DockerRootDir filesystem: external containerd/snapshotter image storage uses
the former here. See `docs/docker-acquisition-plan.md`: unknown artifact lengths,
counts, closures or expansion bounds refuse before effects. The conservative
declared peak counts compressed/staging/PM-partial duplication, unpacked parent,
working/commit blobs/retained snapshot overlap and per-member filesystem
overhead, PLUS 512 MiB untouched unrelated-host reserve. No fixed 2 GiB envelope
or final image.Size is a fit proof. Sampled free-space minimum adds observability
and abort protection, not a hard quota. The recipe additionally refuses public
prerequisites above 1 GiB. Storage mapping, actual peak and failure residue
must be verified before claiming the bounded build works. Do not migrate or
restart daemons, grant privilege, or prune unrelated resources to make it fit.

One active attempt is enforced by nonblocking controller AND durable-registry
leases and stable names. Exact
commit/tree/image/daemon/ownership labels and immutable IDs are read back before
cleanup; mismatches are preserved and refused. Cleanup runs on success,
failure, interruption and export error. Original errors are retained, cleanup
failure is separately surfaced, and container absence is read back.

Retain compact identity/inspection/scan/receipt/log/hash/outcome evidence before
removal, and a consistent synthetic SQLite backup when produced. At most eight
attempt evidence directories and 256 MiB retained evidence are admitted; cap
exhaustion refuses another attempt, never erases audits automatically. Retained
review/publication consumers must end before explicit owned retirement. The
durable default-profile registry ends in `.hermes/network-atlas/docker-acceptance`,
is private, explicit and outside the prunable controller scratch. It records
base/upstream/image identities, bootstrap residue, consumers, retained evidence
and last-consumer disposition. It is not inferred from active-profile HOME.
No live registry/image is created by unit tests. The implementation refuses a
second owned base or stale registered bootstrap; predecessor rotation and
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
