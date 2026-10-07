# Public bootstrap permission contract

## Current contract: normal hosted provisioning, strict candidate acceptance

The active task supersedes the earlier source-only/per-attempt approval restrictions:
use Docker on disposable GitHub-hosted Ubuntu runners, not heavyweight local
fixtures. The public-only UID/GID 0:0 bootstrap now uses Docker's standard default
capabilities. No cap-add/drop override, privileged mode, SYS_ADMIN, host namespaces,
host homes/credentials/socket, seccomp/AppArmor disabling or deployment access.
No-new-privileges, private namespaces, fixed readonly public inputs, finite
CPU/memory/PID/deadline/log limits and authenticated pinned sources remain.

The standard set is CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, SETGID, SETUID,
SETPCAP, NET_BIND_SERVICE, NET_RAW, SYS_CHROOT, MKNOD, AUDIT_WRITE and SETFCAP.
These are provisioning defaults, not grants to Atlas discovery or permission to
send probe packets. In particular, CHOWN/DAC_OVERRIDE/FOWNER/FSETID provide normal
package ownership/access/mode operations; SETUID/SETGID support ordinary package
identity operations. The actual process must have exactly the standard effective,
permitted and bounding mask, zero inherited/ambient masks, NNP=1 and seccomp=2.
Root identity and container diagnostics are checked before apt/source/tool/PM
effects, including direct apt and warm dispatch. Actual process diagnostics are
retained in inventory and independently checked by the host before rootfs commit.
Host create/inspect refuses any capability override,
privileged/unconfined configuration, host namespace, extra mount/device or port.

`require_bootstrap_contract()` now admits only the fixed hosted feature job with
exact source/workspace/run diagnostics before scratch/daemon/archive/pull effects.
Those strings and /.dockerenv are accidental-use guards, not isolation against
malicious same-UID code. The reviewed workflow/ephemeral VM is the trust boundary.
No package/source pin changes, authentication bypass, statoverride, skipped
maintainer script or fake configuration. The disabled legacy metadata-plan path
is not rearmed. Candidate acceptance remains UID/GID 1000:1000, cap-drop ALL,
no-new-privileges, read-only, network-none and inherited packet denial.

Builder hands off committed PRE_CI_SOURCE_REVIEW; Faolan owns independent source/
workflow review, scoped non-force publication and meaningful corrected CI runs
under standing authority. Repository concurrency serializes/coalesces runs without
cancelling active cleanup. No local Docker, acquisition or new native fixtures.
Actual exact-head native/canonical/cold/cleanup evidence and final same-card
Gilfoyle review are still required; preliminary source review is not acceptance.

## Retained failure observation versus source-derived cause

The following records the earlier capless attempt; it is not a claim that the
corrected standard-provisioning candidate has already executed on a hosted VM.

The retained hosted stopped state shows an exited, non-OOM bootstrap with exit 1.
Its log shows apt package downloads denied at
`/var/cache/apt/archives/partial/*.deb` and chmod of `partial` denied. It does not
show that directory's UID/GID/mode. A pre-existing directory owned by another UID
is a plausible explanation, not an observed ownership fact. The package index
phase completed far enough for apt to select a closure; that is not proof of a
successful package installation. Inventory/provenance files were not produced.

The Debian apt 2.6.1 reference source's `SetupAPTPartialDirectory` only attempts
chown when `APT::Sandbox::User` is not root; root sandbox selection does not repair
existing foreign-owned directories. It still attempts chmod, then downloads into
that directory. Root without DAC/FOWNER capabilities cannot ignore ownership or
access failures. Fresh fixed root-owned index/cache/partial directories could
address acquisition permission in a future reviewed repair without a privilege
grant, but cannot establish the rest of the contract. No speculative chmod or
acquisition-path change is presented here as a functioning fix.

There is a decisive later incompatibility: the snapshot-selected
`openssh-client` version `1:9.2p1-2+deb12u10` runs its `configure` maintainer script
under `set -e`. `set_ssh_agent_permissions` creates `_ssh` if needed, then (absent
an existing dpkg statoverride) runs `chgrp _ssh /usr/bin/ssh-agent` and
`chmod 2755 /usr/bin/ssh-agent`. The bootstrap specifies GID 0 with no supplemental
`_ssh` group and no capabilities. It cannot change the file to an unrelated group;
setting the intended setgid bit also has capability/group constraints. No
statoverride, forced non-root dpkg option, script omission or fake successful
configuration is allowed as a workaround. Dpkg's normal archive extraction also
sets owners/groups/modes; fixing download permissions does not bypass this layer.
This is a source-derived incompatibility, not a claim that a subsequent hosted
installation was executed and failed at that line.

## Historical capless phase audit

The original audit below remains evidence of the incompatible capless recipe.
The current contract changes only hosted bootstrap capabilities and admission
guards, not package/source pins, authentication, scripts, export/cleanup or
candidate containment. Current apt/dpkg/PM/cache sufficiency must be observed in
the real hosted run, not inferred from mock fixtures or one source-derived blocker.

| Phase and fixed paths | Required behavior and containment | Audit outcome |
| --- | --- | --- |
| Public input / upstream | Exact Python 3.14.7 linux/amd64 image digest, exact Hermes commit/tree, fixed public recipe inputs; only readonly `/opt/inputs`, no candidate/host Git/home/credential/socket | Pins and create/readback predicates preserved. No image/layer acquisition or live rootfs inspection in source-only repair. |
| Apt sources / authentication | Only dated Debian snapshot and packaged archive keyring; signature/index/package hashes enabled, root acquisition sandbox, no retries or recommendations | Existing source/authentication options retained behind unconditional gate. `Check-Valid-Until: no` is the existing historical-snapshot choice, not permission to disable signatures. |
| Index/cache/archive paths | `/var/lib/apt/lists`, partial/auxfiles/locks, `/var/cache/apt/archives`, partial/locks; acquisition must write, chmod and rename under ordinary ownership | Observed archive-partial denial; exact original ownership unknown. Root sandbox is not an ownership repair. No live apt operation or guessed root-cache success. |
| Dpkg unpack/configure/triggers | `/var/lib/dpkg`, installed `/usr`, `/etc`, `/var` files, alternatives/groups and package-defined ownership/modes must remain genuine | Dpkg reference source performs fchown/fchmod and chown/lchown. Exact selected SSH postinst requires nonzero group ownership; incompatible with present capless contract. Full archive member ownership/maintainer closure is not inspected from payloads or claimed verified. |
| Git / SSH / CA readiness | Fixed `git`, `openssh-client`, `ca-certificates` roots, ordinary transitive dependencies; Git reconstructs exact complete public source, SSH executes no live connection | Failed apt log selects Git 1:2.39.5-0+deb12u3 and SSH above; CA already at 20250419~deb12u1. No Git/SSH installation or final TLS/readiness proof. Existing CA statement does not prove every future trigger's compatibility. |
| Public source | Data-filtered full archive under `/opt/seed/hermes-source`; reconstruct literal commit object/tree, no candidate editing or host Git copying | Data filter discards archive ownership metadata. Reconstruction uses ordinary owned local Git writes. Unchanged source logic, blocked before execution. |
| Setup identity / native tool phase | Isolated `/opt/seed/user`, `/opt/seed/hermes`, `/opt/seed/tools`; native `pm.cli install python uv --tools-only` authenticates literal public lock and tool archives | Pinned PM extracts with its data filter, publishes store entries/facts and executable modes using ordinary owned files. No tool payload or PM installation was executed. No optional tools/source expansion or trust-recorded shortcut. |
| Verifier wheels | Binary-only PyPI dry-run; genuine report/index URL/hash/size match; finite authenticated wheels; ordinary native offline build at `/opt/verifier` | Existing validation/bounds retained, no new resolver, wheel or package payload. The base Python and PM-selected build Python are distinct prerequisites, not fake environments. |
| Member-union prewarm | Dependency-input manifest only; real native sync/admission, resolved lock and selected interpreter package inventory | PM-owned home/install-generation/cache writes require writable ordinary state. No candidate/admission receipt is created in this phase. Actual complete union/cache sufficiency remains unproved. |
| Reusable handoff | Retain only public core/tool facts/cache/verifier; move UV cache, remove setup home/member/user and compatibility selector; exclude admission/native selection files | Pinned PM cache/home/store APIs and recipe cleanup/readable-seed calls inspected. Root-owned data-filtered files can be normalized for non-root read/search without chown. No live reusable seed, relocation/cold-cache proof or inherited admission is asserted. |
| Stopped base | Exited zero, no OOM/start error; complete success inventory/provenance before rootfs commit; exact owned image labels/layer lineage and USER 1000:1000 | Failed stopped state is checked before success-only exports. A verified stopped successful base remains mandatory; never blindly delete an image from a guessed/returned-but-unverified ID. |
| Acceptance | UID/GID 1000:1000, readonly base/source, private bounded work/tmp, network none, capability drop/no-new-privileges; inherited packet denial before native install/enable | Unchanged. Fresh contained copies, genuine complete scans, DANGEROUS refusal, PM-selected generation, full canonical/restart/cold proof all remain required. Mocked exporter/state tests do not prove these effects. |

## Failure evidence contract

The controller first interprets the actual stopped state. Nonzero exit, OOM,
start error, running or non-exited state is the primary setup failure, before any
success-only copy or commit. Export re-inspects exact owned immutable identity
after stopping, then writes `stopped.json` before attempting `bootstrap.log`.
Logging remains `local/max-size=4m/max-file=1/compress=false`; bounds are unchanged.

The fixed failure-stage members are `inventory.json`, `resolved-union.lock`,
`verifier-resolution.json` and `union-packages.json`. Each is independently read
through the bounded Docker archive seam. `export-members.json` distinguishes
`present` (with actual SHA256), `missing` (only the exact Docker absent-file
response) and `error` (permission, transport, malformed archive, wrong member or
bound/write failure). A failed setup may lack these success-stage files; it is
not promoted to success. A successful setup requires every member and retained
logs/state. Legacy disabled builder exports retain their inventory-only contract.
A failed diagnostic/log export itself fails export; unexamined files are not
invented or called present/missing.

Secondary export, owned cleanup, cleanup-evidence write and final host-diagnostic
errors remain separate, with notes on the original exception where needed.
Cleanup still checks exact container/image ownership/identity and reads absence
back. No record means no authority for blind image removal. Unexpected ownership,
resource or cleanup drift remains failed/incomplete evidence, not permission for
prune or retry. Upstream image retirement and whole VM disposal are separate from
owned-bootstrap removal.

## Verification and next decision

Required `BootstrapRepairTests` are discovered by both `scripts/check_docker.py`
and the unchanged full `scripts/verify.py` path, alongside every historical test
and manifest ID. They test actual production entrypoints/export/error seams with
small synthetic regular tar members and packet denial, in normal and optimized
processes. No Docker daemon, apt/dpkg install, source/tool/wheel payload acquisition,
real root setup or native admission is used. A previous receipt-selected Python
can bootstrap tests only; missing fresh admission remains a canonical failure.
The complete unchanged workflow must still pass the pinned validator.

The conservative branch estimate for the new `export_seed_members` boundary is
11: a fixed at-most-four-member loop deliberately isolates each export failure,
then separately enforces setup-success completeness. This soft warning is kept
visible and covered by missing/error/malformed/all-present cases; no new/changed
function exceeds 15. Original higher-warning functions are not refactored here.

The three historical pre-effect regression IDs now enforce real local/non-hosted
refusal rather than the superseded unconditional stop. Every primary-failure,
missing-member, error/ownership, cleanup and diagnostic regression remains.
Additional mandatory tests cover the standard capability golden mask and drift,
root/container/NNP/seccomp guard, normal authenticated apt invocation and actual
controller/export/commit/readback ordering through tiny mocked boundaries. Missing
or malformed exported process proof refuses before commit and still performs
owned cleanup. These tests do not claim an actual apt installation. The pre-CI
handoff does not require missing local admission fixtures; those mandatory local
canonical failures stay honest until real exact-head hosted evidence resolves them.
No automatic unchanged-source retry, local Docker or local/runtime force.

## Public source references

- [Selected SSH maintainer script](https://sources.debian.org/data/main/o/openssh/1:9.2p1-2+deb12u10/debian/openssh-client.postinst)
- [Apt 2.6.1 acquisition reference](https://github.com/Debian/apt/blob/2.6.1/apt-pkg/acquire.cc)
- [Dpkg 1.21.22 archive reference](https://github.com/guillemj/dpkg/blob/1.21.22/src/main/archives.c)
- [Linux chown permission rules](https://man7.org/linux/man-pages/man2/chown.2.html)
- [Linux capability rules](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Docker default runtime capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [Pinned native PM](https://github.com/NousResearch/hermes-agent/tree/f42f579cf8bac4918ac9599bece71618afadd846/pm)

The apt/dpkg reference versions are source audits, not an unobserved installed
version inventory. Bounded source text/metadata retrieval is not package payload
acquisition or authentication of a complete executable dependency closure.
