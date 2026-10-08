# Hosted native-tool execution evidence

## Observed boundary and limits

Actual GitHub run `37720941089` on `5dd9fda7787283906449981815f1d20ba051f889`
reached genuine hosted native installation after complete authenticated public
source equality and the full native CAUTION scan. Installation reported:

    [Errno 13] Permission denied: /work/fixture/tools/uv-0.12.3-linux-x64/uv

The plugin was not published. Enable, selected-generation admission, full
canonical verification and cold/restart acceptance were not reached. Five
reached containers and the owned committed base had verified cleanup; this is
not all-mode feature acceptance. Actual tool/ancestor modes, effective kernel
mount flags and loader readback were absent. The historical cause is UNKNOWN;
EACCES alone does not establish noexec, mode, UID, loader or LSM denial.

Moby v28.0.4 `daemon/oci_linux.go`, `withMounts`, starts tmpfs options with
`noexec,nosuid,nodev,rprivate`, appends the supplied data and calls
`mount.MergeTmpfsOptions`. The issue-6 `/work` data omits both exec and noexec;
`/tmp` explicitly specifies noexec. This establishes a credible normal-source
mechanism, not actual historical kernel flags or a successful permission repair.
Docker HostConfig is intended input, not a substitute for kernel readback.

This successor is DIAGNOSTICS ONLY. The `/work` and `/tmp` option strings and
all isolation predicates remain byte-identical. It does not silently change
mounts, chmod/chown tools, invoke PM's healing selector, add capabilities, remount,
substitute /opt tools or broaden executable mounts. A later compatibility repair
must use actual evidence and preserve fixture-contained native execution.

## Native path and producer audit

Pinned Hermes remains `f42f579cf8bac4918ac9599bece71618afadd846`, tree
`008b644d38770b7de0835592ddaf19a708e2fa82`, complete source digest
`880bc1836050b055ecd47f08bcc3f25fc1392f824a170f93d07e2ae7e8705b96`.
Producer `docker/hosted_setup.py` uses normal named native `install python uv`,
authenticated tool archives, genuine verifier/member-union PM warming, then
rebuilds the entire authenticated source. `base_setup.readable_seed` preserves
executable bits while granting public prerequisites ordinary read/search access.
`docker_inside.prepare` copies tools with symlinks retained into fresh private
`/work/fixture/tools` and selects that root via HERMES_RUNTIME_DIR. Neither source
inspection nor those intended mode rules establish actual kernel execution.

Pinned `pm/environments.py:112-116` selects HERMES_RUNTIME_DIR;
`pm/install.py:83-130` selects the facts entry and native package binary.
That path calls `_heal_exec_bit` (`pm/install.py:70-80`), despite the read-only
wording on `installed_package`. Diagnostics deliberately do NOT call it.
Instead, actual native `Lockfile`, strict `Facts.installed`, `Store.entry` and
`get_package(name).binary` project the same current linux-x64 pin without writes,
fetches, verification probes or installs. Actual definitions place uv at `uv`
and Python at `bin/python3` (`pm/packages.py:189-230`). A stale version, target,
archive identity, different entry name, external store or escaping link does not
receive executable probe authority. Archive pin hashes and actual executable
hashes are distinct fields; one is not fabricated from the other.

## Incremental, bounded actual evidence

After full native scan/DANGEROUS refusal and hosted scope validation,
`docker_inside.hosted_install` runs the fixed verifier Python and
`scripts/native_tool_execution.py` before the unchanged genuine installer.
The child requires UID/GID 1000, the exact /work/fixture/runtime layout, hosted
context and complete core authentication before native imports. No arbitrary
command/path arguments are accepted.

The flat `tool-execution.json` is written incrementally with 0600 files using
the existing aggregate/count/atomic-replacement exporter bounds:

- Actual UID/effective UID/GID/effective GID and bounded supplementary groups.
- Relevant longest-prefix kernel mountinfo projections for /work, /tmp, /opt,
  /candidate and resolved binaries; statvfs flag values and readonly/nosuid/noexec
  predicates. Mount sources, roots, full mount tables and environment are omitted.
- Current public PM versions/target/archive pins, requested/resolved binary paths,
  lstat type/mode/UID/GID/device/inode and literal/resolved ancestor chains,
  symlink text and streamed stable-fd SHA-256/byte counts.
- Bounded ELF64 PT_INTERP metadata for system /lib or /lib64 loader paths, without
  reading or executing loader contents. This is metadata, not loader validity.
- Exactly one contained uv and one contained Python `--version` attempt under
  the existing owned process-group runner: shell-free, null stdin, inherited
  network denial, five seconds and 64 KiB each. Exit or actual errno, retained
  output count/hash and 2 KiB head/tail survive denial. Timeout/output-limit
  diagnostics mark output incomplete; zero captured bytes is not zero emitted
  bytes. No retry or alternate executable follows failure.

Limits are 128 KiB per report, 256 KiB/4096 input mountinfo rows, 32 path
components/groups and 128 MiB per streamed binary with 1 MiB working blocks.
Loader tables have at most 128 headers and loader text at most 4096 bytes.
Both selected tools and original installer remain in the same offline bounded
container; this is not a sandbox against same-UID fixture races. Resolved link,
fd/type/size/identity guards reject obvious escape/drift; they do not claim
atomic exec/hash identity against malicious same-UID mutation.

Tool metadata is persisted before exec. A probe error is evidence, not native
success, and does not suppress the real installer. A diagnostic collection/export
failure is secondary to actual installer failure. If install succeeds but
required diagnostic collection fails, the harness refuses before enable rather
than silently claiming complete evidence. Generic bounded Docker/compact export
already retains these flat files independently of result.json. No success-only
export dependency or receipt is introduced.

## Required regressions and remaining gates

Eight additive mandatory `tests/test_docker_tool_execution.py::ToolExecutionTests`
IDs cover actual pinned native read-only selection without acquisition/healing,
selection drift, tiny real contained ELF/link/hash/mode/EACCES, escapes/loops/
missing/FIFO/size/loader bounds, kernel mount projection versus intended input,
incremental pre-exec export/aggregate retention, real failed/output/deadline
children with unrelated-child survival, and primary installer failure despite
secondary diagnostics with unchanged mount/isolation contract. Tiny copied public
ELF/version outputs are labeled seams, never reported as uv/Python versions.
Normal and optimized processes are required. No inherited test bodies are edited.

The unchanged predecessor's installer seam retains a real EACCES child but lacks
the tool/kernel report (RED); the successor retains both (GREEN). This proves the
missing evidence repair, not the historical cause or actual hosted native success.
Actual corrected hosted evidence, install/enable/selected generation, full
canonical/cold/restart/all-mode cleanup and final independent same-card Gilfoyle
review remain mandatory. Faolan owns exact pre-CI source/workflow review and the
next meaningful feature-only hosted attempt. No local Docker, dependency
acquisition, admission/force, push, main integration or live installation occurs.

Primary sources:
- https://github.com/moby/moby/blob/v28.0.4/daemon/oci_linux.go
- https://docs.docker.com/engine/storage/tmpfs/
- https://man7.org/linux/man-pages/man2/execve.2.html
- https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html
