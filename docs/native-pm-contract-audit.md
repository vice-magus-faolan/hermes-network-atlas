# Pinned native PM contract audit

## Observed defect and narrow repair

GitHub run `37628525414`, attempt 1, job `112816449150`, checked out
`731ac1ce20e05fc644c54f4722806d91d8da8693`. Actual APT proof completed
(two signed index/list records, 27 acquired archives, 124 installed identities).
The subsequent native command `python -m pm.cli install python uv --tools-only`
failed with the pinned CLI's incompatible-flags message. Native acceptance was
not reached. These facts do not revise the preceding failed runs or establish
later provisioning, cold-cache or cleanup success.

The unchanged public core is `f42f579cf8bac4918ac9599bece71618afadd846`, tree
`008b644d38770b7de0835592ddaf19a708e2fa82`. In that source:

- `pm/cli.py:267-294` rejects names/extras/target with `--tools-only`.
- `pm/cli.py:343-408` implements two DISTINCT valid paths: named installs
  install the requested tools and do not sync a venv; nameless `--tools-only`
  installs the default tool closure, activates it, and installs optional defaults.
- `pm/registry.py:53-66,159-176` computes those roots/dependencies. Walking the
  explicit Python/uv roots yields exactly Python/uv. The nameless closure also
  includes node/npm/ffmpeg/ripgrep, and `pm/defaults.py:61-89` selects the optional
  agent-browser/cua-driver defaults (including browser dependencies).

The correction is `python -m pm.cli install python uv`, NOT a nameless
`--tools-only` request. It preserves the original authenticated two-tool seed
and verification; it does not expand acquisition to unrelated default tools.
No `--trust-recorded`, target staging, alternate installer, lock changes or
fabricated installed facts. The identical invalid argv in the execution-disabled
legacy recipe is repaired too; its independent execution guard remains closed.

## All native PM boundaries in the hosted path

Coordinates below refer to the unchanged pinned core, not the latest upstream.
All installation/build/publication effects below remain hosted-only. The
lightweight contract tests bind signatures or intercept effect boundaries;
they do NOT execute these effects or certify usable offline closures.

| Candidate boundary | Actual pinned source contract | Guards, effects and remaining proof |
| --- | --- | --- |
| `docker/hosted_setup.py::fetch_tools`, `Store(SEED/tools)`, `install_lock`, `scratch`, `fetch_many(artifacts, scratch, progress=...)` | `pm/store.py:349-350,363-403,406-412,436-450` | Hosted/root/process guard precedes import. Native lock/scratch and finalized hash-verified download publication; unchanged lock URLs/hashes. Bounded progress and parent child deadline/output. Actual archive hashes are retained BEFORE normal install removes fetch entries. No live/local acquisition. |
| Native `pm.cli install python uv` | Parser `pm/cli.py:794-814`; flag predicate `267-294`; dispatch `343-408`; tool install `238-262`; native release `pm/install.py:244,386,419` | Named dispatch verifies tools (`verify=True`), no default closure/venv sync. Python launcher publication uses `create=False`. Normal named-package opt-back-in bookkeeping belongs only to isolated setup state. Real installation/verification/cache release remains a runner gate. |
| CLI manager-runtime routing (implicit in native commands) | `pm/cli.py:849-867`; `pm/runtime.py:216-253,271-274` | Real PM dispatch may first prepare its independent manager runtime with pinned Python/uv and PM dependency lock. Candidate does not spoof runtime readiness. Setup home/cache remain isolated; actual runtime build and offline cache sufficiency are not proven by parser interception. |
| Verifier `pm.build_env --out /opt/verifier --wheelhouse ... --offline --requirement ...` | `pm/build_env.py:13-61,90-94`; facade `pm/__init__.py:27-32`; `pm/client.py:387-398`; engine `pm/build_operations.py:65-94` | Actual parser passes the explicit sequence/out/wheelhouse/offline/explicit contract. Genuine pip report/public-index hashes precede this call. Native build refuses an existing destination, disables indexes/source builds for wheelhouse builds and cleans its exclusively claimed failed output. No local build. |
| `Members([SEED/dependency-input])`, `pm.sync_venv(explicit=True, plugins=..., project_root=CORE)` | `pm/plugin_inputs.py:13-18,42-50`; facade `pm/__init__.py:27-32`; client `pm/client.py:205-232`; engine `pm/install.py:739-807` | Guard precedes PM import. Explicit Members bypass config discovery, NOT PM resolution/admission. Foreign-project routing retains project_root. Real union recipe, resolver lock, receipt and generation are produced by native PM, never manually synthesized. |
| Warm union `runtime_facts_path(CORE)`, `selected_venv(CORE)` | `pm/environments.py:49-50,162-205` | Source/home-scoped facts and committed generation; broken selection fails rather than falling back silently. Resolved lock must remain under seed. Actual selected interpreter inventories its distributions; cold relocation remains unproven until hosted. |
| `scripts/native_install.py`, real `plugins_cmd.cmd_install(file_uri, enable=False, ref=...)`; hosted CAUTION force only | `hermes_cli/plugins_cmd_install.py:424-482`; `scripts/ci_admission.py` unchanged | Full native scan/catalog/source/kill-list/PM publication remain intact; no `allow_removed`/`no_deps` bypass. Exact contained candidate/core/hosted identity checked. CAUTION-only standing hosted policy is not local/runtime permission. Actual installed tree readback required. |
| Real `plugins_cmd.cmd_enable('network-atlas')` and narrow dependency consent | `hermes_cli/plugins_cmd.py:636-686`; dependency prompt `hermes_cli/plugins_cmd_install.py:84-120`; `hermes_cli/plugins_admission.py:50-80` | Ordinary exact PM prompt only; enable submits `Selection` to explicit native sync, not an application-written selection. Full union/config/environment transaction, offline cache and non-root/capless containment remain actual runner gates. |
| `scripts/native_install.py::readback`, `scripts/docker_cold.py::check_selection`, `scripts/cumulative_acceptance.py::NativeAtlas` | `pm/environments.py:49-50,162-220` | Bind source-scoped facts, selected/committed generation and `venv_python`; cold process checks real prefix/executable/config/installed tree. These read APIs create no state. Readbacks and restart/canonical execution cannot be replaced by signature tests. |

## Executed contracts, diagnostics and acceptance limits

`tests/test_docker_pm.py::NativePMContractTests` requires the actual pinned core
commit/tree and unchanged tracked PM source. It executes the native parser and
flag predicate on the candidate's ACTUAL argv expression. The original named
`--tools-only` request is rejected before install/lock dispatch; the corrected
named argv passes. Real `cmd_install` control flow is exercised with the install
and bookkeeping boundaries intercepted: only Python/uv, verification enabled,
no activation, input stamping, venv sync or optional default install. Pure native
registry/default functions prove why simply removing names would expand scope.
The actual build-env parser routes production argv into a signature-validated
public build API boundary; Members encoding and every used PM/readback/install/
enable signature are checked without invoking installation. All eight IDs are
mandatory in `scripts/verify.py`; both normal and optimized processes are used.

Public prerequisite commands now print started and terminal JSON diagnostics to
the existing bounded `bootstrap.log`: actual argv, phase, exit, elapsed time,
output byte count/hash, and at most 32 KiB head/tail output with explicit
truncation. The existing child capture remains capped at 4 MiB with a 900-second
deadline and owned-process-group reaping. Diagnostic failure never replaces a
primary command exception. Nonzero exits raise a bounded exit-code summary, never
the captured output; no exception cause reintroduces raw output in traceback.
Started/terminal JSON is limited to 1 MiB encoded bytes per wrapper process and
32 commands. Bounded argv (64 tokens, 8 KiB encoded started row) and a reserved
256 KiB terminal row are checked BEFORE spawn. Reservation accounts for worst-case
sixfold JSON escaping of the 32 KiB head/tail plus argv/metadata. Exhaustion refuses
before emitting a new started row or launching a child; evidence is never silently
dropped. Actual row bytes (including newline) consume the budget before emission,
even if the stream write fails. Nested wrapper output remains captured/bounded
by its parent's command audit; the root aggregate leaves ample traceback headroom
under the UNCHANGED 4 MiB bootstrap exporter. It is not an OS write quota.

Four additional mandatory `CommandLogTests` execute a real near-4-MiB failed child
with an uncaught wrapper traceback through the actual aggregate reader and
production exporter (synthetic daemon only), repeated failed hostile-output rows
to cumulative refusal, metadata/count pre-effect refusal, and real failure with
broken terminal emission. Real hashes/counts/head-tail/exit and primary tracebacks
survive in normal/-O; no package/Docker/native effects are exercised. Existing
APT incremental proof/export and complete success-only inventory remain mandatory.

A parser/dispatch/signature pass cannot establish PM archive usability, actual
manager/verifier/union installation, native admission/enable, exact selected
runtime, full canonical suite, cold/restart behavior or owned Docker cleanup.
These must execute on the reviewed exact successor on disposable GitHub Actions.
Local missing-admission tests continue to fail honestly. PRE_CI_SOURCE_REVIEW
is only the implementation handoff; final native Gilfoyle review and publisher
acceptance still follow actual hosted evidence. No additional operator-consent
relay is needed for routine reviewed fixes under the standing contract.
