# Disposable issue #6 validation

This is the active CI delivery contract, replacing the retained-producer repair
chain. All push-to-main, push-to-feat/6-host-discovery and pull-request-to-main
artifacts run the same `offline-verification` job on fresh GitHub-hosted Ubuntu
24.04. PR evidence binds the checked-out merge artifact, not the head tip.

## Small native lifecycle

1. Pinned checkout actions acquire the complete Atlas artifact and public Hermes
   commit `5645275e50d66dca04c9565634f9b5207a38aef5`. Credentials are not persisted.
2. `docker/validation.Dockerfile` uses the unchanged authenticated Python
   3.14.7 linux/amd64 base digest. Ordinary signed APT and public PyPI provisioning
   run online with Docker defaults; no unsigned-package/trusted-host bypass.
   Its image contains public source and verifier prerequisites, not native
   selections, plugin admission, operator homes, credentials or a daemon socket.
3. The ordinary UID1000 setup container invokes existing
   `scripts/prepare_acceptance.py --admission-mode hosted-ci-caution` ONLINE.
   This snapshots the entire committed candidate and pinned core, authenticates
   full core/scanner bytes before imports, runs full native scanning, supported
   install and supported ONLINE enable, then reads real installed bytes/tree and
   native PM selection/generation/recipe/lock hashes. SAFE needs no force;
   CAUTION alone may use the supported hosted exception; DANGEROUS refuses.
4. One fresh Docker-owned named volume keeps that very installation at unchanged
   absolute paths. `scripts/disposable_validation.py verify` runs the admission
   controls and complete `python3 scripts/verify.py` with network:none and inherited
   socket denial. Every product, authorization, provenance, budget, transport and
   historical harness regression remains discovered. Native tool/slash/CLI
   dispatch, nine synthetic host-method scenarios, the three-alias scenario and
   fresh-process persistence/restart run through the real installed plugin.
   Before discovery the verifier binds `pm`, `hermes_cli` and `tools` package roots
   to the configured pinned core (commit/tree, relevant source diff and import
   origins checked). It does not reset caches, rewrite modules or change admission.
5. A SEPARATE cold network-none container uses the SAME selected native interpreter
   and `scripts/docker_cold.py`, checking genuine generation/installed bytes and
   registration without reinstalling, resolving dependencies or collecting.
   Canonical success and unchanged native receipt are prerequisites.
6. Explicit workflow-wide `shell: bash` uses GitHub's `bash --noprofile --norc -e
   -o pipefail {0}` template: a failing Docker producer cannot be masked by tee.
   No job/step shell override or continue-on-error bypass exists on any event path.
   Ordinary CI logs retain actual exits/output. Compact setup/enable/scan/admission,
   canonical and cold evidence is uploaded, including on failure. Cleanup stops
   and removes only this run's three named containers, its volume and its image
   tag. No global prune, daemon changes, forced cleanup or reused candidate state.

The source image is read-only during setup/testing. Standard volume-subpath
read-only mounts also protect the admitted fixture's full core and installed
plugin during verification/cold runs; synthetic Atlas state remains writable.
Only `/state` and a 64 MiB
noexec/nosuid/nodev `/tmp` tmpfs are mutable. Native state and synthetic SQLite
fixtures live in the owned volume, never a host bind mount. Containers run UID1000,
cap-drop ALL, no-new-privileges, default seccomp/AppArmor, 2 CPUs, 6 GiB memory/no
additional swap and 256 PIDs. The job is capped at 60 minutes; each owned entry
child is bounded to 30 minutes and its process group is reaped. Provisioning uses
the disposable hosted builder's ordinary resource limits; no privileged build or
host PID/network/security-profile override is used. Git ownership is ordinary
UID1000, not a broad safe.directory exception.

A stopped setup container retains the same volume for compact native evidence
readback before scoped cleanup. Failed steps stay failed; a missing native receipt,
canonical success or cold result is not inferred from source tests or image build.
Hosted run `37864339897` is NOT acceptance despite its provider success status.
Native online install/enable and installed candidate identity genuinely passed;
canonical reported `Ran 444 tests ... FAILED (errors=8)` and exited 1. Cold then
refused the missing `canonical-complete.json`. Implicit bash -e pipelines hid both
failures behind tee. The eight observed errors were missing pinned PM modules/native
API; the hosted log did not record those packages' import origins. Source tracing
identifies a lifetime hazard: scanner-policy tests load native packages from a
temporary core snapshot which their class cleanup deletes. A cold interpreter
reproduction of that actual pinned import path imports the
actual pinned `plugins_cmd`, removes only a tiny source-path alias and reproduces
`No module named 'pm.cli'`; sys.path insertion alone does not repair cached __path__.
Binding package roots before tests fixes that lifetime boundary without changing
inherited tests or their assertions. Corrected exact-head HOSTED native/full-
canonical/cold proof is still UNPERFORMED, not inferred from local regressions.

Hosted run `37870601979` correctly failed canonical and skipped cold: all 493
tests ran, with two pinned PM workspace errors importing `packaging`. Native
online install/enable and pinned package origins passed; cleanup completed.
`requirements-test.txt` now declares `packaging==26.0`, matching the unchanged
core application declaration and `pm/pyproject.toml` / `pm/uv.lock`; the existing
Dockerfile installs this verifier prerequisite online. The additive mandatory
`test_disposable_dependencies` regression checks declaration/lock alignment,
Dockerfile consumption and the actual PM requirement-parser import site. Local
availability is not clean-image proof: corrected hosted full-canonical/cold
acceptance remains pending. No native/core/base pin or interpreter choice changes.

Hosted run `37874270081` then ran all 494 tests and failed the same two workspace
paths at the actual pinned `pm/workspace.py:129` import of `tomli_w`; cold was
correctly skipped and owned cleanup succeeded. The test requirements now include
the COMPLETE unchanged four-package PM runtime declaration/lock: packaging26.0,
tomli-w1.2.0, ruamel.yaml0.18.16 and truststore0.10.4. Two additive mandatory
dependency regressions check every exact declaration against the PM lock and
Docker requirements, and execute the actual pinned workspace TOML writer with
tiny synthetic inputs and no acquisition. The existing packaging test body,
Dockerfile, native setup, interpreter selection and all inherited coverage remain
unchanged. Hermes-owned imports and optional interactive `prompt_toolkit` are not
extra PyPI prerequisites for these paths. Cached local availability does not prove
a clean image: actual corrected hosted native/full-canonical/cold remains pending.

## Acceptance checklist

The twelve H01–H12 rows in `docs/acceptance-matrix.md` map every public issue #6
criterion to exact product tests. The feature audit retains policy/compatibility,
ordinary datagram-only permission diagnostics, sensitive TCP4403 exclusion,
combined resource bounds, method/time/address evidence, profile-local authority,
conservative identity/no-response semantics and restart. No product transport
change is required by this CI correction.

New mandatory `tests/test_disposable_validation.py` covers the sole event path,
unchanged pins, online-once/same-volume lifecycle, offline/non-root/resource flags,
pre-effect local refusal, full canonical dispatch, stale-selection/cold refusal,
primary error evidence, fresh-volume refusal, real tiny owned-child exit/reaping,
and scoped cleanup/artifact paths. These tests do not run Docker or native admission.
Three additive mandatory `tests/test_disposable_failure.py` IDs execute the real
failing-producer/tee shell (including the old false-green control), cold -S actual
pinned PM import RED/GREEN and stale-origin refusal, and a real failed canonical
child which cannot publish success proof or start cold execution. The import test
uses existing dependencies without .pth/bootstrap and only a tiny temporary path
alias to read-only core source, not a new environment or full-core copy. Normal
and actual -O are required. All inherited test files/assertions remain unchanged
in this bounded correction; native admission and the same owned volume are unchanged.

Local source review uses ONLY the retained interpreter/cache, packet-denied tiny
fixtures and retained actionlint 1.7.7. No local downloads, new environments,
full-core fixtures, Docker, native admission, live policy/stores or service changes.
Full canonical success is required HOSTED; missing local admission remains an
honest failure, not a reason to skip tests or fake a receipt.

## Explicit retirement and test changes

Superseded ACTIVE requirements: producer-only tool/cache closure, fresh offline
installation, image-commit/readback controller, Git-only retained representation,
packing measurement, 1 GiB retained seed and 2 GiB reconstruction. These are not
increased ceilings or historical successes; they no longer govern this conventional
Docker path. Product limits and native security/admission semantics are unchanged.

Retained historical source: `docker/Dockerfile`, acquisition/base/hosted setup,
APT/Git/retention helpers and dependencies/measurement anchor; scripts
`docker_acceptance`, `docker_contract`, `docker_inside`, `docker_builder`,
`docker_evidence`, `docker_snapshot`, `docker_cold`, `check_docker`, `hosted_docker`,
`hosted_contract`, `hosted_evidence`, `measurement_route`, `packing_measurement`,
`core_representation`, `native_tool_execution` and `native_union_diagnostics`.
Their retired controllers are not called by active CI. `docker_cold` is reused
only for its existing real native selection/registration readback. Complete
core identity, offline guard, setup/readback and admission helpers remain active.
Historical test bodies/JSON fixtures and their limits remain intact except FOUR
workflow-contract methods directly affected by the approved routing change:

- `test_ci_admission.test_reviewed_workflow_hosted_readonly_pins_no_secrets_or_privileged_event`:
  Ubuntu latest -> fixed Ubuntu24.04; security/action/permission checks unchanged.
- `test_ci_admission.test_workflow_runner_context_scratch_initialized_at_step_then_persisted`:
  host pip setup -> actual owned-name/evidence initialization plus Dockerfile pip
  assertion. Still executes quoted shell initialization with space-containing paths.
- `test_hosted_docker.test_workflow_single_initial_vm_job_pins_permissions_and_step_context`:
  split feature/fallback jobs -> one unconditional Docker job; pinned/context/
  no-secret/always-upload assertions retained.
- `test_docker_measurement.test_feature_phase_gates_measurement_separately_from_native_acceptance`:
  mutually exclusive measurement routing -> explicit absence of that routing and
  retained controllers. The remaining marker/packing/refusal tests are unchanged.

All original test IDs and required IDs remain; new IDs are additive. No test skip
or removed product assertion makes the new path green. Historical documents for
that superseded harness remain useful provenance, not present acceptance:
`docker-acceptance`, `hosted-first-docker`, `docker-acquisition-plan`,
`bootstrap-permission-contract`, `native-pm-contract-audit`,
`committed-image-readback`, `container-identity-readback`, `snapshot-startup-contract`,
`complete-core-identity`, `native-tool-execution`, `native-union-cache-diagnostics`,
`native-offline-consumer`, `producer-git-preparation`, `producer-retention`,
`hosted-packing-measurement`, and `core-retained-representation` (all under docs).

## Review/publication boundaries

This lane commits source and requests SAME-CARD Gilfoyle exact-SHA preliminary
security/correctness/workflow review. That handoff does not need unavailable local
native admission and does not certify feature delivery. Faolan owns the reviewed
feature-only non-force push and actual hosted execution. Final exact-head
native/canonical/cold evidence and Gilfoyle approval precede one unmerged PR to main
and requested jabez007/CodeRabbit feedback. Main/runtime/live activation stay
untouched; no new task/reviewer family or automatic repair chain is introduced.
