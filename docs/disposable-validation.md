# Disposable issue #6 validation

All pushes to main or feat/6-host-discovery and pull requests to main run one
`offline-verification` job on fresh GitHub-hosted Ubuntu 24.04. PR evidence binds
the checked-out merge artifact, not the head tip. Source-only review is not hosted
acceptance; changed bytes require fresh exact-artifact evidence and approval.

## Native lifecycle

1. Pinned checkout actions acquire the entire Atlas artifact and public Hermes
   commit `5645275e50d66dca04c9565634f9b5207a38aef5`, without persisted credentials.
2. `docker/validation.Dockerfile` provisions a conventional pinned Python 3.14.7
   image using ordinary APT and public PyPI. `requirements-test.txt` includes the
   exact PM runtime prerequisites: packaging 26.0, tomli-w 1.2.0, ruamel.yaml
   0.18.16 and truststore 0.10.4. No native selection enters an image layer.
3. A fresh UID1000 setup container runs `scripts/prepare_acceptance.py` ONLINE.
   It snapshots the full committed candidate and core, authenticates complete
   core/scanner bytes before imports, performs supported native install AND enable,
   and reads back installed bytes/tree, enabled selection and genuine PM
   generation/interpreter/recipe/lock hashes. One run-owned volume preserves
   that selection at unchanged absolute paths. There is no second offline install.
4. `scripts/disposable_validation.py verify` runs the admission controls and
   complete `python3 scripts/verify.py` in a network-none container with inherited
   socket denial. All remaining tests are discovered; none are filtered, skipped
   or marked xfail. Native tool/slash/CLI dispatch, nine synthetic host-method
   scenarios, three authorized synthetic aliases and fresh-process persistence/
   restart exercise the admitted plugin. The verifier pins pm/hermes_cli/tools
   import roots before temporary scanner fixtures; stale origins refuse.
5. A separate network-none cold container runs `scripts/docker_cold.py` with the
   SAME PM-selected interpreter/generation, validating selection, installed tree
   and registration without reinstalling or collecting. Exact candidate-bound
   canonical success and unchanged admission receipt are mandatory prerequisites.
6. Explicit workflow-wide `shell: bash` preserves failures through tee via
   GitHub's `bash --noprofile --norc -e -o pipefail {0}` template. No shell override
   or continue-on-error bypass exists. Compact actual scan/install/enable/admission,
   canonical and cold logs/readbacks are uploaded even on failure. Cleanup stops
   and removes only this run's three named containers, volume and image tag; no
   global prune, forced cleanup or cross-candidate state reuse occurs.

Containers run UID1000, cap-drop ALL, no-new-privileges, default seccomp/AppArmor,
2 CPUs, 6 GiB memory/no additional swap and 256 PIDs. Their image is read-only;
verification/cold also mount the admitted full core and plugin read-only using
volume subpaths. Only run-owned /state and a 64 MiB noexec/nosuid/nodev /tmp tmpfs
are mutable. There are no host homes, bind mounts, credentials, daemon sockets,
privileged modes or host namespaces. The job is capped at 60 minutes; owned
entry children are bounded to 30 minutes and their process groups are reaped.

## Admission and local consent

The hosted-only exception is explicit `--admission-mode hosted-ci-caution` in
this reviewed workflow. SAFE needs no force; CAUTION alone uses the supported
native force option after full scanning; DANGEROUS always refuses. Fresh fixture,
origin/ref/tree, default scan policy and nonreplacement checks remain required.
Environment strings are diagnostics, not an OS isolation boundary or operator
consent: a same-UID caller can forge them. Local/runtime force is prohibited.

The optional detached-signature confirmation route is INACTIVE by default. Its
small existing helper is retained because native setup imports it for complete
core/scanner authentication and explicit ordinary local consent. It is not a
signing-controller, CI gate or automatic approval: no trust anchor, real key or
approval is shipped. Candidate-controlled anchors, changed commit/tree/scope/
findings and dangerous verdicts refuse. A PTY alone cannot authorize install.
Synthetic confirmation/security regressions remain mandatory but are not native
admission or independent review. Missing native evidence makes publication fail
honestly, not pass with a substituted receipt.

## Coverage and review

H01–H12 and A01–A14 in the acceptance matrix retain policy, datagram-only ordinary
permission, <=4 strict TCP ports, TCP4403 exclusion, shared budgets, method/time
provenance, conservative identity/no-response semantics and profile authority.
The baseline main tests/assertions and genuine issue #6 tests remain. Obsolete
acquisition/packing/retention/measurement/controller code, its added tests/fixtures
and historical docs are removed together; archival Git history and private receipts
preserve them outside the merge payload. No product regression is removed.

Focused mandatory disposable tests exercise actual producer/tee failure, pinned
PM dependency alignment and real workspace TOML writing, cold-interpreter import
lifetime RED/GREEN, missing/stale canonical proof, native readback drift, fresh
setup/local refusal, actual owned-child failure/reaping and scoped cleanup. Normal
and actual -O source checks use only the retained interpreter, tiny packet-denied
fixtures and actionlint 1.7.7. Local full-core fixtures, Docker, downloads, new
environments and native admission are not authorized for source-only review.

The original card requests SAME-CARD Gilfoyle exact-SHA SOURCE-ONLY review of the
WHOLE main-to-candidate scope and safety. Faolan then owns a non-force update to
the existing draft PR #7, fresh hosted native/full-canonical/cold evidence, final
independent approval and human/CodeRabbit review. Old-SHA hosted approval is not
approval of this corrected artifact. Main integration, runtime enablement, LAN/SSH
collection and gateway changes remain separately gated and unperformed.
