# Native CAUTION admission: hosted CI exception and local consent

## Controlling scope

The reviewed issue-6 workflow has explicit operator approval for supported native
CAUTION force acceptance **only on fresh GitHub-hosted Ubuntu VMs**. This replaces
the inactive signing-controller CI plan: no signing-controller, deployed trust
anchor, real signing keys or per-commit signed CI consent is required. It does not
approve local/runtime force, persistent replacement, deployment, live collection,
publication of unreviewed bytes or main integration.

Hermes is pinned to f42f579cf8bac4918ac9599bece71618afadd846. Its unchanged
`plugin-guard-v8` scanner scans the entire committed plugin tree, including source,
docs, tests and harnesses, under ordinary native exclusions. SAFE proceeds without
force. CAUTION selects the supported `cmd_install(..., force=True)` option in the
approved hosted scope only. **DANGEROUS always refuses**, including with force or
signed approval. Native install scans again before publication; catalog/kill-list,
source trust and PM dependency admission are not disabled or overridden.

The force option also permits replacement in Hermes. Atlas therefore requires a
fresh marked fixture, exact isolated HOME/HERMES_HOME/TMPDIR, default scan/selection
config, contained exact public core/candidate snapshots, no existing installed
Atlas and no existing admission/enable receipt. No allow-removed, blanket yes,
subset archive, scanned-source rewrite or policy override is supplied.

## Hosted workflow and evidence

The approved [hosted-first continuation](hosted-first-docker.md) adds one INITIAL
feature-push `hosted-docker` job on a standard `ubuntu-24.04` x64 VM, 60 minutes,
with actual network-none/capability-dropped nonroot Docker native acceptance.
Its explicit diagnostics require push/feature/exact source/job/workspace/attempt1;
the container workspace is the real `/candidate` read-only bind. Environment
strings are not host-isolation proof. Main/PR regression contexts below remain
separate. First hosted authorization/invocation belongs to the delivery owner,
not this code builder, and no prior local-native/all-green requirement is invented
for the approved first-attempt exception. Final actual acceptance still must pass.

`.github/workflows/verify.yml` tests pushes to `main` and `feat/6-host-discovery`
and pull requests targeting `main`, with pinned actions and a fresh
`ubuntu-latest` hosted runner, top-level `contents: read` and checkout with
`persist-credentials: false`. It supplies no repository/environment secrets,
deployment credentials, PATs, tunnel or privileged candidate execution. Actual
hosted job identity/isolation and workflow permissions are the protected boundary;
GITHUB_ACTIONS/RUNNER_ENVIRONMENT strings are **not an OS isolation** or approval
proof. They are diagnostic guardrails against accidental local invocation, not a
sandbox against same-UID candidate code. Do not forge them to exercise force on a
server, self-hosted runner, LAN or runtime profile.

The workflow records checked-out full commit/tree and explicitly selects:

    python3 scripts/prepare_acceptance.py --hermes-source "$NETWORK_ATLAS_HERMES_ROOT" --admission-mode hosted-ci-caution

The parent and child require matching repository, job, event/ref, source SHA,
workspace and hosted-run diagnostics. Only the main/issue-6 feature push or PR
merge checkout is supported; unrelated branch/tag pushes, non-merge PR refs and
other events refuse. The workflow filters PR base branches; its checked-out merge
SHA/tree, not the contributor's branch tip, binds PR acceptance. This test context
does not authorize a main push/merge or runtime installation. No environment
variable automatically selects this mode.
The child authenticates the complete pinned public Hermes snapshot before importing
native code, requires the candidate's full tree to match the checked-out artifact,
scans the complete clean candidate and records every finding with
core/scanner/candidate identity in `ci-scan.json`. SAFE never selects force;
CAUTION alone does. Real native install/enable, complete installed tree readback,
PM selection and candidate-bound admission evidence remain mandatory. Acceptance
runs separately with inherited packet denial through installed native tool/slash/
CLI dispatch and restart; a mocked policy result is not an admission receipt.

The publisher must inspect the real exact-head hosted job, native setup/readback
and full canonical result after pushing the independently reviewed branch. Hosted
execution cannot be proven by this repository's local synthetic tests. Do not
require an actual hosted run before the publication owner can push an independently
reviewed branch; do require it before publication completion. Final cumulative
independent review and fixture archive/restore-tested retirement remain gates.

## Local/runtime route remains unchanged

Default `--admission-mode local` never passes force. Ordinary non-TTY CAUTION still
refuses; real local scratch admission needs fresh explicit exact-byte operator
consent after a full scan and the supported ordinary affirmative prompt. A previous
candidate's consent/receipt cannot admit a successor. Dependency consent and
native enabled-selection/PM checks remain ordinary. No live installation or
activation is authorized by test setup.

The prior detached SSH-signature transport remains **INACTIVE by default** as
historical optional regression code, not a required CI/provisioning/publication
gate. No signer/anchor/approval is shipped; real credentials are not shipped.
Its canonical request binds candidate commit/tree, complete pinned core/scanner
identity, all findings and an external scope. Missing/candidate-local authority,
byte/signature/scope mismatch, source drift and DANGEROUS refuse. A PTY only carries
one response after validated authority; it is not consent. Any future real use
still requires separate ordinary local authorization and protected external
invocation; its signature checker is not a replay ledger or same-UID isolation.
No external signing service or controller is deployed by the hosted exception.

## Executed regression contract and limitations

`REQUIRED_CI_ADMISSION_TESTS` mandates all ten tests in
`tests/test_ci_admission.py`: explicit mode/context; fresh contained nonreplacement
fixture; real full native CAUTION scan and supported force-policy selection; real
DANGEROUS scan refusal even with force; SAFE/no-force and candidate/core drift;
parsed hosted read-only/pinned/no-secret workflow; real entrypoint refusal for
local mode misuse, mixed consent and enable; origin/ref/config revalidation;
main/feature push and PR merge contract matching the parsed workflow; rejection
of unrelated branches/tags, malformed/non-merge refs and disallowed events.
Every install boundary in these tests is a mock; synthetic SAFE/CAUTION/DANGEROUS
controls also mock the expected checkout-tree mapping, while a real mismatch
refusal is tested separately. Real scanner policy is exercised,
not an actual force install on the server. Synthetic environment diagnostics are
never described as actual hosted execution.

All eight legacy `REQUIRED_CONFIRMATION_TESTS` remain canonical and run before
hosted setup: non-TTY refusal, missing/mismatched external authority, signed
DANGEROUS refusal, candidate/core drift and bounded ordinary prompt transport.
The synthetic signed CLI reaches the ordinary prompt but downstream PM
publication fails honestly under packet denial in its empty home. It leaves no
installed/enabled plugin or receipt; no changed repository bytes are admitted by
these regression tests. Synthetic signing keys are not authority. Local admission
consent is not independent feature approval or proof of GitHub CI.

Missing/stale final-candidate native admission still fails the canonical verifier.
Record real failures; obtain the separately bounded local-only consent decision
when needed. Do not force locally, reuse old receipts, weaken scanning or resurrect
the superseded mandatory controller gate. No live reachability, ICMP permission,
real SSH host key, production migration or runtime readiness is established here.
