# Prospective exact-artifact native CAUTION confirmation

## Status and authority

This route is **INACTIVE by default**. It implements and tests a prospective
human-gated confirmation transport, not installation consent, GitHub security
consent, CI activation, a deployed trust anchor or final feature acceptance.
The existing workflow deliberately supplies no approval inputs. Its non-TTY
native setup still refuses a CAUTION artifact. A previous local fixture's consent
and receipt do not approve successor bytes or unattended CI. Green unit tests
cannot release the publication gate.

Hermes is pinned to f42f579cf8bac4918ac9599bece71618afadd846. Its unchanged
`plugin-guard-v8` scanner scans the complete committed plugin tree, including
source, docs, tests and harnesses, under its ordinary exclusions. SAFE uses the
existing ordinary route. CAUTION requires explicit confirmation. DANGEROUS always
refuses, including with a valid signature. No force, catalog-reviewed label,
scanner rewrite, trust-policy change, subset scan or automatic generic yes exists.

## Selected approval transport and trust boundary

The proposed transport is an OpenSSH detached SSH signature (`ssh-keygen -Y`),
namespace `network-atlas-native-caution-v1`, over canonical JSON bytes. The
operator's externally managed allowed-signers file and an explicitly selected
signer principal are the trust anchor; they are **not shipped** in this repository.
There is no repository private key, deployed public key, default signer, bundled
approval, boolean consent flag or environment-variable activation.

The request binds all of:

- the final original full 40-character candidate commit and complete Git tree;
- the exact Hermes commit/tree, complete public core source-member digest,
  scanner version and byte hashes of the scanner,
  context/pattern engine and ordinary native installer;
- every full-tree finding (pattern, severity, category, relative file, line,
  match and description), deterministically sorted, and the native verdict;
- the ordinary pending CAUTION decision and an exact externally selected scope.

Volatile scan time, clone directory/name and report summary are not signed:
changing them must not make the same immutable tree into a different artifact.
Findings themselves and complete commit/tree identities are signed. Local scratch
consent and CI consent require **separate scopes and signatures**. A CI scope must
identify the owner/repository, exact workflow/launcher identity, intended ref,
run/attempt and scratch-only install/enable effect; an external controller must
select and enforce that scope. Local scope must identify its single authorized
disposable setup invocation/effect and owner-selected nonce; record its generated
fixture root. The controller must enforce run/nonce consumption, not reuse a signed
scope for a different invocation. The signature checker alone is not a replay
ledger. Never let candidate files choose scope, principal or trust anchor.

Approval, detached signature and allowed-signers paths must resolve outside the
candidate worktree, public core source and disposable admission root. Missing
inputs, partial input sets, oversized inputs, candidate-local authority (including
symlinks into it), modified request bytes, wrong key/principal/namespace and any
commit/tree/scope/scanner/finding mismatch fail closed. The checker accepts only
canonical request bytes, not a generic approval object or self-asserted label.

Path separation alone is **not** isolation. Candidate-controlled workflow code
can select a different anchor, modify writable files or bypass a checker under
its UID. Therefore activation requires an **operator-owned launcher/controller
outside the candidate repository**, pinned to the independently reviewed helper
bytes, with a protected read-only anchor and fixed scope/principal. It must verify
candidate/helper/core identities before executing candidate-controlled code.
No secrets/anchors may be exposed to a pull-request job; a candidate-authored
workflow cannot be its own approving controller. An isolated trusted controller
may stage the approved immutable tree and invoke the ordinary scratch setup;
packet-denied acceptance then runs separately. This trust boundary must be
provisioned and reviewed by the owner before activation, not inferred from a
workflow name, a manual dispatch, environment approval or a PTY. The code is not
an OS sandbox for malicious native plugins or concurrent same-UID writers.

## Prospective operator sequence — not permission to execute

1. Commit and independently inspect the full cumulative candidate. In a trusted
   scanner-only process, generate a request with no installation or network effects:

       python3 scripts/caution_confirmation.py --hermes-source <exact-public-core-source> --candidate <clean-committed-candidate> --scope <externally-selected-exact-scope> > <outside-candidate-request.json>

   The command installs inherited packet denial, checks pinned scanner/installer
   bytes, checks clean tracked/untracked candidate state and scans the full tree.
   It emits exact canonical bytes without a trailing newline. Re-run separately
   for each intended local/CI scope. An operator must inspect the actual findings,
   not merely approve a hash or a candidate-generated file.

2. Obtain new explicit operator consent for those exact final commit/tree bytes,
   scanner identity/full findings and each effect scope. Outside the candidate,
   the authorized signer can sign the unchanged canonical request using the
   namespace above. The implementation never generates a real signer, acquires
   credentials or signs on the operator's behalf. Synthetic test keys are not
   authority and must never be deployed. External approval is also not independent
   Gilfoyle code-review approval: both gates remain necessary.

3. Only after separate owner authorization and provisioning of the trusted
   launcher/anchor, that launcher can supply all five explicit optional setup
   inputs (no defaults):

       python3 scripts/prepare_acceptance.py --hermes-source <exact-public-core-Git-checkout> --approval <external-request.json> --approval-signature <external-request.json.sig> --allowed-signers <external-read-only-anchor> --signer <externally-selected-principal> --confirmation-scope <same-exact-scope>

   Setup archives the entire committed candidate and exact public core. The
   parent and child independently rescan/check the exact signed request. Only
   after child validation is a request-bound marker emitted. The parent allocates
   a PTY purely to carry one affirmative response to the unchanged ordinary native
   CAUTION prompt. A PTY alone, missing marker or another prompt cannot authorize
   confirmation. Log size/deadline failures kill/reap only the owned child group.
   Native install scans its full immutable clone again, with no overrides; enable
   and declared dependency consent/PM publication remain ordinary supported paths.

4. Read back real installed bytes/full tree, selected generation, config/locks and
   candidate-bound admission evidence. Run genuine canonical packet-denied native
   dispatch/restart acceptance on the admitted final candidate, then request final
   independent cumulative exact-SHA review. CI setup/admission and exact-head checks
   must also actually pass after separately authorized activation. Do not reuse an
   older admission receipt, equate local success to CI, or fabricate a successor
   receipt. Keep fixtures for remaining consumers; retirement is separately gated.

## Executed regression contract and remaining gates

`tests/test_caution_confirmation.py` uses generated synthetic keys in isolated
scratch directories, not credentials or live profile state. It archives the exact
public Hermes Git checkout and invokes unchanged native scan/CLI entrypoints
under inherited socket denial. It proves real CAUTION plus non-TTY refusal,
missing/mismatched/candidate-local authority refusal, altered bytes/scanner
refusal, signed DANGEROUS refusal and ordinary CAUTION prompt confirmation from
synthetic authority. A separate synthetic prompt child proves bounded successful
transport; unknown prompts, absent marker and output/deadline exhaustion refuse.

The real signed synthetic CLI test reaches the ordinary affirmative prompt but
its subsequent native PM publication fails honestly: the isolated empty home has
no admitted toolchain, and packet denial prevents dependency acquisition. It
must leave no installed/enabled plugin or admission receipt. This test is **not**
a successful native install/enable, and no changed repository bytes are installed
by these regressions. Fresh real final-candidate admission/canonical acceptance
remains required after explicit consent. The eight critical confirmation tests
are mandatory canonical IDs and also run before default CI setup. Tests do not
provision GitHub environments/secrets/protections, deploy trust, change Hermes
policy/source/profile settings, grant privileges, collect packets or activate CI.

Before delivery can resume, the owner must approve final local and CI consent
scopes after full scan, separately authorize/provision the external trust boundary
and run actual native admission/CI acceptance. Until then the implementation
card is blocked, final independent approval is absent and publication stays gated.
