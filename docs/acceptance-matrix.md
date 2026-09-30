# Acceptance matrix

All entries below are implementation requirements, not bootstrap completion
claims. Tests use synthetic fixtures and isolated homes by default.

Phase 2 implementation evidence is indexed in [Local Discovery](local-discovery.md):
tests/test_discovery.py and tests/test_discovery_extra.py exercise A03/A07/A08/A10,
with actual native dispatch and fresh-process replay in tests/test_runtime.py.
These milestone checks do not claim A09/A13 or full PM-managed A01 completion.

- **A01 Native plugin**: supported install/enable, discovery, schemas, actual
  tool invocation, and operator commands under a temporary Hermes home.
- **A02 Persistence**: reopen/fresh process retains IDs, facts, relations,
  observation history, access evidence, and map output without discovery.
- **A03 Config/authorization**: malformed/out-of-policy CIDRs, excessive ranges,
  disabled modes, unknown options, and unauthorized SSH aliases fail closed.
- **A04 Identity**: MAC survives address change; interface/device distinction;
  IP/name collisions do not force merges; alias identity and ambiguous matches.
- **A05 Provenance**: field-specific precedence; conflicts retained; operator
  attestation cannot be forged through tools; inference explanation preserved.
- **A06 Update/query**: authorized operator changes versus inference; parameterized
  bounded queries do no collection; alias association cannot grant SSH permission.
- **A07 Reconciliation**: new/changed/unchanged/missing/conflicting, stale threshold,
  reappearance, retired persistence, failed/partial scans, idempotent event history.
- **A08 Bounds**: fixed argv, no command/option/SQL injection; time/output/operation
  limits, owned child cleanup, missing optional dependencies, IPv4 scan cap.
- **A09 SSH**: strict host keys, noninteractive, no forwarding/LocalCommand/multiplex
  reuse/sudo; only fixed read-only probes; invalid target and parser/command failures.
- **A10 Atomicity**: rollback, concurrent writers, restart, busy timeout, schema
  version handling, transaction/events consistency; subprocess outside write locks.
- **A11 Rendering**: deterministic Markdown/Mermaid, escaping hostile text, stale
  visibility, only supported edges, isolated nodes, fixed safe export destinations.
- **A12 Profiles**: profile-aware homes; explicit shared atlas reads; separate
  inspection policy; no implicit authority transfer and no other-profile mutation.
- **A13 End to end**: three synthetic aliases, bounded collection, inspection,
  reconciliation, change/conflict/absence answers, maps, then restart/re-query.
- **A14 Operator docs**: supported installation, config, dependency failures,
  source meaning, trust boundaries, direct user updates, safety, examples, and
  explicit distinction between isolated acceptance and unperformed live validation.
- **A15 Repository delivery**: exact independent approval, passing canonical
  checks on target, final artifact ancestry, clean checkout, guarded cleanup,
  later external publication kept behind an operator approval gate.

The cumulative card must provide paths/tests covering every ID, run the canonical
verifier, and identify residual or unperformed live checks without claiming V1
activation. Reviewer completion is not evidence of integration/publication.
