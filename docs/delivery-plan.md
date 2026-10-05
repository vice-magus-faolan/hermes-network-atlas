# Delivery plan

## Outcome

Give Hermes durable structured answers about known network devices, provenance,
authorized inspection, changes, and supported topology without another service.
V1 delivery means reviewed code on the declared integration target plus passing
isolated acceptance evidence. It does not mean live installation or LAN scanning.

## Serial feature lane

The native Hermes board is the coordination authority. The initial implementation
root owns one task-associated branch/worktree. Subsequent component cards reuse
it after parent approval and a clean/no-writer preflight. Native same-card review
routes k3rn3l artifacts to Gilfoyle; remediation returns to k3rn3l on the same card.
Exact commit SHAs, tests, risks, and verdicts belong in immutable run handoffs.

1. **Contract and harness**: ratify the addendum's per-field precedence,
   provenance/permission path, batch schema, ceilings, shared-store semantics,
   and compatibility. Add the normal native plugin scaffold and make the
   canonical verifier test actual behavior. Independent review gates Phase 1.
2. **Phase 1 — Atlas Core**: schema/migrations, transactional history/events,
   config validation, identity, source selection, operator/inference updates,
   read-only query, deterministic map/exports, and synthetic manual seeding.
3. **Phase 2 — Local Discovery**: fixed bounded passive/Nmap adapters,
   observation batches, deterministic/idempotent reconciliation, freshness,
   conflicts, partial failures, and evidence-qualified absence.
4. **Phase 3 — SSH Inspection**: authorized fixed read-only probes, strict
   transport bounds, per-profile authorization, access evidence, and failures.
5. **Cumulative V1 acceptance**: complete operator commands, docs, fixture clean
   install/restart acceptance, current Hermes registration, and negative matrix.
6. **Local delivery**: integrate the final exact reviewed artifact through the
   configured guarded target-advance path, rerun canonical verification on the
   target, reconcile board/repository, and safely clean eligible worktrees.
7. **Later publication**: separate approval-gated task for the implementation
   push. A bootstrap push is not authorization for future pushes or releases.

Phase 4 integrations and optional automatic context injection stay out of this
queue. Runtime deployment/live-network validation is a separate future decision.

Issue #6 uses a separate serial host-only lane: staged policy/capability contract,
then bounded ICMP/TCP transport, then cumulative safety/native acceptance and
operator docs. Each stage requires same-card independent exact-SHA approval
before the next starts; component approval is not main integration/publication.
The reviewed-branch PR-only publication owner is separate. No main advancement,
runtime promotion or live probes are implied. See host-discovery-policy.md.

## Gates

Seed every card behind an inert construction gate before any can run. Verify
idempotency keys, exact edges, worktree lineage, reviewer policy, and dry-run.
Release only the first serial root after construction; actual spawn may wait
behind host-wide WIP. Keep later publication behind an inert operator approval
parent in addition to local-delivery dependencies.

## Verification contract

```sh
python3 scripts/verify.py
```

At bootstrap this verifies only repository contract tests. The first component
must extend the same command for implemented code, isolated Hermes integration,
and negative tests. Subsequent modules must be represented in that verifier in
the same change that introduces them. No passing status may disguise omitted
plugin tests. Complexity: soft warning near 10, justify/refactor above 15 unless
an explicit tighter repo rule applies. Standard-library Python is preferred;
declare necessary dependencies through supported native plugin packaging.
