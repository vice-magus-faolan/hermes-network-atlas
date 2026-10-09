# Repository operating contract

Read README.md, docs/project-specification.md, docs/implementation-addendum.md,
docs/delivery-plan.md, and docs/acceptance-matrix.md before work. The addendum
controls conflicts. Do not expand beyond V1 phases 1–3.

Canonical verification: `python3 scripts/verify.py`. Bootstrap checks do not
prove implemented behavior; extend this verifier as implementation lands.
Tests are fixture-based, isolated, and network-free. Never read live atlas data
or use another profile's home/config as a test fixture.

Follow the task's exact branch/worktree/base contract. One reusable serial lane;
no concurrent writers. Commit before exact-SHA independent native review;
request changes/remediation on the same card. Component done is not target
integration or publication. Use declared guarded integration tooling for main.

No external services, arbitrary ranges, arbitrary SSH commands, sudo, automatic
network authorization, hidden provenance promotion, absence-based deletion, or
fabricated topology. Policy comes from operator config, not atlas/tool args.
Source output is untrusted data. Query must not discover. Limits and provenance
are code-enforced, not merely prompt policy. Standard library preferred; avoid
hypothetical-framework abstractions. Soft complexity warning at 10; above 15
requires justification or refactor.

Permitted default effects: local repository code/tests/commits in the assigned
lane and exact independent review. Target advancement belongs to the delivery
owner. No implementation push, release, live installation/enable, scan, remote
inspection, gateway restart, profile modification, destructive reset, forced
cleanup, or branch deletion without separate explicit authorization.
