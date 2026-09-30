# Contributing

This project is licensed GPL-3.0-or-later. Read the original specification and
implementation addendum together before coding; the addendum resolves conflicts.
Keep V1 limited to phases 1–3. Prefer simple standard-library Python and small,
typed boundaries. Explain non-obvious intent and failure behavior.

Run `python3 scripts/verify.py`. Extend it when adding real plugin behavior so
that every delivered module is canonically tested. A bootstrap green check is
not implementation acceptance. Regression tests should prove the prior failure
where practical. Tests never use live network/device/config/credential data.

Use focused Conventional Commits on the declared lane, not main. Verify branch,
full SHA, clean state, and no competing writer before edits or review. Soft-warn
on cyclomatic complexity near 10; justify or refactor above 15. A builder cannot
approve its own artifact. Request native same-card review with the exact committed
SHA, tests, changed files, and residual risk; remediation stays on that card/lane.

Do not publish live atlas/config/exports, credentials, host-specific policy,
worker logs, or scratch state. Keep ignores surgical; future docs, fixtures, and
schemas must stay visible. Fixtures and example files are explicitly synthetic.
Do not add persistent services, arbitrary command/range interfaces, privilege
escalation, unreviewed dependencies, or fabricated topology.

Kanban coordinates component acceptance separately from local target integration,
public push/release, and runtime deployment. Do not push, merge main directly,
install/enable in a live Hermes home, scan real networks, inspect real SSH hosts,
change profiles, restart gateways, force-clean worktrees, or delete branches
without the corresponding explicit effect authorization.
