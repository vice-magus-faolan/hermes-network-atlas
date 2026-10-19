# Contributor instructions

Read README.md, CONTRIBUTING.md, SECURITY.md, and the relevant feature guide in
docs/ before changing behavior.

Canonical verification: `python3 -m pytest -q` on stock supported Hermes.
See CONTRIBUTING.md for dependencies and the Docker verification commands.
Native installer tests resolve dependencies online; application tests use
isolated synthetic fixtures and deny network access. Never use live atlas data,
homes, configuration, or credentials as fixtures. Add behavioral regression
coverage for changed behavior; documentation checks do not prove runtime behavior.

Prefer simple standard-library Python, small typed boundaries, and focused
Conventional Commits. Explain non-obvious intent and failure behavior. Avoid
abstractions for hypothetical integrations. Soft-warn on cyclomatic complexity
near 10; justify or refactor above 15. Keep documentation aligned with behavior.
