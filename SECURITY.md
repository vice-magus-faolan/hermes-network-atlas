# Security boundaries

Network Atlas observes and remembers; it does not administer infrastructure.
V1 must enforce allowlisted named networks, authorized SSH aliases, fixed
read-only probes, strict host keys, bounded subprocess execution/output, and
transactional provenance/history. It is not a generic shell, vulnerability
scanner, or privileged network manager.

Native plugin code, the local operator, installed executables, and the operator's
SSH configuration are trusted. The plugin is not an OS sandbox for other Hermes
tools or same-UID processes. Remote output and discovered labels are untrusted.
An SSH allowlist restricts this plugin, not every ability of the agent account.
Sharing atlas state does not share profile-local inspection authority.

Configuration examples and fixtures are synthetic, never live authorization.
No live scan, SSH inspection, private device seeding, or plugin deployment is
part of repository bootstrap or default CI. Never attach a real atlas database,
private exports, SSH keys, passwords, tokens, or live config to a public issue.

For suspected security defects, do not publish exploit details or private
network data in an issue. Use GitHub private vulnerability reporting when the
repository offers it; otherwise contact a maintainer privately to arrange a
safe report. See docs/implementation-addendum.md for required negative tests
and the explicit SSH-config/local-user trust limitations.
