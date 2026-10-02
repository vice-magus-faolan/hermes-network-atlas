# Scaffold verification and compatibility

Historical contract/scaffold milestone evidence. Phase 1 now implements the
applying CLI, persistence, query and map surfaces; see [Atlas Core](atlas-core.md).
The validation-only descriptions below record the original parent artifact, not
the current runtime behavior. For current supported PM install/enable, the
candidate-bound fixture and cumulative verification, use operator-guide.md.
All remaining-gate statements below are historical scaffold evidence only.

This is the contract/harness milestone, not a functional persistent atlas or a
release. No live install, profile mutation, scan, SSH, or gateway restart is part
of verification. Native plugin code and the local operator are trusted.

## Prerequisites

- Python >=3.11,<3.15; actual local evidence uses Python 3.14.7.
- Real Hermes source/API: tested exact commit
  f42f579cf8bac4918ac9599bece71618afadd846 (v0.21.4 canary).
- Its admitted dependencies. Atlas uses ruamel.yaml>=0.18.16,<0.19; declared in
  plugin.yaml, matching the inspected runtime's installed 0.18.16 pin.
- An existing local scratch directory in TMPDIR. Tests never fall back to /tmp.

Use an already-admitted compatible Hermes Python environment read-only, or prepare
an isolated development environment outside production. Set PATH so python3 is
that environment's interpreter, and NETWORK_ATLAS_HERMES_ROOT to the verified
Hermes source root (unless hermes_cli is already importable). No test reads a live
Hermes profile config/atlas or copies a profile home. Requirements-test.txt is a
small native-loader test dependency subset, not a full Hermes environment and
not a substitute for plugin admission. Setup may download dependencies; tests
remain network-free. Missing dependencies/runtime/scratch make checks FAIL.

Do not run pip against a production Hermes interpreter. On current Hermes,
plugin.yaml python_dependencies are surfaced at discovery and admitted via native
PM/install/enable flows; declaring them does not silently install them. The CI
workflow checks out the exact inspected Hermes commit and prepares only a disposable
verifier runtime at this historical milestone. Current CI additionally prepares
supported isolated native admission before socket-denied verification. Changes to
that pin or dependency admission require review.

## Commands

After those prerequisites are set:

```sh
python3 -m unittest discover -s tests -p 'test_boundaries.py' -v
python3 -m unittest discover -s tests -p 'test_runtime.py' -v
python3 scripts/verify.py
```

Canonical checks include bootstrap contracts, implemented config/provenance/tools/
commands, and three actual native-loader subprocess cases (valid, invalid, disabled).
The native smoke creates a fresh synthetic scratch home, installs source as
plugins/network-atlas/plugin.yaml and __init__.py plus sibling modules, and uses
explicit plugins.enabled configuration for the native opt-in selector. It invokes
real Hermes discovery, tool definitions, scoped dispatch, slash commands, and the
native CLI registration's argparse setup/handler; it then tests config revocation
and native unload. No fake registry or origin attestation mocks are used. An audit
hook refuses socket connect/bind/DNS calls. Subprocess environment contains no
operator credentials or session/profile environment. Bootstrap and PM are NOT
imported, preventing runtime activation/repair as a test side effect.

Runtime records are printed by canonical tests as real JSON evidence. Success is
not a full Hermes chat/provider/transport acceptance run or native PM admission.
The fresh process proves discovery boundaries, not persistent restart behavior.
The source copy and explicit opt-in fixture test are supported directory-plugin
behavior. The `hermes plugins install/enable` command cycle (which publishes
managed dependency selections) remains REQUIRED isolated A01 acceptance later;
these tests must not be presented as proof of that command cycle.

## Surfaces shipped now

- network_query accepts exactly {"view":"status"}; reads policy readiness only,
  never inventory or collection. It says persistence_available=false and
  collection_available=false. Authorized aliases mean ONLY current local policy,
  not that any inspection succeeded or a host is reachable.
- network_update validates a bounded proposal with device_id, field, value, and
  explanation. Receipts are inference/inferred, applied=false, persisted=false.
  Unknown arguments, retirement, permission edits, and caller source claims fail.
- /network status reports the same readiness; /network update refuses because
  the inspected slash API passes only raw text, not operator-origin attestation.
- The equivalent local operator CLI registered through ctx.register_cli_command
  is `hermes network-atlas validate-update --device-id <existing-id> --field
  <field> --value-json <scalar-json>`. It creates user/user_supplied validation
  receipts itself, not by accepting a source argument. Retired requires a boolean.
  This milestone does NOT persist or apply it. Atlas Core must consume the same
  validated path in audited transactions and supply an applying update command.

The local CLI is a trusted-operator convention outside Atlas's model tool
surface, NOT human cryptographic attestation or a same-UID sandbox. Other tools
and local processes may invoke it; they are outside Atlas's isolation promise.

## Operator policy example (synthetic, not live authorization)

The profile-local file is get_hermes_home()/network-atlas/config.yaml. It is separate
from Hermes's plugins.enabled selector and cannot be edited by Atlas tools.
No file means empty allowlists; an existing empty/malformed file fails closed.

```yaml
version: 1
networks:
  lab:
    cidr: 192.0.2.0/24
    discovery:
      passive: true
      ping: false
ssh:
  enabled: false
  hosts:
    lab-router:
      alias: lab-router
      inspect: false
limits:
  command_timeout_seconds: 10
  operation_timeout_seconds: 60
retention:
  stale_after_days: 14
render:
  include_addresses: true
  include_interfaces: false
```

All keys, booleans, canonical scopes, aliases, and numerical ceilings are strictly
validated before ANY plugin registration and again on every invocation. See
contract-decisions.md for complete bounds/schema/precedence/profile decisions.
Shared data must be an explicit absolute store.shared_sqlite_path; grants and
exports always stay profile-local. This scaffold creates no data/export files.

## Evidence limitations and next gates

Local canonical/focused suites pass using the existing admitted runtime, without
modifying it. An attempted disposable lean dependency setup was refused by the
host's package threat-intelligence approval gate (lookups timed out). It was not
retried with weaker security settings; the already-installed read-only dependency
environment was used instead. CI setup/dependency installation has NOT been run
on GitHub (no implementation push authorized). Do not claim broader Python/Hermes
matrix coverage or CI success from local checks.

A01 full isolated native install/admission/CLI cycle and A02 fresh-process
persistent query/map remain later gates. Collector/freshness/identity/reconciliation
and complete fixture acceptance in A03–A13 are not implemented by this card.
No release, target integration, real network validation, or live enablement is
claimed. Exact-SHA independent review is required before Phase 1 starts.
