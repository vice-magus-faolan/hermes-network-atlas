# Scaffold verification and compatibility

The original scaffold milestone introduced native directory-plugin registration,
strict policy validation, six tool schemas and the operator/inference boundary.
Its update command validated proposals without applying them. Atlas Core now
implements applying updates, persistence, query and map; see [atlas-core.md](atlas-core.md).
Historical artifact evidence remains in Git history, not a separate setup harness.

## Current verification

Use stock supported Hermes (>=0.21.4), Python >=3.11,<3.15, and
requirements-test.txt. The current Docker path checks official unmodified v0.21.7
and v0.22.2; CI requires both on Linux x86_64 and arm64. Platform coverage depends
on successful exact-head jobs, not an earlier commit's results.
If Hermes is not importable, NETWORK_ATLAS_HERMES_ROOT may point to its checkout.
Pytest supplies scratch directories; no manual TMPDIR, native receipt or
core-identity pin is required. Never pip-edit the production Hermes runtime.

    python3 -m pytest -q tests/test_boundaries.py tests/test_runtime.py

For the complete required online-installer/network-denied application split, use
the Docker build/run commands in [CONTRIBUTING.md](../CONTRIBUTING.md).

The native smoke copies only Atlas source into a fresh synthetic Hermes home,
sets explicit plugins.enabled selection and uses actual discovery, registry,
tool dispatch, slash/CLI registration, policy revocation and unload. All six
tools are checked. Fixture transports cannot forward real LAN/SSH traffic;
a Python audit tripwire rejects connect/bind/DNS. Docker's --network none is the
independent network boundary, not a custom admission or security-fence exception.

## Scope and limitations

Profile-local policy comes from get_hermes_home()/network-atlas/config.yaml,
separate from Hermes's plugin selector. Empty allowlists are the default;
malformed policy fails before registration. Shared atlas data never grants
another profile inspection authority. See [contract-decisions.md](contract-decisions.md).

The operator CLI is a trusted local route outside the model tool argument
surface, not cryptographic human attestation or a same-UID sandbox. Native code
and the local operator are trusted. No test reads a live profile or atlas.

Directory discovery/opt-in is not native enablement. The additional
tests/test_compatibility.py exercises real CLI enable/status on known non-root
v0.21.7 and v0.22.2 in fresh synthetic homes
during the required online image build. It is excluded only from the subsequent
network-denied application suite; offline installation is not claimed.
Three-alias collection/reconciliation/restart acceptance is synthetic, not live
reachability or provider chat evidence. Live installation/enable, actual scans/SSH,
profile activation and gateway restart remain separately controlled effects.
Current setup and residual checks are in [operator-guide.md](operator-guide.md)
and [acceptance-matrix.md](acceptance-matrix.md). Independent exact-SHA review,
hosted platform evidence, publication and human approval do not follow from a
local test pass.
