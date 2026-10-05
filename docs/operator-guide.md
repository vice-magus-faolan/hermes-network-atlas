# Operator guide and cumulative V1 verification

V1 phases 1–3 are implemented. Native supported scratch installation/admission,
synthetic collection and fresh-process persistence are tested. This does NOT
validate a real network, host key, deployment, gateway restart or provider chat.
Final independent approval, local target integration and publication have their
own gates. Do not infer permission from these examples.

## Supported installation (only after separate operator authorization)

Compatibility is Python >=3.11,<3.15 and Hermes >=0.21.4,<0.22; executable evidence
uses Linux x86_64, Python 3.14.7 and exact Hermes
f42f579cf8bac4918ac9599bece71618afadd846. Other platforms/versions are not proven.
Atlas itself needs only ruamel.yaml>=0.18.16,<0.19 beyond the standard library,
declared with the supported native plugin.yaml python_dependencies field.

The repository root is a native directory plugin. Choose a reviewed immutable
40-character commit and the intended profile explicitly. Do not run these on a
live profile merely to verify this repository:

    hermes plugins install https://github.com/vice-magus-faolan/hermes-network-atlas.git --ref <reviewed-40-character-SHA> --no-enable
    hermes plugins enable network-atlas
    hermes plugins show network-atlas

Install clones/scans the exact artifact; enable uses native PM member-union
resolution/publication, not a hand-edited enabled list. Retain security checks
and ordinary dependency/capability consent. Do not use force or disable scanning
to get a refused candidate through admission. No runtime activation/restart of a
live gateway is authorized by these instructions. Native enable's restart hint
is advice for a separately authorized deployment, not an action this test runs.

Missing Python dependencies/PM toolchain or a resolver conflict is an installation
failure, not evidence that Atlas works. Prepare an isolated test environment or
follow Hermes's supported PM diagnosis/recovery; do not pip into production,
remove dependency declarations, substitute versions, fabricate lock/facts, or
relax security settings. Native enable can resolve upstream optional requirements
and revalidate URL dependencies even when a frozen core build is cached. Therefore
setup may need the network; the Atlas test process must not have it. An incomplete
package-intelligence warning is not a clean vulnerability verdict.

## Profile-local policy

Atlas reads `<get_hermes_home()>/network-atlas/config.yaml`, separate from Hermes's
plugin selector. No policy means empty allowlists. An existing empty/malformed file,
unknown keys, invalid numbers, noncanonical or overbroad scopes fail closed at
registration and every invocation. Invalid-policy CLI refusal returns exit 2 and
explicit applied=false/persisted=false before command dispatch or store changes.
Maintain this file as an operator in a 0700
directory with mode 0600; never let model tools edit it. A synthetic example:

```yaml
version: 1
networks:
  lab:
    cidr: 192.0.2.0/29
    discovery:
      passive: true
      ping: false
ssh:
  enabled: false
  hosts:
    lab-a: {alias: lab-a, inspect: false}
    lab-b: {alias: lab-b, inspect: false}
    lab-c: {alias: lab-c, inspect: false}
retention:
  stale_after_days: 14
render:
  include_addresses: true
  include_interfaces: false
```

The reserved documentation range and disabled SSH/ping are intentional. This is
not an operational network authorization. Explicitly enable only real operator-
chosen modes and existing reviewed OpenSSH aliases during a later authorized
activation. IPv4 ping ranges have at most 256 addresses. Stored/passive IPv6 is
not permission for active IPv6 scanning. Numeric ceilings and selection precedence
are detailed in [contract-decisions.md](contract-decisions.md).

Issue #6 accepts network-local discovery.icmp_echo (default false) and
discovery.tcp_ports (default [80,443], at most four distinct integer ports;
4403 is forbidden). Nonlegacy ping uses bounded numeric-only echo datagrams and
TCP connects with no application traffic. Passive and legacy traffic are unchanged.
ICMP-only policy uses tcp_ports: []; ICMP requires ping: true. Socket permission
is diagnosed honestly: unavailable ICMP does not suppress a TCP positive (or vice
versa). A TCP refusal is positive host-response evidence, not a listening service.
The synthetic example [80,443,2222,22000] is not a default or service claim.
No helper, grants or fallback are enabled. Read
[host-discovery-policy.md](host-discovery-policy.md) before selecting methods;
old binaries reject the new keys. Query/status never opens a capability socket.
Method outcomes retain port, UTC times and contributing positives without a schema
migration. Status address_count/responding_address_count deduplicate hosts; total
probe/observation counts include method evidence, not extra devices. An excluded,
timed-out, unavailable or not-started method makes coverage absence-ineligible.
Network/broadcast addresses (except /31 and /32 host semantics), multicast,
loopback, unspecified and reserved destinations are excluded before transport.

Policy stays local even with an explicitly configured absolute
`store.shared_sqlite_path`. Another profile can read knowledge but cannot inherit
inspection authority, apply foreign batches, or reuse foreign alias anchors.
Exports stay profile-local. Same-UID processes, operator SSH config, executables,
ProxyJump/ProxyCommand/Match exec and local native plugins are trusted, not OS-
sandboxed. Keep DB/WAL/config/audit/exports private. See [SECURITY.md](../SECURITY.md),
[Atlas Core](atlas-core.md) and [SSH trust boundaries](authorized-ssh-inspection.md).

## Explicit commands and provenance

    /network help
    /network status
    /network discover lab passive
    /network inspect lab-a
    /network reconcile <returned-batch-id>
    /network show <stable-device-id>
    /network map markdown

Discover requires a configured name and mode; inspect requires an authorized alias
or uniquely mapped stable ID. Collection stores immutable batches only; reconcile
applies one eligible batch atomically and exact-ID retry returns the saved result.
Missing means not observed in that complete exact run, never deleted or offline.
Passive neighbors and failed/partial scans cannot prove absence. Age-based stale
status is distinct from latest scan absence. User retirement is sticky.

Status reports total known inventory, observed/stale subsets, configured scopes,
authorized aliases/device count, last discovery scope/completion/whole-batch evidence,
and separate last inspection success/failure. Neither configuration nor an old
successful attempt proves present reachability. SSH inventory does not prove every
stored IP is reachable. Only qualified exact-address ping evidence can say that.

Last discovery/collection `probe_summary` always counts the entire batch, including
the scope-coverage probe: total_count, outcome_counts, coverage_counts,
failure_count and absence_eligible_count. Inventory pagination cannot suppress
these aggregates, including after /24 or /25 discovery. `probes` is explicitly a
bounded sample (`detail_limit=limits.result_count`), with failures first and stable
ordering. Check returned_count, omitted_count and omitted_failure_count before
treating it as complete detail. Omitted failures remain in whole-batch outcome/
coverage totals. Status does not offer probe pagination, and device history is not
batch probe detail; collection returns the full bounded outcome/diagnostic receipt.
See [Atlas Core](atlas-core.md) for exact field semantics. Public status still obeys
the serialized output_bytes ceiling; a too-small ceiling refuses read-only.

Ping discovery uses serial fixed 16-address chunks, preserving earlier completed
evidence when a later chunk fails. New address_count/address_outcome_counts exclude
the synthetic scope-coverage probe. not_started means the work had no child because
its budget expired; timeout means started transport exceeded its deadline; neither
means offline. success/completed_at_boundary retains valid finished work despite
postprocessing crossing the transport boundary. Chunk failures leave all their
addresses unknown, never absent. Legacy /24 and /25 records remain readable, but
old timeout diagnostics remain ambiguous; upgrade shared-store readers for the
additive outcome enum. See local-discovery.md for fixed argv, total concurrency/
average-rate bounds and limitations. No real-world completion guarantee is made.

The slash runtime cannot attest human origin, so `/network update` refuses.
Use the trusted local operator CLI for user-supplied knowledge:

    hermes network-atlas create --name "Synthetic workstation"
    hermes network-atlas update --device-id <returned-id> --field description --value-json '"Operator assertion"'
    hermes network-atlas update --device-id <returned-id> --field ssh_alias --value-json '"lab-a"'
    hermes network-atlas update --device-id <returned-id> --field retired --value-json true
    hermes network-atlas query --query-json '{"access_method":"ssh","limit":10}'
    hermes network-atlas query --query-json '{"view":"history","device_id":"<returned-id>","limit":10}'
    hermes network-atlas map --format mermaid --export

Alias association requires preexisting current permission; it never grants it.
Retired=false reactivates through the same operator path. The local CLI is a trust
convention, not cryptographic human attestation. Model `network_update` proposals
always retain inference/explanation; caller `source=user` and runtime origin flags
cannot promote them. Applying receipts say persisted=true; the compatibility
validate-update command still says applied=false/persisted=false.

Queries/maps read existing SQLite, never collect or schedule. Follow has_more
with bounded offset/limit; oversized entity evidence fails explicitly, with
history pagination available. Maps render stored supported relations only,
escape labels, and retain isolated/stale/uncertain nodes. Exports are fixed
profile-local exports/network_map.md and network_map.mmd, not authoritative.
An interruption between file replacements can leave mismatched exports; regenerate
both from SQLite. No service enumeration, full-atlas prompt hook or scheduler ships.

### When discovery found responses but inventory has zero devices

MAC-less ping response evidence correctly remains unidentified. It is not a
reason to fabricate canonical devices or assign an IP's previous owner. Read it
through `network_query` with `view=unresolved`, or the native query CLI:

    hermes network-atlas query --query-json '{"view":"unresolved","address":"192.0.2.10","limit":10}'
    hermes network-atlas query --query-json '{"view":"unresolved","batch_id":"<returned-batch-id>","limit":10,"offset":0}'

The response's evidence array is distinct from devices. Check identity_state,
historical_responder_evidence, freshness, origin/policy_context and batch/probe
coverage. Never-reconciled, reconciled-unresolved/conflicting and later-resolved
originals are explicitly distinguished; resolved historical originals remain
listed, not mislabeled. Fresh evidence still does not prove reachability now,
identity, ownership or inspection access. Foreign shared evidence remains visible
knowledge, not permission to apply it. See [the strict bounded evidence contract](unresolved-evidence.md)
for pagination, all output fields, lineage limits and partial/legacy batch handling.

Passive collection needs installed iproute2; ping needs optional installed Nmap;
SSH needs a supported OpenSSH client and existing operator-managed config/keys/
known_hosts plus remote Linux utilities. Missing executables/remote commands
produce bounded per-probe failures, never automatic installation or weaker SSH.
Older clients rejecting a safety option fail closed. Fixed argv, ARP/TCP behavior,
output/time limits and remote cancellation caveats are documented in the collector
guides. Inspect/query failures are not an excuse to discard the atlas.

## Reproduce the isolated acceptance

Tests need an existing scratch directory, a compatible verifier interpreter and
an exact public Hermes Git checkout. No live config, atlas, credentials, homes or
profile selections are copied. A lean disposable verifier can be prepared with
requirements-test.txt (setup only). Do not install into production. GitHub CI
checks out the exact Hermes pin and uses this same path; GitHub execution itself
remains unperformed until separately authorized publication.

First, ONLINE PREREQUISITE SETUP, outside the test process:

    export TMPDIR=<existing-absolute-scratch-directory>
    export NETWORK_ATLAS_HERMES_ROOT=<public-Hermes-Git-checkout-at-exact-pin>
    python3 scripts/prepare_acceptance.py --hermes-source "$NETWORK_ATLAS_HERMES_ROOT"

Optionally `--software-seed <authorized-disposable-directory>` copies public
pinned tools from tools/; it never copies homes or state. Setup intentionally uses
a fresh uv cache: flattened/dereferenced links in older recovery caches can fail
native cache revalidation. Do not mutate a production cache to repair that.
Setup has bounded subprocess/log budgets and requires at least 1 GiB free; a full
fresh tool/core/source/cache closure may need more. Never delete unrelated state
to manufacture capacity. Preserve the printed marked fixture root.

Commit the candidate first; tracked changes fail setup. Setup snapshots the ENTIRE
committed candidate tree (including tests/docs/harnesses) and public Hermes source
with git archive; invokes actual
plugins_cmd.cmd_install(file://<synthetic-repo>, enable=False, ref=<exact-SHA>)
and cmd_enable('network-atlas'), the entrypoints used by the supported CLI; reads
back installed bytes/full Git tree, enabled selector, PM facts/generation, recipes/locks and
candidate identity. No admission, scanner, registry, selection or resolver mocks.
Only ordinary dependency consent can be answered; other warnings/refusals are
not forced through. Explicit native enable on this runtime may not ask a separate
Python dependency question. This is setup evidence, NOT the acceptance result.

Then, SEPARATE NETWORK-DENIED ACCEPTANCE:

    export NETWORK_ATLAS_ACCEPTANCE_FIXTURE=<printed-marked-fixture-root>
    python3 scripts/verify.py

Canonical verification installs inherited Linux x86_64 seccomp socket/connect/bind
refusal plus Python socket/DNS audit refusal before loading tests. fork/exec children
inherit refusal. The guard self-test checks parent and exec-child socket syscalls
without sending a packet. Unsupported guard platforms fail, not skip/weaken.
The synthetic transport PATH contains only non-forwarding ip/Nmap/SSH fixtures
and Python. It cannot fall back to real network executables.

`tests/test_acceptance.py::CumulativeAcceptanceTests` validates candidate/installed
bytes/selection evidence, configures three synthetic SSH aliases, performs bounded
passive/ping discovery and all three fixed inspections, operator alias association,
new/changed/missing/conflict/unresolved reconciliation, operator/inference/direct
source separation, synthetic host-key refusal, query/status and escaped maps/exports.
A second fresh native process uses the admitted PM-selected interpreter and
re-queries/replays with transport binaries removed. It compares complete devices,
history, access evidence, status, maps/exports and SQLite row counts, without
rediscovery or audit growth. No LLM/provider response is fabricated or claimed.
Both processes also verify invalid ICMP/port/option policy refusal through native
tool/slash/CLI with explicit no-effects receipts and unchanged files/store counts.
The collection process exercises valid ICMP/extra-port/ICMP-only policy through
non-forwarding sockets on all three routes; restart reads the same method evidence
without transport. The original fixture policy is restored.
Repeated verification starts a new synthetic atlas only in this marked fixture;
never in a live profile. Missing/stale fixture evidence fails canonical checks.
Rebuild setup after a new candidate commit or changed plugin/selector/recipe/lock.

`docs/acceptance-matrix.md` indexes A01–A14 to exact tests and documentation;
A15 remains the delivery owner. No self approval, main advancement, push, release,
live activation, actual scan/SSH or gateway restart is proven by green tests.
