# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit subset collection with immutable, pre-traffic successor reservations.

A reservation is never released: without a durable child its physical effects
are unknowable. Recovery may project a saved child, but must never recollect it.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
import sqlite3
import time

from . import endpoints
from .batches import Probe, _validate_probes, store_batch
from .config import Limits, NAME_PATTERN, Policy
from .errors import RequestError
from .host_schedule import Scheduler
from .host_transport import excluded
from .storage import Store, encode, identifier, parse_time, response_json, timestamp, utc_now

# Retain the structural traversal bound, not a cumulative probe-row quota.
# With <=256 IPv4 addresses, <=32 ports per protocol and <=4096 full-grid rows,
# the largest eligible grid is /24 x 16 selections: (256 - 2) x 16 = 4064.
# /25 x 32 yields 4032; /26 x 64 yields 3968; smaller scopes cannot exceed
# those (even /31-/32 without network/broadcast exclusions). Other exclusions
# only reduce work. Thus root + one progressing child per eligible tuple fits
# below 4096 batches. Zero-progress histories can still hit this structural
# bound; time/capacity refusals or an unsaved reservation can stop progress first.
LINEAGE_BATCH_LIMIT = 4096
LINEAGE_LIMIT_ERROR = ('endpoint continuation: lineage batch limit (4096) reached; '
                       'retain saved IDs and history for operator review; no new collection')
UNCERTAIN_ERROR = ('endpoint continuation: reserved child may still be in progress '
                   'or its producer ended without saving; confirm producer exit or its original operation deadline, '
                   'then preview parent again; waiting cannot restore unsaved evidence; '
                   'no recollection; retain history and child ID')


@dataclass
class Lineage:
    """Validated historical coverage, not a simultaneous or live network census."""
    batch: sqlite3.Row
    root: str
    runs: int
    remaining: tuple[str, ...]
    counts: dict[str, int]
    excluded_count: int
    grid: dict[str, tuple[str, int]]
    attempted_count: int

    def progress(self) -> dict:
        return {'root_batch_id': self.root, 'runs': self.runs, 'total': sum(self.counts.values()),
                'attempted': self.attempted_count,
                'responded': self.counts['open'] + self.counts['closed'],
                'still_unattempted': len(self.remaining), 'excluded': self.excluded_count,
                'unavailable': self.counts['unavailable'] - self.excluded_count,
                'scope': 'selected_batch_ancestry',
                'historical': True, 'current_reachability': 'not_established'}


@dataclass(frozen=True)
class Reservation:
    """Request-local proof from the reservation transaction, never cold authority.

    Keep the same open connection and immutable policy snapshot through collection
    and publication. Complete parent ancestry was validated in a snapshot whose
    data_version was checked under the write lock (or revalidated there). Only
    this exact immutable claim may reuse it. Other invocations always
    replay history. No connection, policy or caller-selected subset can replace it.
    """
    store: Store
    policy: Policy
    lineage: Lineage
    claim: tuple

    def selection(self, store: Store, *, child: str | None = None) -> tuple[str, ...]:
        if store is not self.store or store.policy is not self.policy:
            raise RequestError('endpoint continuation: matching request-local reservation required')
        parent = self.lineage.batch['id']
        claim = _claim(store, 'parent_batch_id', parent)
        if claim is None or tuple(claim) != self.claim:
            raise RequestError('endpoint continuation: matching request-local reservation required')
        _validate_reservation(self.lineage, claim)
        batch = endpoints._stored(store, parent)
        if tuple(batch) != tuple(self.lineage.batch):
            raise RequestError('endpoint continuation: reserved parent changed; retain history')
        if child is not None:
            batch = endpoints._stored(store, child)
            _validate_link(self.lineage.batch, batch, claim, _selection(claim), self.lineage.remaining)
        return self.lineage.remaining


def _claim(store: Store, column: str, batch_id: str):
    if store.schema_version < 3:
        return None
    if column not in {'parent_batch_id', 'child_batch_id'}:
        raise ValueError('invalid continuation reference')
    return store.connection.execute(
        f'SELECT * FROM endpoint_continuations WHERE {column}=?', (batch_id,)).fetchone()


def _selection(claim) -> tuple[str, ...]:
    # Bound untrusted stored JSON before parsing; no caller-provided subset exists.
    text = claim['selection_json']
    if not isinstance(text, str) or len(text) > Limits().output_bytes:
        raise RequestError('endpoint continuation: invalid saved selection')
    names = json.loads(text)
    if (not isinstance(names, list) or not 1 <= len(names) <= Limits().observations
            or any(not isinstance(name, str) for name in names) or names != sorted(set(names))):
        raise RequestError('endpoint continuation: invalid saved selection')
    parse_time(claim['created_at'])
    return tuple(names)


def _probes(store: Store, batch) -> tuple[Probe, ...]:
    rows = store.connection.execute('SELECT * FROM probes WHERE batch_id=? ORDER BY probe_name LIMIT ?',
                                    (batch['id'], Limits().observations + 1)).fetchall()
    if (any(row['absence_eligible'] for row in rows) or store.connection.execute(
            'SELECT 1 FROM observations WHERE batch_id=? LIMIT 1', (batch['id'],)).fetchone()):
        raise RequestError('endpoint continuation: contradictory identity evidence')
    probes = tuple(Probe(row['probe_name'], row['outcome'], row['started_at'], row['ended_at'],
                         row['coverage_kind'], row['coverage_value'], row['evidence_kind'], row['diagnostic_code'])
                   for row in rows)
    return probes


def _history(store: Store, batch_id: str) -> list:
    """Read bounded ancestry without interpreting missing records as fresh work."""
    chain, seen = [], set()
    current = batch_id
    while current is not None:
        if current in seen:
            raise RequestError('endpoint continuation: cyclic lineage; retain history for operator review')
        if len(seen) >= LINEAGE_BATCH_LIMIT:
            raise RequestError(LINEAGE_LIMIT_ERROR)
        seen.add(current)
        batch = endpoints._stored(store, current)
        if batch['source'] != batch['collector'] or batch['schema_version'] != 1:
            raise RequestError('endpoint continuation: inconsistent saved batch')
        claim = _claim(store, 'child_batch_id', current)
        chain.append((batch, claim))
        current = claim['parent_batch_id'] if claim is not None else None
    return chain


def load_lineage(store: Store, batch_id: str, *, allow_unapplied: bool = False) -> Lineage:
    """Validate complete ancestry before selecting work; never prune failed history."""
    chain = _history(store, batch_id)
    counts: dict[str, int] = dict.fromkeys(endpoints.STATES, 0)
    grid: dict[str, tuple[str, int]] = {}
    remaining, excluded_count, previous = (), 0, None
    attempted_count = 0
    exclusions = None
    for batch, claim in reversed(chain):
        store.check_deadline()
        # Retain batch/claim metadata, not up to 4096 full grids of Probe objects.
        probes = _probes(store, batch)
        selection = _selection(claim) if claim is not None else None
        if previous is not None:
            _validate_link(previous, batch, claim, selection, remaining)
            counts['not_started'] = 0
        grid = endpoints.validate_probes(store.policy, batch['scope_name'], probes, selection=selection)
        _validate_probes(store, batch['collector'], 'network', batch['scope_value'], batch['started_at'],
                         batch['ended_at'], batch['completion'], probes)
        _verify_projection(store, batch, probes, grid, allow_unapplied and batch['id'] == batch_id)
        network = endpoints._authorized_network(store.policy, batch['scope_name'])
        if exclusions is None:
            exclusions = {name: excluded(network, address) for name, (address, _) in grid.items()}
        for probe in probes:
            is_excluded = probe.diagnostic_code == 'destination_excluded'
            if is_excluded != exclusions[probe.probe_name]:
                raise RequestError('endpoint continuation: contradictory exclusion evidence')
            counts[endpoints.RESULTS[(probe.outcome, probe.diagnostic_code)][0]] += 1
            excluded_count += int(is_excluded)
            attempted_count += int(endpoints.attempted(probe.outcome, probe.diagnostic_code))
        remaining = tuple(sorted(probe.probe_name for probe in probes if probe.outcome == 'not_started'))
        previous = batch
    return Lineage(chain[0][0], chain[-1][0]['id'], len(chain), remaining, counts, excluded_count,
                   grid, attempted_count)


def _verify_projection(store: Store, batch, probes, grid, allow_missing: bool) -> None:
    """Contradictory saved projections cannot be used to authorize further work."""
    application = store.connection.execute('SELECT * FROM applications WHERE batch_id=?', (batch['id'],)).fetchone()
    if application is None:
        if allow_missing:
            return
        raise RequestError('endpoint continuation: resume-endpoints saved batch before continuing')
    rows = store.connection.execute(
        'SELECT p.probe_name,e.* FROM probes p JOIN endpoint_observations e ON e.probe_id=p.id '
        'WHERE p.batch_id=? LIMIT ?', (batch['id'], Limits().observations + 1)).fetchall()
    actual = {row['probe_name']: (row['address'], row['protocol'], row['port'], row['state'], row['qualified'])
              for row in rows}
    expected = {probe.probe_name: (grid[probe.probe_name][0], endpoints.protocol(probe.probe_name),
                grid[probe.probe_name][1],
                *endpoints.RESULTS[(probe.outcome, probe.diagnostic_code)]) for probe in probes}
    counts: dict[str, int] = dict.fromkeys(endpoints.STATES, 0)
    for probe in probes:
        counts[endpoints.RESULTS[(probe.outcome, probe.diagnostic_code)][0]] += 1
    result = {'id': application['id'], 'batch_id': batch['id'], 'applied': True, 'projected': True,
              'observation_count': len(probes), 'state_counts': counts, 'applied_at': application['applied_at']}
    if (actual != expected or len(rows) != len(probes) or application['schema_version'] != 1
            or application['result_json'] != encode(result)):
        raise RequestError('endpoint continuation: contradictory saved projection; retain history')


def _validate_link(parent, child, claim, selection, remaining) -> None:
    # The immutable reservation orders runs causally. UTC may step backward
    # between parent, reservation and child; it is evidence, not a causal clock.
    if (selection != remaining or not selection or claim['parent_batch_id'] != parent['id']
            or claim['child_batch_id'] != child['id']
            or (child['collector'], child['scope_name'], child['scope_value']) != (
                parent['collector'], parent['scope_name'], parent['scope_value'])):
        raise RequestError('endpoint continuation: inconsistent saved lineage; no new collection')


def saved_selection(store: Store, batch_id: str, reservation: Reservation | None = None) -> tuple[str, ...] | None:
    """Projection of a subset must validate the claim and full original intent."""
    if reservation is not None:
        return reservation.selection(store, child=batch_id)
    claim = _claim(store, 'child_batch_id', batch_id)
    if claim is None:
        return None
    load_lineage(store, batch_id, allow_unapplied=True)
    return _selection(claim)


def _preview(store: Store, lineage: Lineage) -> dict:
    claim = _claim(store, 'parent_batch_id', lineage.batch['id'])
    if claim is not None:
        _validate_reservation(lineage, claim)
    child = claim['child_batch_id'] if claim is not None else None
    child_saved = child is not None and store.connection.execute(
        'SELECT 1 FROM batches WHERE id=?', (child,)).fetchone() is not None
    if child_saved and child is not None:
        load_lineage(store, child, allow_unapplied=True)
    state = ('continued' if child_saved else 'uncertain') if claim is not None else (
        'ready' if lineage.remaining else 'exhausted')
    # Details use the normal query cap; counts describe the complete selection.
    cap = store.policy.limits.result_count
    result = {'batch_id': lineage.batch['id'], 'successor_batch_id': child, 'state': state,
              'collection_performed': False, 'progress': lineage.progress(),
              'remaining': [{'address': lineage.grid[name][0], 'port': lineage.grid[name][1],
                             'protocol': endpoints.protocol(name)}
                            for name in lineage.remaining[:cap]],
              'omitted_remaining': max(0, len(lineage.remaining) - cap)}
    response_json(result, store.policy.limits.output_bytes)
    return result


def _validate_reservation(lineage: Lineage, claim) -> None:
    if (_selection(claim) != lineage.remaining or not lineage.remaining
            or not isinstance(claim['child_batch_id'], str)
            or re.fullmatch(NAME_PATTERN, claim['child_batch_id']) is None):
        raise RequestError('endpoint continuation: inconsistent saved reservation; retain history')


def continuation(policy: Policy, params: dict) -> dict:
    """Preview is observational; continue reserves once then makes NEW TCP/UDP traffic."""
    key, batch_id = next(iter(params.items()))
    if not isinstance(batch_id, str) or re.fullmatch(NAME_PATTERN, batch_id) is None:
        # check() admits only the two code-owned continuation selection keys.
        raise RequestError(f'{key}: stable saved endpoint batch ID required')
    deadline = time.monotonic() + policy.limits.operation_timeout_seconds
    # Read-only first: invalid/foreign intent cannot create or upgrade a store.
    with Store(policy, deadline=deadline) as reader:
        version = reader.connection.execute('PRAGMA data_version').fetchone()[0]
        with reader.snapshot():
            lineage = load_lineage(reader, batch_id)
            preview = _preview(reader, lineage)
        if key == 'preview_batch_id' or preview['state'] == 'exhausted':
            return preview
        return _continue(reader, version, lineage, deadline)


def _continue(reader: Store, version: int, lineage: Lineage, deadline: float) -> dict:
    policy, batch_id = reader.policy, lineage.batch['id']
    if lineage.runs >= LINEAGE_BATCH_LIMIT and _claim(reader, 'parent_batch_id', batch_id) is None:
        raise RequestError(LINEAGE_LIMIT_ERROR)
    # Preflight the complete bounded recovery envelope before reserving or traffic.
    response_json({**endpoints._receipt('0' * 36), 'parent_batch_id': batch_id,
                   'stage': 'projection', 'completion': 'complete',
                   'error': endpoints.longest_recovery_error(policy, UNCERTAIN_ERROR)},
                  policy.limits.output_bytes)
    with Store(policy, writable=True, deadline=deadline) as store:
        with store.transaction():
            # data_version is comparable only on this SAME retained reader.
            # Under BEGIN IMMEDIATE no other writer can commit between this
            # check and reservation. Any intervening commit (including upgrade)
            # requires a fresh complete validation before effects.
            if reader.connection.execute('PRAGMA data_version').fetchone()[0] != version:
                lineage = load_lineage(store, batch_id)
            claim = _claim(store, 'parent_batch_id', batch_id)
            if claim is not None:
                _validate_reservation(lineage, claim)
            else:
                # Leave both useful transport time and the existing finalization
                # reserve AFTER real ancestry validation, before any durable claim.
                reserve = policy.limits.operation_timeout_seconds / 4
                if time.monotonic() >= deadline - 2 * reserve:
                    raise RequestError('endpoint continuation: insufficient operation budget after lineage validation; '
                                       'no reservation or collection; retain saved IDs and history')
                child = identifier()
                created = timestamp(utc_now())
                store.connection.execute('INSERT INTO endpoint_continuations VALUES (?,?,?,?)',
                                         (batch_id, child, encode(lineage.remaining), created))
                reservation = Reservation(store, policy, lineage,
                                          (batch_id, child, encode(lineage.remaining), created))
        if claim is not None:
            return _recover(policy, batch_id, claim['child_batch_id'], deadline)
        return _collect(reservation, deadline)


def _recover(policy: Policy, parent: str, child: str, deadline: float) -> dict:
    with Store(policy, deadline=deadline) as store:
        saved = store.connection.execute('SELECT 1 FROM batches WHERE id=?', (child,)).fetchone()
    if saved is None:
        return {**endpoints._receipt(), 'parent_batch_id': parent, 'batch_id': child,
                'stage': 'uncertain', 'error': UNCERTAIN_ERROR}
    return endpoints._finish(policy, {**endpoints._receipt(child), 'parent_batch_id': parent}, deadline)


def _collect(reservation: Reservation, deadline: float) -> dict:
    store, lineage = reservation.store, reservation.lineage
    policy, child = store.policy, reservation.claim[1]
    parent = lineage.batch['id']
    receipt = {**endpoints._receipt(), 'batch_id': child, 'parent_batch_id': parent,
               'collection_performed': True, 'stage': 'uncertain'}
    try:
        selection = reservation.selection(store)
        network = endpoints.network_policy(policy, lineage.batch['scope_name'])
        started = timestamp(utc_now())
        # SQL lock patience is not a CPU/serialization budget: lowering
        # busy_timeout_ms must not remove the post-contact persistence reserve.
        reserve = policy.limits.operation_timeout_seconds / 4
        probes = Scheduler(network, policy, deadline - reserve, endpoints=True,
                           selection=frozenset(selection)).run()
        completion = endpoints.collection_completion(probes)
        stored = store_batch(store, endpoints.collector(network), network.name, started, timestamp(utc_now()),
                             completion, probes, deadline=deadline, endpoint_reservation=reservation)
        if stored != child:
            raise ValueError('continuation persistence identity mismatch')
        receipt.update(persisted=True, completion=completion)
    except (OSError, ValueError, sqlite3.Error):
        receipt['error'] = ('endpoint continuation: collection uncertain; no automatic recollection; '
                            'retain history and reserved child ID')
        return receipt
    # Use the original no-contact projection/readback path, including on retries.
    return endpoints._finish(policy, receipt, deadline, reservation=reservation)
