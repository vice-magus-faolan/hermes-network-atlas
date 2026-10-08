#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Two fixed hosted source-only Git measurements; never native acceptance.

No Docker, package acquisition, core import, PM, cache or selection operation.
The hosted VM's Git/zlib differs from the pinned producer: versions are recorded
and the result is only a prerequisite projection, never proof of full-seed fit.
"""
from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import stat
import sys
import tarfile
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'docker'))
import acquisition_support as acquisition
import hosted_retention as retention
from core_identity import source_manifest, require_identity, manifest_digest, CORE_TREE
from docker_evidence import BoundedDirectory, regular_read
from hosted_contract import REPOSITORY
from hosted_evidence import pack as export_pack
from measurement_route import route, FEATURE

CORE_COMMIT = '5645275e50d66dca04c9565634f9b5207a38aef5'
CURRENT = ('git', '-c', 'pack.threads=1', '-c', 'pack.windowMemory=16m',
           'repack', '-a', '-n', '--no-write-bitmap-index')
TUNED = ('git', '-c', 'pack.threads=1', '-c', 'pack.windowMemory=16m', '-c', 'pack.compression=9',
         'repack', '-a', '-n', '--no-write-bitmap-index', '--window=250', '--depth=50')
RECIPES = {'current': CURRENT, 'tuned': TUNED}
EXPECTED_OBJECTS = {'count': 17895, 'sha256': 'e604c591615790fc076bc85b2a77849219fc8acae1a119b125b010bc1ec31c1c'}
FALSE_GATES = {'native_acceptance': False, 'full_canonical': False, 'final_approval': False}
ANCHOR_HASH = '5587ce3c9f513d3e43a0930193806471113beae1b33fd279d4af8cf93b4038de'
RESERVE = 8 * 1024 ** 2


class AuditSink:
    """Incremental actual command rows, bounded before every filesystem write."""
    def __init__(self, evidence: BoundedDirectory, name: str):
        self.path = evidence.reserve(name, acquisition.COMMAND_LOG_LIMIT)
        self.stream = self.path.open('x', encoding='utf-8')
        self.path.chmod(0o600)
        self.bytes = 0

    def write(self, value: str) -> int:
        size = len(value.encode())
        if self.bytes + size > acquisition.COMMAND_LOG_LIMIT:
            raise ValueError('measurement aggregate audit bound')
        self.bytes += size
        result = self.stream.write(value)
        self.stream.flush()
        return result

    def flush(self) -> None:
        self.stream.flush()

    def close(self) -> None:
        self.stream.close()


def require_host(root: Path, env: dict) -> None:
    """Accidental local/ref/retry refusal, not an unforgeable same-UID sandbox."""
    expected = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux',
                'RUNNER_ARCH': 'X64', 'GITHUB_REPOSITORY': REPOSITORY, 'GITHUB_EVENT_NAME': 'push',
                'GITHUB_REF': FEATURE, 'GITHUB_JOB': 'packing-measurement', 'GITHUB_WORKSPACE': str(root),
                'GITHUB_RUN_ATTEMPT': '1'}
    if any(env.get(key) != value for key, value in expected.items()):
        raise ValueError('source measurement hosted diagnostics mismatch')
    import re
    if not re.fullmatch(r'[1-9][0-9]*', env.get('GITHUB_RUN_ID', '')):
        raise ValueError('initial actual hosted run identity required')
    if route(root, env['GITHUB_EVENT_NAME'], env['GITHUB_REF'], env.get('GITHUB_SHA', '')) != 'measurement':
        raise ValueError('exact reviewed measurement phase required')


def owned_directory(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or path.resolve(strict=True) != path:
        raise ValueError('owned literal nonsymlink measurement directory required')


def authenticate_source(source: Path) -> dict:
    """Full public bytes/modes/symlinks plus native commit/tree; do not import core."""
    run = lambda args: acquisition.bounded_run(['git', '-C', str(source), *args], source, timeout=60)
    if run(['rev-parse', 'HEAD', 'HEAD^{tree}']).splitlines() != [CORE_COMMIT, CORE_TREE]:
        raise ValueError('exact public measurement source commit/tree required')
    if run(['status', '--porcelain=v1', '--untracked-files=all']):
        raise ValueError('clean complete public measurement source required')
    value = source_manifest(source)
    require_identity(value)
    if len(value) != 16871:
        raise ValueError('complete public measurement member count required')
    return value


def anchor() -> dict:
    payload = regular_read(ROOT / 'docker/measurement-anchor.json', 16 * 1024)
    if hashlib.sha256(payload).hexdigest() != ANCHOR_HASH:
        raise ValueError('immutable authenticated Run95 anchor differs')
    value = json.loads(payload)
    if value['seed_bytes'] != sum(item['bytes'] for item in value['components'].values()):
        raise ValueError('complete Run95 anchor counters differ')
    if value['components']['hermes-source/.git']['bytes'] != 84408010 or value['seed_bytes'] != 1096574127:
        raise ValueError('literal observed Run95 totals differ')
    return value


def projection(current: dict, tuned: dict, observed: dict) -> dict:
    """Absolute measured Git plus immutable non-Git anchor; no whole-seed claim."""
    for row in (current, tuned):
        if row.get('stage') != 'complete' or row.get('objects_before') != row.get('objects_after'):
            raise ValueError('both completed preserving measurements required for projection')
    if current['objects_before'] != tuned['objects_before'] or current['source_digest'] != tuned['source_digest']:
        raise ValueError('variants do not measure the same complete source/objects')
    non_git = observed['seed_bytes'] - observed['components']['hermes-source/.git']['bytes']
    projected = non_git + tuned['after']['bytes'] + RESERVE
    return {'interpretation': 'sufficient-for-projected-prerequisite' if projected <= retention.BYTE_LIMIT else 'insufficient',
            'anchor_run': observed['run'], 'anchor_diagnosis_sha256': observed['diagnosis_sha256'],
            'non_git_anchor_bytes': non_git, 'historical_deficit_bytes': observed['seed_bytes'] - retention.BYTE_LIMIT,
            'measured_current_git_bytes': current['after']['bytes'], 'measured_tuned_git_bytes': tuned['after']['bytes'],
            'actual_variant_delta_bytes': current['after']['bytes'] - tuned['after']['bytes'],
            'headroom_reserve_bytes': RESERVE, 'projected_seed_with_reserve_bytes': projected,
            'unchanged_seed_limit_bytes': retention.BYTE_LIMIT,
            'producer_runtime_equivalence': False, 'whole_seed_fit_proven': False, **FALSE_GATES}


def prepare(source: Path, work: Path, commit: str, tree: str, report: dict) -> Path:
    """Native archive/reconstruction of fresh loose objects, with expansion bounds."""
    archive, obj = work / 'source.tar', work / 'commit'
    def poll():
        if archive.exists() and archive.lstat().st_size > 256 * 1024 ** 2:
            raise ValueError('measurement public archive byte bound')
    def run(argv, cwd, **kwargs):
        kwargs.update(timeout=60, limit=4 * 1024 ** 2, poll=poll)
        return acquisition.bounded_run(argv, cwd, **kwargs)
    acquisition.audited_run(['git', 'archive', '--format=tar', '--output=' + str(archive), commit], source, runner=run)
    poll()
    obj.write_bytes(acquisition.audited_run(['git', 'cat-file', 'commit', commit], source, runner=run).encode())
    core = work / 'hermes-source'
    core.mkdir(mode=0o700)
    with tarfile.open(archive) as bundle:
        acquisition.tar_bounds(bundle, {'unpacked_bytes': 256 * 1024 ** 2, 'members': 100000})
    with tarfile.open(archive) as bundle:
        bundle.extractall(core, filter='data')
    reconstruct(core, obj, commit, tree, run)
    with archive.open('rb') as stream:
        report['archive'] = {'sha256': hashlib.file_digest(stream, 'sha256').hexdigest(),
                             'bytes': archive.stat().st_size,
                             'literal_commit_sha256': hashlib.sha256(regular_read(obj, 128 * 1024)).hexdigest()}
    archive.unlink()  # Only this exclusive generated archive, not checkout/evidence.
    return core


def reconstruct(core: Path, obj: Path, commit: str, tree: str, runner) -> None:
    """The production six-stage reconstruction, each child capped at 60 seconds.

    No production helper change: the setup helper's general 900-second default
    is inappropriate for this measurement. Keep its literal native algorithm.
    """
    if any(key.startswith('GIT_') for key in os.environ) or (core / '.git').exists():
        raise ValueError('fresh measurement Git reconstruction required')
    run = lambda argv: acquisition.audited_run(argv, core, runner=runner)
    run(['git', 'init', '--quiet'])
    run(['git', 'add', '--force', '--all'])
    if run(['git', 'write-tree']).strip() != tree:
        raise ValueError('complete measurement archive tree mismatch')
    if run(['git', 'hash-object', '-t', 'commit', '-w', str(obj)]).strip() != commit:
        raise ValueError('literal measurement commit mismatch')
    (core / '.git/shallow').write_text(commit + '\n')
    run(['git', 'update-ref', 'HEAD', commit])
    if run(['git', 'status', '--porcelain=v1', '--untracked-files=all']):
        raise ValueError('extra reconstructed measurement source')


def packed(core: Path, commit: str, tree: str, recipe: tuple, report: dict,
           evidence: BoundedDirectory, name: str) -> None:
    """Same production proof sequence and unchanged runner; fixed recipe only."""
    if recipe not in (CURRENT, TUNED):
        raise ValueError('only two fixed measurement recipes allowed')
    run = retention.runner(core, report.setdefault('observation', {}))
    run(['git', 'fsck', '--full', '--no-reflogs', '--no-dangling'])
    if run(['git', 'rev-parse', 'HEAD', 'HEAD^{tree}']).splitlines() != [commit, tree]:
        raise ValueError('measurement reconstructed identity differs')
    argv = ['git', 'cat-file', '--batch-all-objects', '--batch-check=%(objectname) %(objecttype) %(objectsize)']
    before = run(argv)
    report['objects_before'] = retention.object_rows(before)
    evidence.write(name + '-objects-before.txt', before.encode())
    run(list(recipe))
    indices = sorted((core / '.git/objects/pack').glob('*.idx'))
    if len(indices) != 1 or indices[0].is_symlink():
        raise ValueError('one genuine measurement pack index required')
    run(['git', 'verify-pack', str(indices[0])])
    run(['git', 'fsck', '--full', '--no-reflogs', '--no-dangling'])
    run(['git', 'prune-packed'])
    after = run(argv)
    report['objects_after'] = retention.object_rows(after)
    evidence.write(name + '-objects-after.txt', after.encode())
    if report['objects_before'] != report['objects_after']:
        raise ValueError('complete measurement objects differ after packing')
    if regular_read(core / '.git/shallow', 128) != (commit + '\n').encode():
        raise ValueError('measurement shallow boundary drift')
    if run(['git', 'status', '--porcelain=v1', '--untracked-files=all']):
        raise ValueError('measurement source/index drift')


def variant(core: Path, commit: str, tree: str, name: str, expected: dict,
            evidence: BoundedDirectory, report: dict) -> None:
    """Measure actual strict before/after and refuse drift, partials or file bounds."""
    retention.git_layout(core, commit)
    before = source_manifest(core)
    if before != expected:
        raise ValueError('fresh reconstructed measurement source differs')
    report.update(commit=commit, tree=tree, source_digest=manifest_digest(before),
                  source_members=len(before), before={}, after={}, recipe=list(RECIPES[name]))
    retention.measure(core / '.git', report['before'])
    if report['before']['bytes'] > 2 * 1024 ** 3:
        raise ValueError('measurement transient object bound')
    evidence.json(name + '.json', report)
    packed(core, commit, tree, RECIPES[name], report, evidence, name)
    if source_manifest(core) != before:
        raise ValueError('complete measurement source bytes/modes/links drift')
    retention.measure(core / '.git', report['after'])
    retention.require_accounting(report['after'])
    report['stage'] = 'complete'
    retention.require_compaction(report)


def dispose(work: Path, parent: Path) -> None:
    """Delete only the exclusively created direct child after owned-path readback."""
    owned_directory(parent)
    owned_directory(work)
    if work.parent != parent or work.name not in RECIPES:
        raise ValueError('measurement disposal scope differs')
    shutil.rmtree(work)
    if work.exists() or work.is_symlink():
        raise ValueError('measurement owned disposal absent readback failed')


def run_variant(source: Path, root: Path, name: str, expected: dict,
                evidence: BoundedDirectory, commit: str = CORE_COMMIT, tree: str = CORE_TREE) -> dict:
    """Incremental failure/audit/cleanup proof; never continue after a refusal."""
    work = root / name
    work.mkdir(mode=0o700)  # Exclusive/no suffix retries; only created work is disposed.
    report = {'variant': name, 'stage': 'started', 'cleanup_verified': False, **FALSE_GATES}
    original = None
    sink = None
    previous_log = acquisition.COMMAND_LOG
    try:
        sink = AuditSink(evidence, name + '-audit.log')
        acquisition.COMMAND_LOG = acquisition.CommandLog()  # Two serial independent bounded audits.
        with redirect_stdout(sink):
            core = prepare(source, work, commit, tree, report)
            report['prepared_storage'] = {}
            retention.measure(work, report['prepared_storage'])
            variant(core, commit, tree, name, expected, evidence, report)
            report['after_storage'] = {}
            retention.measure(work, report['after_storage'])
            report['peak_observed_variant_bytes'] = (report['prepared_storage']['bytes'] -
                                                    report['before']['bytes'] +
                                                    report['observation']['peak_observed_bytes'])
            report['peak_is_sampled_lower_bound_not_quota'] = True
    except BaseException as exc:
        original = exc
        report.update(stage='failed', error=type(exc).__name__, message=str(exc)[:512])
        raise
    finally:
        acquisition.COMMAND_LOG = previous_log
        finish_variant(work, root, name, evidence, report, sink, original)
    return report


def finish_variant(work: Path, root: Path, name: str, evidence: BoundedDirectory,
                   report: dict, sink, original) -> None:
    """Primary failure wins; cleanup/evidence failures remain explicit secondary errors."""
    try:
        errors = cleanup_steps(work, root, sink, report)
        if errors:
            report['cleanup_error'] = '; '.join(type(exc).__name__ + ': ' + str(exc)[:256] for exc in errors)
            report['stage'] = 'failed'
            if original is None:
                original = errors[0]
                raise original
            original.add_note('measurement cleanup failed: ' + type(errors[0]).__name__)
    finally:
        try:
            evidence.json(name + '.json', report)
        except BaseException as exc:
            if original is None:
                raise
            original.add_note('measurement evidence failed: ' + type(exc).__name__)


def cleanup_steps(work: Path, root: Path, sink, report: dict) -> list:
    """A diagnostic close failure must not strand owned work before next variant."""
    errors = []
    if sink is not None:
        try:
            sink.close()
        except BaseException as exc:
            errors.append(exc)
    try:
        dispose(work, root)
        report['cleanup_verified'] = True
    except BaseException as exc:
        errors.append(exc)
    return errors


def versions(source: Path) -> dict:
    binary = shutil.which('git')
    if binary is None:
        raise ValueError('hosted native Git executable absent')
    return {'git': version_run(['git', '--version', '--build-options'], source),
            'python': sys.version, 'python_zlib_compile': zlib.ZLIB_VERSION,
            'python_zlib_runtime': zlib.ZLIB_RUNTIME_VERSION, 'platform': platform.platform(),
            'kernel': platform.release(),
            'git_linked_libraries': version_run(['ldd', binary], source),
            'git_binary_sha256': hashlib.sha256(regular_read(Path(binary), 8 * 1024 ** 2)).hexdigest(),
            'git_zlib_packages': version_run(['dpkg-query', '-W', '-f=${Package} ${Version}\n', 'git', 'zlib1g'], source),
            'runtime_equivalent_to_producer': False,
            'limit': 'Host Git/zlib/platform differs; only comparative prerequisite projection, not producer fit.'}


def version_run(argv: list, source: Path) -> str:
    def run(args, cwd, **kwargs):
        kwargs.update(timeout=60, limit=4 * 1024 ** 2)
        return acquisition.bounded_run(args, cwd, **kwargs)
    return acquisition.audited_run(argv, source, log=acquisition.CommandLog(), runner=run)


def main() -> int:
    require_host(ROOT, dict(os.environ))  # BEFORE any scratch, source copy, archive or native effects.
    if any(key.startswith('GIT_') for key in os.environ):
        raise ValueError('ambient Git authority refused')
    temporary = Path(os.environ['RUNNER_TEMP'])
    owned_directory(temporary)
    root = temporary / 'atlas-packing-measurement'
    root.mkdir(mode=0o700)
    # No operator/global Git config. No package install or privilege change.
    home = root / 'home'
    home.mkdir(mode=0o700)
    os.environ.update(HOME=str(home), XDG_CONFIG_HOME=str(home))
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024 ** 3, 2 * 1024 ** 3))
    summary = root / 'summary'
    summary.mkdir(mode=0o700)
    evidence = BoundedDirectory(summary)
    report = {'phase': 'exact-core-packing-measurement-only', 'stage': 'started',
              'candidate_commit': os.environ['GITHUB_SHA'], 'run_id': os.environ['GITHUB_RUN_ID'],
              'two_serial_fixed_variants': True, 'projection': {'interpretation': 'unknown'}, **FALSE_GATES}
    original = None
    try:
        source = ROOT / '.hermes-runtime-source'
        expected = authenticate_source(source)
        observed = anchor()
        evidence.json('source-manifest.json', expected)
        evidence.json('anchor.json', observed)
        sink = AuditSink(evidence, 'versions-audit.log')
        try:
            with redirect_stdout(sink):
                evidence.json('versions.json', versions(source))
        finally:
            sink.close()
        evidence.json('outcome.json', report)
        results = []
        for name in RECIPES:
            row = run_variant(source, root, name, expected, evidence)
            if row['objects_before'] != EXPECTED_OBJECTS:
                raise ValueError('complete pinned producer object manifest differs on measurement runtime')
            results.append(row)
        report.update(stage='complete', variants=results, projection=projection(results[0], results[1], observed))
        return 0
    except BaseException as exc:
        original = exc
        report.update(stage='failed', error=type(exc).__name__, message=str(exc)[:512])
        raise
    finally:
        final_evidence(root, evidence, report, original)


def final_evidence(root: Path, evidence: BoundedDirectory, report: dict, original) -> None:
    try:
        evidence.json('outcome.json', report)
        export_pack(root, root.parent / 'packing-measurement-evidence.tar')
    except BaseException as exc:
        if original is None:
            raise
        original.add_note('measurement final export failed: ' + type(exc).__name__)


if __name__ == '__main__':
    raise SystemExit(main())
