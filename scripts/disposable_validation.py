#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""One candidate-owned Docker volume: online admission, offline canonical, cold read.

The reviewed hosted workflow supplies isolation, not these forgeable diagnostics.
This is not a local installer or a retained-software producer. No candidate state
is transferred to a different image/candidate; no second offline install occurs.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys

from acceptance_support import ROOT, fixture_root, git_head, validate_receipt
from ci_admission import MODE, select_mode

STATE = Path('/state')
EVIDENCE = STATE / 'evidence'
FIXTURE = STATE / 'fixture.path'


def guard() -> None:
    """Catch accidental host/root invocation before admission or filesystem effects."""
    select_mode(MODE, os.environ)
    if os.getuid() != 1000 or not Path('/.dockerenv').is_file() or Path(os.environ['TMPDIR']) != STATE:
        raise ValueError('disposable non-root hosted container required')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    for key, value in {'CapEff': '0000000000000000', 'CapPrm': '0000000000000000',
                       'CapBnd': '0000000000000000', 'NoNewPrivs': '1', 'Seccomp': '2'}.items():
        if status.get(key, '').strip() != value:
            raise ValueError('capless/no-new-privileges/seccomp container required')


def run(argv: list[str], env: dict[str, str] | None = None) -> None:
    """Leave real output in ordinary CI logs; reap only this owned child group."""
    print('Executing: ' + json.dumps(argv), flush=True)
    process = subprocess.Popen(argv, cwd=ROOT, env=env, start_new_session=True)
    try:
        code = process.wait(timeout=1800)
        if code:
            raise subprocess.CalledProcessError(code, argv)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def retain_native(root: Path) -> None:
    """Copy only compact actual native diagnostics, even after failed enable."""
    for name in ('ci-scan.json', 'install.log', 'enable.log', 'enable-command.json',
                 'native-enabled.json', 'admission.json'):
        path = root / name
        if path.is_file() and not path.is_symlink():
            if path.stat().st_size > 4 * 1024 ** 2:
                raise ValueError('native diagnostic exceeds compact artifact bound')
            shutil.copyfile(path, EVIDENCE / name)


def setup() -> None:
    """Fresh online supported install AND enable; preserve that exact selection."""
    if FIXTURE.exists() or any(STATE.glob('atlas-admission-*')):
        raise ValueError('candidate volume must be fresh; native admission cannot be reused')
    EVIDENCE.mkdir()
    original = None
    try:
        run([sys.executable, 'scripts/prepare_acceptance.py', '--hermes-source',
             os.environ['NETWORK_ATLAS_HERMES_ROOT'], '--admission-mode', MODE])
        roots = list(STATE.glob('atlas-admission-*'))
        if len(roots) != 1:
            raise ValueError('one fresh native fixture required')
        root = fixture_root(str(roots[0]))
        validate_receipt(root)
        FIXTURE.write_text(root.name + '\n')
    except BaseException as exc:
        original = exc
        raise
    finally:
        try:
            for root in STATE.glob('atlas-admission-*'):
                retain_native(root)
        except Exception as exc:
            if original is None:
                raise
            original.add_note('secondary native diagnostic failure: ' + type(exc).__name__)


def admitted() -> tuple[Path, dict]:
    root = fixture_root(str(STATE / FIXTURE.read_text().strip()))
    return root, validate_receipt(root)


def verify() -> None:
    """Full canonical suite, including installed native scenario and fresh restart."""
    root, receipt = admitted()
    env = dict(os.environ, NETWORK_ATLAS_ACCEPTANCE_FIXTURE=str(root))
    # These remain in the full canonical suite too. Run explicitly before it so
    # native admission/refusal controls have obvious ordinary CI log coordinates.
    for script in ('tests/test_ci_admission.py', 'tests/test_caution_confirmation.py', 'scripts/verify.py'):
        run([sys.executable, '-B', script], env)
    validate_receipt(root)
    (EVIDENCE / 'canonical-complete.json').write_text(json.dumps({
        'candidate_commit': git_head(), 'candidate_tree': receipt['candidate_tree'],
        'native_generation': receipt['native_generation'], 'canonical_exit': 0}))


def cold(image: str) -> None:
    """A separate network-none container uses the SAME genuine native generation."""
    root, receipt = admitted()
    proof = json.loads((EVIDENCE / 'canonical-complete.json').read_text())
    expected = {'candidate_commit': git_head(), 'candidate_tree': receipt['candidate_tree'],
                'native_generation': receipt['native_generation'], 'canonical_exit': 0}
    if proof != expected:
        raise ValueError('cold restart requires this candidate canonical success')
    env = dict(receipt['environment'], TMPDIR=str(STATE))
    run([receipt['python'], '-B', 'scripts/docker_cold.py', str(root), '--image', image], env)
    validate_receipt(root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('phase', choices=('setup', 'verify', 'cold'))
    parser.add_argument('--admission-mode', choices=(MODE,), required=True)
    parser.add_argument('--image')
    args = parser.parse_args()
    guard()
    if args.phase != 'setup':
        from offline_guard import deny_network
        deny_network()
    if args.phase == 'setup':
        setup()
    elif args.phase == 'verify':
        verify()
    else:
        cold(args.image)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
