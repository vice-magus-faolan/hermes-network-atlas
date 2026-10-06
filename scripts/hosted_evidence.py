#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compact PUBLIC hosted proof export; no contexts, homes, tools or opaque caches."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile

from docker_evidence import regular_read

LIMIT = 128 * 1024 ** 2


def selected(root: Path) -> list[Path]:
    if root.is_symlink() or root.resolve(strict=True) != root:
        raise ValueError('literal owned evidence root required')
    groups = [root / name for name in ('summary', 'bootstrap', 'registry')]
    groups.extend(sorted((root / 'evidence').glob('*/export')))
    groups.extend(sorted((root / 'evidence').glob('*/metadata')))
    paths = []
    for group in groups:
        if not group.exists():
            continue
        if group.is_symlink() or not group.resolve().is_relative_to(root):
            raise ValueError('evidence directory escape')
        for path in sorted(group.iterdir()):
            if path.is_symlink() or not path.is_file():
                raise ValueError('nonregular evidence member')
            paths.append(path)
            if len(paths) > 256:
                raise ValueError('compact evidence count bound')
    if not paths:
        raise ValueError('missing hosted proof; not a successful attempt')
    return paths


def pack(root: Path, destination: Path) -> dict:
    paths = selected(root)
    manifest = {}
    size = 10240
    for path in paths:
        payload = regular_read(path, 8 * 1024 ** 2)
        size += 512 + ((len(payload) + 511) // 512) * 512
        manifest[str(path.relative_to(root))] = {'sha256': hashlib.sha256(payload).hexdigest(), 'bytes': len(payload)}
    data = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    if size + len(data) + 20480 > LIMIT:
        raise ValueError('aggregate evidence bound before archive writes')
    with destination.open('xb') as stream:
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as bundle:
            for path in paths:
                payload = regular_read(path, 8 * 1024 ** 2)
                name = str(path.relative_to(root))
                if hashlib.sha256(payload).hexdigest() != manifest[name]['sha256']:
                    raise ValueError('proof changed during export')
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                bundle.addfile(member, io.BytesIO(payload))
            member = tarfile.TarInfo('hashes.json')
            member.size = len(data)
            bundle.addfile(member, io.BytesIO(data))
    if destination.stat().st_size > LIMIT:
        raise ValueError('archive padding bound')
    return {'members': len(manifest), 'bytes': destination.stat().st_size,
            'sha256': hashlib.sha256(destination.read_bytes()).hexdigest(), 'acceptance_inferred': False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('root', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    print(json.dumps(pack(args.root, args.destination), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
