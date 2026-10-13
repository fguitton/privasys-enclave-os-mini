#!/usr/bin/env python3
"""Create an exact task-owned SDK copy for the default-off allocation profile."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / 'patches/teaclave/fallible-allocation-v1'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def prepare(source, identity, destination):
    manifest = json.loads((PROFILE / 'manifest.json').read_text())
    if manifest['schema'] != 1 or manifest['profile'] != 'fallible-allocation-v1':
        raise ValueError('unsupported source profile')
    if not manifest['files'] or not manifest['patches']:
        raise ValueError('source profile must contain files and patches')
    revision = subprocess.check_output(
        ['git', '-C', str(identity), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != manifest['base_sdk_commit']:
        raise ValueError('SDK identity differs from acquired base')
    if destination.exists() or destination.is_symlink():
        raise ValueError('destination must be new')
    source = source.resolve(strict=True)
    parent = destination.parent.resolve(strict=True)
    if source == parent or source in parent.parents:
        raise ValueError('destination must be outside SDK source')
    for row in manifest['files']:
        path = Path(row['path'])
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('invalid manifest path')
        original = source / path
        expected = row['before_sha256']
        if expected is None:
            if original.exists() or original.is_symlink():
                raise ValueError('new allocator module already exists')
        elif not original.is_file() or original.is_symlink() or digest(original) != expected:
            raise ValueError('original SDK input differs: ' + str(path))
    patches = []
    for row in manifest['patches']:
        relative = Path(row['path'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('invalid patch path')
        path = PROFILE / relative
        if not path.is_file() or path.is_symlink() or digest(path) != row['sha256']:
            raise ValueError('source patch differs')
        patches.append(path)
    names = subprocess.check_output(
        ['git', '-C', str(identity), 'ls-tree', '-r', '--name-only', revision], text=True).splitlines()
    # The already reviewed locked std recipe adds this one acquired input.
    names.append('rustlib/std/Cargo.lock')
    destination.mkdir(mode=0o700)
    copied = []
    for name in sorted(set(names)):
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('unsafe pinned input path')
        old = source / relative
        if not old.is_file() or old.is_symlink():
            raise ValueError('nonregular/missing pinned input: ' + name)
        new = destination / relative
        new.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(old, new)
        if digest(old) != digest(new):
            raise ValueError('SDK copy differs: ' + name)
        copied.append({'path': name, 'sha256': digest(new)})
    for patch in patches:
        subprocess.run(['git', 'apply', '--check', str(patch)],
                       cwd=destination, check=True, env={'PATH': '/usr/bin:/bin', 'GIT_CEILING_DIRECTORIES': str(parent)})
        subprocess.run(['git', 'apply', str(patch)],
                       cwd=destination, check=True, env={'PATH': '/usr/bin:/bin', 'GIT_CEILING_DIRECTORIES': str(parent)})
    after = []
    for row in manifest['files']:
        path = destination / row['path']
        if not path.is_file() or path.is_symlink() or digest(path) != row['after_sha256']:
            raise ValueError('patched SDK differs: ' + row['path'])
        after.append({'path': row['path'], 'sha256': digest(path)})
    receipt = {'schema': 1, 'profile': manifest['profile'], 'base_sdk_commit': revision,
               'manifest_sha256': digest(PROFILE / 'manifest.json'), 'copied_inputs': copied,
               'afterimages': after, 'scope': 'source acquisition only; no SDK/std/build/runtime qualification'}
    (destination / 'fallible-allocation-source-receipt-v1.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--identity', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    receipt = prepare(args.source, args.identity, args.destination)
    print('FALLIBLE-SDK-SOURCE PASS', receipt['manifest_sha256'])


if __name__ == '__main__':
    main()
