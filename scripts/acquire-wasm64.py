#!/usr/bin/env python3
"""Materialize pinned upstream sources plus reviewed memory64 patches.

A source with a patch digest is an upstream revision plus that reviewed patch;
one without is a fork revision that already carries the change. Acquisition
needs network access; subsequent builds can run offline. Existing checkouts
must match the pin and patch exactly and are never reset or cleaned.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PATCHES = ROOT / 'patches/wasm64'
DESTINATION = ROOT / 'third_party/wasm64'


def run(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd)


def abbreviation(patch):
    # Git abbreviates object names to the length its source repository needed;
    # a shallow acquisition would abbreviate differently, so compare at the
    # patch's own length.
    match = re.search(rb'^index ([0-9a-f]+)\.\.', patch, re.M)
    return len(match.group(1)) if match else 7


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    DESTINATION.mkdir(parents=True, exist_ok=True)
    for source in json.loads((PATCHES / 'sources.json').read_text()):
        name = source['name']
        patch = PATCHES / (name + '.patch')
        digest = source.get('patch_sha256')
        if digest is None:
            if patch.exists():
                raise ValueError(f'{name}: a fork revision takes no patch')
            expected = b''
        else:
            expected = patch.read_bytes()
            if hashlib.sha256(expected).hexdigest() != digest:
                raise ValueError(f'{name}: patch digest mismatch')
        dest = DESTINATION / name
        if not dest.exists():
            if args.verify_only:
                raise ValueError(f'{name}: acquire pinned memory64 sources first')
            run('git', 'init', '--quiet', str(dest))
            run('git', 'remote', 'add', 'origin', source['url'], cwd=dest)
            run('git', 'fetch', '--depth=1', 'origin', source['revision'], cwd=dest)
            run('git', 'checkout', '--detach', 'FETCH_HEAD', cwd=dest)
            if digest is not None:
                run('git', 'apply', str(patch), cwd=dest)
        if run('git', 'rev-parse', 'HEAD', cwd=dest).decode().strip() != source['revision']:
            raise ValueError(f'{name}: source revision mismatch')
        actual = run('git', 'diff', 'HEAD', '--binary', f'--abbrev={abbreviation(expected)}', cwd=dest)
        if actual != expected:
            raise ValueError(f'{name}: source patch differs; refusing to overwrite')
        if run('git', 'ls-files', '--others', '--exclude-standard', cwd=dest).strip():
            raise ValueError(f'{name}: untracked source files')
        print(f'WASM64-SOURCE PASS {name} {source["revision"]} {digest or "fork"}')


if __name__ == '__main__':
    main()
