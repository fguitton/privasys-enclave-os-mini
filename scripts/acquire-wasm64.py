#!/usr/bin/env python3
"""Materialize pinned upstream sources plus reviewed memory64 patches.

A source with a patch digest is an upstream revision plus that reviewed patch;
one without is a fork revision that already carries the change. Every source
pins the digest of its materialized files, which is what builds rely on: git's
own view of a checkout can be changed locally by index flags, filters, replace
references or excludes, so it is checked only for clearer errors. Acquisition
needs network access; verification is offline. Existing checkouts must match
exactly and are never reset or cleaned.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PATCHES = ROOT / 'patches/wasm64'
DESTINATION = ROOT / 'third_party/wasm64'
# Git settings a local configuration could otherwise use to run commands or
# rewrite what the checks below read. A root build verifies a checkout another
# user owns; the file digest, not git, is what it trusts.
GIT = ['git', '-c', 'core.fsmonitor=', '-c', 'core.hooksPath=/dev/null',
       '-c', 'core.autocrlf=false', '-c', 'safe.directory=*']
GIT_ENVIRONMENT = dict(os.environ, GIT_NO_REPLACE_OBJECTS='1')


def git(*args, cwd, stdin=None):
    return subprocess.run([*GIT, *args], cwd=cwd, env=GIT_ENVIRONMENT, input=stdin,
                          stdout=subprocess.PIPE, check=True).stdout


def abbreviation(patch):
    # Git abbreviates object names to the length its source repository needed;
    # a shallow acquisition would abbreviate differently, so compare at the
    # patch's own length.
    match = re.search(rb'^index ([0-9a-f]+)\.\.', patch, re.M)
    return len(match.group(1)) if match else 7


def files_digest(dest):
    """Digest every regular file and symbolic link under a checkout but `.git`:
    its path, its kind and its bytes or target. Modes are left out, since a
    checkout on a Windows mount reports every file as executable."""
    entries = []
    for directory, subdirectories, files in os.walk(dest, followlinks=False):
        relative = Path(directory).relative_to(dest)
        if relative == Path('.'):
            subdirectories[:] = [name for name in subdirectories if name != '.git']
            files = [name for name in files if name != '.git']
        for name in subdirectories:
            path = Path(directory) / name
            if path.is_symlink():
                entries.append(((relative / name).as_posix(), b'l', os.readlink(path).encode()))
        for name in files:
            path = Path(directory) / name
            if path.is_symlink():
                entries.append(((relative / name).as_posix(), b'l', os.readlink(path).encode()))
            elif path.is_file():
                entries.append(((relative / name).as_posix(), b'f',
                                hashlib.sha256(path.read_bytes()).digest()))
            else:
                raise ValueError(f'{path}: not a regular file or symbolic link')
    digest = hashlib.sha256()
    for path, kind, payload in sorted(entries):
        digest.update(path.encode() + b'\0' + kind + len(payload).to_bytes(4, 'big') + payload)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--print-digests', action='store_true',
                        help='print each materialized digest instead of requiring the pin')
    args = parser.parse_args()
    DESTINATION.mkdir(parents=True, exist_ok=True)
    for source in json.loads((PATCHES / 'sources.json').read_text(encoding='utf-8')):
        name = source['name']
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]*', name):
            raise ValueError(f'{name!r}: invalid source name')
        patch = PATCHES / (name + '.patch')
        digest = source.get('patch_sha256')
        if digest is None:
            if patch.exists():
                raise ValueError(f'{name}: a fork revision takes no patch')
            expected = b''
        else:
            # Read once: the same bytes are checked, applied and compared.
            expected = patch.read_bytes()
            if hashlib.sha256(expected).hexdigest() != digest:
                raise ValueError(f'{name}: patch digest mismatch')
        dest = DESTINATION / name
        if not dest.exists():
            if args.verify_only:
                raise ValueError(f'{name}: acquire pinned memory64 sources first')
            git('init', '--quiet', str(dest), cwd=None)
            git('remote', 'add', 'origin', source['url'], cwd=dest)
            git('fetch', '--depth=1', 'origin', source['revision'], cwd=dest)
            git('checkout', '--detach', 'FETCH_HEAD', cwd=dest)
            if digest is not None:
                git('apply', '-', cwd=dest, stdin=expected)
        if git('rev-parse', 'HEAD', cwd=dest).decode().strip() != source['revision']:
            raise ValueError(f'{name}: source revision mismatch')
        actual = git('diff', 'HEAD', '--binary', '--no-ext-diff', '--no-textconv',
                     f'--abbrev={abbreviation(expected)}', cwd=dest)
        if actual != expected:
            raise ValueError(f'{name}: source patch differs; refusing to overwrite')
        materialized = files_digest(dest)
        if args.print_digests:
            print(f'WASM64-SOURCE DIGEST {name} {materialized}')
            continue
        if materialized != source['files_sha256']:
            raise ValueError(f'{name}: materialized files differ from the pinned digest')
        print(f'WASM64-SOURCE PASS {name} {source["revision"]} {digest or "fork"} {materialized}')


if __name__ == '__main__':
    main()
