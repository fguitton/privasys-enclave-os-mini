#!/usr/bin/env python3
"""Prepare guarded liballoc insertion source and a build-owned compiler sysroot view."""
import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / 'patches/rust/fallible-btree-insertion'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative(value):
    path = Path(value)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('invalid liballoc input path')
    return path


def inventory(root):
    rows = []
    for path in sorted(root.rglob('*'), key=lambda path: path.relative_to(root).as_posix()):
        if path.is_symlink():
            raise ValueError('compiler source symlink is unsupported')
        if path.is_file():
            rows.append({'path': path.relative_to(root).as_posix(),
                         'sha256': digest(path), 'mode': path.stat().st_mode & 0o777})
    if not rows:
        raise ValueError('compiler source inventory is empty')
    return rows


def owned_file_mode(mode):
    """Owned sources need read/write access; donor executable bits survive."""
    return mode | stat.S_IRUSR | stat.S_IWUSR


def writable_owned_tree(root):
    for parent, directories, files in os.walk(root, followlinks=False):
        for path in (Path(parent), *(Path(parent) / name for name in (*directories, *files))):
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                mode = stat.S_IMODE(metadata.st_mode) | stat.S_IRWXU
            elif stat.S_ISREG(metadata.st_mode):
                mode = owned_file_mode(stat.S_IMODE(metadata.st_mode))
            else:
                raise ValueError('owned compiler source symlink or irregular member is unsupported')
            path.chmod(mode, follow_symlinks=False)


def prepare(source, destination):
    manifest = json.loads((PROFILE / 'manifest.json').read_text())
    if manifest['schema'] != 1 or manifest['profile'] != 'fallible-btree-insertion':
        raise ValueError('unsupported liballoc source profile')
    if len(manifest['files']) != 3 or len({row['path'] for row in manifest['files']}) != 3:
        raise ValueError('ambiguous liballoc source owners')
    patch = PROFILE / 'profile.patch'
    if digest(patch) != manifest['patch_sha256']:
        raise ValueError('liballoc source patch differs')
    source = source.resolve(strict=True)
    if destination.exists() or destination.is_symlink():
        raise ValueError('liballoc source destination must be new')
    parent = destination.parent.resolve(strict=True)
    if parent == source or source in parent.parents:
        raise ValueError('liballoc destination must be outside compiler source')
    for row in manifest['files']:
        path = source / relative(row['path'])
        if not path.is_file() or path.is_symlink() or digest(path) != row['before_sha256']:
            raise ValueError('liballoc input differs: ' + row['path'])
    before = inventory(source)
    shutil.copytree(source, destination, copy_function=shutil.copy2, symlinks=True)
    writable_owned_tree(destination)
    environment = {'PATH': '/usr/bin:/bin', 'GIT_CEILING_DIRECTORIES': str(parent)}
    subprocess.run(['git', 'apply', '--check', str(patch)], cwd=destination,
                   env=environment, check=True)
    subprocess.run(['git', 'apply', str(patch)], cwd=destination,
                   env=environment, check=True)
    expected = {row['path']: {**row, 'mode': owned_file_mode(row['mode'])} for row in before}
    for row in manifest['files']:
        expected[row['path']]['sha256'] = row['after_sha256']
    for row in manifest['files']:
        (destination / row['path']).chmod(expected[row['path']]['mode'])
    after = inventory(destination)
    if after != sorted(expected.values(), key=lambda row: row['path']):
        raise ValueError('generated liballoc source inventory differs')
    if before != inventory(source):
        raise ValueError('original compiler source changed during acquisition')
    receipt = {'schema': 1, 'profile': manifest['profile'],
               'profile_manifest_sha256': digest(PROFILE / 'manifest.json'),
               'patch_sha256': digest(patch), 'source': str(source),
               'original_inputs': before, 'generated_inputs': after,
               'scope': 'source acquisition only; no compilation/runtime qualification'}
    (destination.parent / 'source-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def sysroot_view(original, library, destination, compiler):
    if destination.exists() or destination.is_symlink():
        raise ValueError('sysroot view must be new')
    destination.mkdir()
    def link_entries(source, target, descend):
        for child in source.iterdir():
            path = target / child.name
            if child.name in descend:
                path.mkdir()
                link_entries(child, path, descend[child.name])
            else:
                path.symlink_to(child)
    link_entries(original, destination, {'lib': {'rustlib': {'src': {'rust': {}}}}})
    # The source subtree is the only changed input in this owned view.
    rust = destination / 'lib/rustlib/src/rust'
    for path in rust.iterdir():
        path.unlink()
    (rust / 'library').symlink_to(library)
    wrapper = destination.parent / 'rustc'
    # Preserve the configured executable's argv[0], including rustup dispatch.
    import shlex
    wrapper.write_text('#!/bin/sh\nexec ' + shlex.quote(str(compiler))
                       + ' --sysroot ' + shlex.quote(str(destination)) + ' "$@"\n')
    wrapper.chmod(0o755)
    result = subprocess.check_output([str(wrapper), '--print', 'sysroot'], text=True).strip()
    if Path(result) != destination:
        raise ValueError('compiler did not select owned sysroot')
    return wrapper


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    receipt = prepare(args.source, args.destination)
    print('FALLIBLE-BTREE-SOURCE PASS', receipt['profile_manifest_sha256'])


if __name__ == '__main__':
    main()
