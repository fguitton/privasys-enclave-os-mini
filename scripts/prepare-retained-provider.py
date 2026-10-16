#!/usr/bin/env python3
"""Materialize a verified, build-owned rustls provider source; never edit vendor."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

PROFILE = Path(__file__).resolve().parents[1] / 'patches/rustls/retained-provider'
PATCH = Path('/usr/bin/patch')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative(name):
    path = Path(name)
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('unsafe source path')
    return path


def verified(path, expected):
    if path.is_symlink() or not path.is_file() or digest(path) != expected:
        raise ValueError('source differs: ' + str(path))


def prepare(source, destination):
    manifest = json.loads((PROFILE / 'manifest.json').read_text())
    if manifest['schema'] != 1 or manifest['profile'] != 'retained-provider':
        raise ValueError('unsupported source profile')
    source = source.resolve(strict=True)
    checksum_path = source / '.cargo-checksum.json'
    checksum_hash = digest(checksum_path)
    suppliers = [row for row in manifest['suppliers']
                 if row['base_checksum_manifest_sha256'] == checksum_hash]
    if len(suppliers) != 1:
        raise ValueError('acquired package identity differs')
    supplier = suppliers[0]
    verified(checksum_path, supplier['base_checksum_manifest_sha256'])
    checks = json.loads(checksum_path.read_text())
    if checks['package'] != supplier['base_package_checksum']:
        raise ValueError('acquired package checksum differs')
    patch = PROFILE / 'profile.patch'
    verified(patch, manifest['patch_sha256'])
    if destination.exists() or destination.is_symlink():
        raise ValueError('destination must be new')
    parent = destination.parent.resolve(strict=True)
    if source == parent or source in parent.parents:
        raise ValueError('destination must be outside acquired source')
    original = []
    for name, expected in sorted(checks['files'].items()):
        path = source / relative(name)
        verified(path, expected)
        original.append({'path': name, 'sha256': expected,
                         'mode': path.stat().st_mode & 0o777})
    for row in supplier['files']:
        before = source / relative(row['path'])
        if row['before_sha256'] is None:
            if before.exists() or before.is_symlink():
                raise ValueError('new source path already exists: ' + str(before))
        else:
            verified(before, row['before_sha256'])
    destination.mkdir(mode=0o700)
    for row in original:
        path = relative(row['path'])
        output = destination / path
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / path, output)
        output.chmod(row['mode'])
        verified(output, row['sha256'])
    subprocess.run([str(PATCH), '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                   cwd=destination, check=True)
    expected_after = {row['path']: row['sha256'] for row in original}
    expected_after.update({row['path']: row['after_sha256'] for row in supplier['files']})
    generated = []
    for row in original:
        verified(source / relative(row['path']), row['sha256'])
    actual = {p.relative_to(destination).as_posix() for p in destination.rglob('*') if p.is_file()}
    if actual != set(expected_after):
        raise ValueError('generated source inventory differs')
    for name, expected in sorted(expected_after.items()):
        output = destination / relative(name)
        verified(output, expected)
        generated.append({'path': name, 'sha256': expected, 'mode': output.stat().st_mode & 0o777})
    verified(checksum_path, checksum_hash)
    receipt = {'schema': 1, 'profile': 'retained-provider',
               'package': supplier['package'], 'version': supplier['version'],
               'routing': manifest['routing'],
               'base_checksum_manifest_sha256': checksum_hash,
               'profile_manifest_sha256': digest(PROFILE / 'manifest.json'),
               'generator_sha256': digest(Path(__file__).resolve()),
               'patch_sha256': digest(patch), 'patch_tool_sha256': digest(PATCH),
               'original_files': original, 'generated_files': generated,
               'scope': 'source acquisition only; no endpoint, build or runtime qualification'}
    (destination / 'retained-provider-source-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    receipt = prepare(args.source, args.destination)
    print('RETAINED-PROVIDER-SOURCE', receipt['version'], receipt['profile_manifest_sha256'])


if __name__ == '__main__':
    main()
