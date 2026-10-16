#!/usr/bin/env python3
"""Supply the current physically fallible BTreeMap to selected native Core consumers."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import runpy
import shlex
import shutil
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def configured(name):
    value = os.environ.get(name.upper()) or shutil.which(name)
    if value is None or not Path(value).is_absolute():
        raise ValueError('fallible BTree source requires an absolute ' + name)
    return Path(value)


def source_inputs(compiler):
    sysroot = Path(subprocess.check_output([str(compiler), '--print', 'sysroot'], text=True).strip())
    if not sysroot.is_absolute():
        raise ValueError('configured compiler has no absolute sysroot')
    version = subprocess.check_output([str(compiler), '--version', '--verbose'], text=True)
    hosts = [line.removeprefix('host: ') for line in version.splitlines() if line.startswith('host: ')]
    if len(hosts) != 1:
        raise ValueError('configured compiler has no unique host')
    return sysroot.resolve(strict=True), version, hosts[0]


def acquire(compiler, build_root):
    functions = runpy.run_path(str(ROOT / 'scripts/prepare-fallible-btree-source.py'))
    original, version, host = source_inputs(compiler)
    supplier = original / 'lib/rustlib/src/rust/library'
    before = functions['inventory'](supplier)
    identity = {'sysroot': str(original), 'compiler': str(compiler), 'compiler_sha256': digest(compiler.resolve(strict=True)),
                'actual_rustc_sha256': digest(original / 'bin/rustc'), 'version': version,
                'profile_sha256': digest(functions['PROFILE'] / 'manifest.json'),
                'generator_sha256': digest(ROOT / 'scripts/prepare-fallible-btree-source.py'),
                'runner_sha256': digest(Path(__file__)),
                'inputs': before}
    profile = json.loads((functions['PROFILE'] / 'manifest.json').read_text())
    expected = {row['path']: dict(row) for row in before}
    for row in profile['files']:
        expected[row['path']]['sha256'] = row['after_sha256']
    expected = sorted(expected.values(), key=lambda row: row['path'])
    recipe = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    build_root.mkdir(parents=True, exist_ok=True)
    owned = build_root / recipe
    if owned.exists():
        record = json.loads((owned / 'producer.json').read_text())
        if record['identity'] != identity:
            raise ValueError('existing BTree source identity differs')
        receipt = json.loads((owned / 'source-receipt.json').read_text())
        if (receipt['original_inputs'] != before
                or receipt['profile_manifest_sha256'] != identity['profile_sha256']
                or receipt['generated_inputs'] != expected
                or functions['inventory'](owned / 'library') != expected):
            raise ValueError('existing BTree generated source differs')
        for name in ('rustc', 'rustdoc'):
            if digest(owned / name) != record[name + '_sha256']:
                raise ValueError('existing BTree compiler wrapper differs')
    else:
        owned.mkdir()
        receipt = functions['prepare'](supplier, owned / 'library')
        compiler_wrapper = functions['sysroot_view'](original, owned / 'library', owned / 'sysroot', compiler)
        rustdoc = configured('rustdoc')
        document_wrapper = owned / 'rustdoc'
        document_wrapper.write_text('#!/bin/sh\nexec ' + shlex.quote(str(rustdoc))
                                    + ' --sysroot ' + shlex.quote(str(owned / 'sysroot')) + ' "$@"\n')
        document_wrapper.chmod(0o755)
        record = {'identity': identity, 'host': host,
                  'rustc_sha256': digest(compiler_wrapper), 'rustdoc_sha256': digest(document_wrapper),
                  'source_receipt_sha256': digest(owned / 'source-receipt.json')}
        (owned / 'producer.json').write_text(json.dumps(record, indent=2) + '\n')
    if (owned / 'sysroot/lib/rustlib/src/rust/library').resolve(strict=True) != owned / 'library':
        raise ValueError('owned sysroot does not select generated liballoc source')
    return owned, functions, receipt, host


def working_directory(manifest, owned):
    # Cargo build-std resolves its own locked registry dependencies. Give it the
    # same reviewed project configuration plus the acquired standard-library
    # vendor closure, without editing the project/vendor or toolchain aliases.
    configs = [parent / '.cargo/config.toml' for parent in (manifest.parent, *manifest.parent.parents)
               if (parent / '.cargo/config.toml').is_file()]
    if len(configs) != 1:
        raise ValueError('native BTree source requires the single current project Cargo configuration')
    original = configs[0]
    text = original.read_text()
    data = tomllib.loads(text)
    vendor = Path(data['source']['vendored-sources']['directory'])
    if not vendor.is_absolute():
        vendor = original.parent.parent / vendor
    union = owned / 'vendor'
    union.mkdir(exist_ok=True)
    for supplier in (vendor, owned / 'library/vendor'):
        for package in supplier.iterdir():
            target = union / package.name
            if target.exists():
                if (json.loads((target / '.cargo-checksum.json').read_text())['package']
                        != json.loads((package / '.cargo-checksum.json').read_text())['package']):
                    raise ValueError('conflicting native/std vendor package: ' + package.name)
                if supplier == vendor:
                    target.unlink()
                    target.symlink_to(package.resolve(strict=True))
            else:
                target.symlink_to(package.resolve(strict=True))
    configuration = owned / 'work/.cargo'
    configuration.mkdir(parents=True, exist_ok=True)
    source_value = data['source']['vendored-sources']['directory']
    before = 'directory = ' + json.dumps(source_value)
    if text.count(before) != 1:
        raise ValueError('current Cargo vendor owner is ambiguous')
    (configuration / 'config.toml').write_text(text.replace(before, 'directory = ' + json.dumps(str(union))))
    return configuration.parent


def command_arguments(arguments, manifest, host):
    boundary = arguments.index('--') if '--' in arguments else len(arguments)
    front, tail = list(arguments[:boundary]), list(arguments[boundary:])
    if not any(value == '--manifest-path' or value.startswith('--manifest-path=') for value in front):
        front += ['--manifest-path', str(manifest)]
    targets = [front[index + 1] for index, value in enumerate(front[:-1]) if value == '--target']
    targets += [value.partition('=')[2] for value in front if value.startswith('--target=')]
    if targets and targets != [host]:
        raise ValueError('native BTree source cannot replace another target profile')
    if not targets:
        front += ['--target', host]
    if not any(value.startswith('-Zbuild-std') for value in front):
        front += ['-Zbuild-std=std,panic_unwind,test']
    return front + tail


@contextmanager
def source_context(manifest, build_root, arguments):
    compiler = configured('rustc')
    owned, functions, receipt, host = acquire(compiler, build_root)
    work = working_directory(manifest, owned)
    before = {name: os.environ.get(name) for name in ('RUSTC', 'RUSTDOC', 'SYSROOT', 'RUSTUP_TOOLCHAIN', 'HONEST_BTREE_SOURCE_RECEIPT')}
    cwd = Path.cwd()
    try:
        os.environ.update(RUSTC=str(owned / 'rustc'), RUSTDOC=str(owned / 'rustdoc'),
                          SYSROOT=str(owned / 'sysroot'),
                          RUSTUP_TOOLCHAIN=json.loads((owned / 'producer.json').read_text())['identity']['sysroot'],
                          HONEST_BTREE_SOURCE_RECEIPT=str(owned / 'source-receipt.json'))
        os.chdir(work)
        yield command_arguments(arguments, manifest, host)
    finally:
        os.chdir(cwd)
        for name, value in before.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        if (functions['inventory'](Path(receipt['source'])) != receipt['original_inputs']
                or functions['inventory'](owned / 'library') != receipt['generated_inputs']):
            raise ValueError('BTree compiler source changed during build')


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--build-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.rustc.is_absolute() or not args.build_root.is_absolute() or not args.output.is_absolute():
        parser.error('compiler and build-owned paths must be absolute')
    if args.output.parent != args.build_root:
        parser.error('source input receipt must belong to the build root')
    owned, functions, receipt, _ = acquire(args.rustc, args.build_root)
    inputs = [{'path': str(owned / 'library' / row['path']),
               'name': 'liballoc/' + row['path'], 'sha256': row['sha256']}
              for row in receipt['generated_inputs']]
    inputs += [{'path': str(path), 'name': 'profile/' + path.name, 'sha256': digest(path)}
               for path in (functions['PROFILE'] / 'manifest.json', functions['PROFILE'] / 'profile.patch',
                            ROOT / 'scripts/prepare-fallible-btree-source.py', Path(__file__))]
    record = {'schema': 1, 'profile': 'fallible-btree-insertion',
              'rustc': str(owned / 'rustc'), 'sysroot': str(owned / 'sysroot'),
              'receipt': str(owned / 'source-receipt.json'), 'inputs': inputs}
    args.output.write_text(json.dumps(record, indent=2) + '\n')
    print('FALLIBLE-BTREE-SOURCE', receipt['profile_manifest_sha256'])


if __name__ == '__main__':
    main()
