#!/usr/bin/env python3
"""Exercise the actual selected SDK map backend with native refusal/lifetime hooks."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

MINI = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk-source', type=Path, required=True)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.rustc.is_absolute() or not args.rustc.is_file():
        parser.error('an acquired absolute rustc is required')
    if not args.output.is_absolute() or args.output.exists() or args.output.is_symlink():
        parser.error('output must be a new absolute task-owned path')
    sdk = args.sdk_source.resolve(strict=True)
    manifest_path = MINI / 'patches/teaclave/fallible-allocation-v1/manifest.json'
    manifest = json.loads(manifest_path.read_text())
    for row in manifest['files']:
        path = sdk / row['path']
        if path.is_symlink() or digest(path) != row['after_sha256']:
            raise ValueError('selected SDK source differs: ' + row['path'])
    receipt = json.loads((sdk / 'fallible-allocation-source-receipt-v1.json').read_text())
    if receipt['manifest_sha256'] != digest(manifest_path):
        raise ValueError('SDK acquisition receipt belongs to another profile')
    expected = [row for row in receipt['copied_inputs']
                if row['path'].startswith('sgx_tstd/hashbrown/')]
    if not expected:
        raise ValueError('actual hashbrown backend source identity is missing')
    for row in expected:
        if digest(sdk / row['path']) != row['sha256']:
            raise ValueError('actual backend source differs: ' + row['path'])
    args.output.mkdir(parents=True, mode=0o700)
    backend = sdk / 'sgx_tstd/hashbrown'
    library = args.output / 'libhashbrown_tstd.rlib'
    fixture = MINI / 'tests/owned-cache/native.rs'
    executable = args.output / 'native'
    commands = [
        ('backend', [str(args.rustc), '--edition=2021', '--crate-name=hashbrown_tstd',
                     '--crate-type=rlib', '--cfg', 'feature="nightly"',
                     '--cfg', 'feature="rustc-dep-of-std"', '--cfg',
                     'feature="rustc-internal-api"', str(backend / 'src/lib.rs'),
                     '-o', str(library)]),
        ('fixture', [str(args.rustc), '--edition=2021', '--test', '-Dwarnings',
                     '--extern', 'hashbrown_tstd=' + str(library), str(fixture),
                     '-o', str(executable)]),
        ('discovery', [str(executable), '--list']),
        ('bodies', [str(executable), '--test-threads=1']),
    ]
    rows = []
    for name, command in commands:
        with (args.output / (name + '.log')).open('xb') as stream:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT)
        rows.append({'name': name, 'command': command, 'exit_code': result.returncode,
                     'log_sha256': digest(args.output / (name + '.log'))})
        if result.returncode:
            break
    for row in expected:
        if digest(sdk / row['path']) != row['sha256']:
            raise ValueError('actual backend changed during execution')
    passed = len(rows) == len(commands) and all(row['exit_code'] == 0 for row in rows)
    if passed:
        passed = ('3 tests, 0 benchmarks' in (args.output / 'discovery.log').read_text()
                  and '3 passed; 0 failed' in (args.output / 'bodies.log').read_text())
    result = {'status': 'PASS' if passed else 'FAIL', 'rows': rows,
              'profile_manifest_sha256': digest(manifest_path),
              'sdk_acquisition_sha256': digest(sdk / 'fallible-allocation-source-receipt-v1.json'),
              'fixture_sha256': digest(fixture), 'runner_sha256': digest(Path(__file__)),
              'rustc_sha256': digest(args.rustc), 'backend_files': expected,
              'scope': 'Actual SDK backend native constructor/growth refusal and origin lifetime; '
                       'native allocator adapter, no SGX execution/metadata-origin/authority claim.'}
    (args.output / 'terminal.json').write_text(json.dumps(result, indent=2) + '\n')
    print(result['status'])
    if not passed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
