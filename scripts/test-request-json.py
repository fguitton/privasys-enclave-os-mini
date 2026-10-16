#!/usr/bin/env python3
"""Focused native request admission proof using an exact current supplier lock."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def audit(root):
    return [{'path': str(path.relative_to(root)), 'sha256': digest(path),
             'mode': path.stat().st_mode & 0o777}
            for path in sorted(root.rglob('*')) if path.is_file()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cargo', type=Path, required=True)
    parser.add_argument('--lock', type=Path, required=True)
    parser.add_argument('--vendor', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not all(path.is_absolute() for path in (args.cargo, args.lock, args.vendor, args.output)):
        parser.error('all inputs and output must be absolute')
    args.output.mkdir(mode=0o700)
    source = args.output / 'source'
    source.mkdir()
    before = audit(ROOT / 'common')
    shutil.copytree(ROOT / 'common', source / 'common')
    if before != audit(ROOT / 'common') or before != audit(source / 'common'):
        raise ValueError('Common source changed during capture')
    for name in ('enclave/src/rpc_client.rs', 'enclave/src/ratls/retained_quote.rs',
                 'enclave/src/ratls/request_json.rs'):
        destination = source / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
        if digest(ROOT / name) != digest(destination):
            raise ValueError('fixture source copy differs')
    (source / 'Cargo.toml').write_text('[workspace]\nmembers = ["common"]\nresolver = "2"\n'
                                      '[workspace.package]\nversion = "0.1.0"\n'
                                      'edition = "2021"\nlicense = "AGPL-3.0"\n')
    shutil.copyfile(args.lock, source / 'Cargo.lock')
    cargo_home = args.output / 'cargo'
    cargo_home.mkdir()
    (cargo_home / 'config.toml').write_text('[source.crates-io]\nreplace-with = "vendored-sources"\n'
                                          '[source.vendored-sources]\ndirectory = ' + json.dumps(str(args.vendor)) + '\n')
    env = os.environ.copy()
    for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER',
                 'RUSTC_WORKSPACE_WRAPPER', 'LD_PRELOAD', 'LD_AUDIT', 'LIBSQLITE3_FLAGS'):
        env.pop(name, None)
    env.update(CARGO_HOME=str(cargo_home), CARGO_TARGET_DIR=str(args.output / 'target'),
               CARGO_NET_OFFLINE='true', CARGO_INCREMENTAL='0')
    rows = []

    def execute(name, command):
        log = args.output / (name + '.log')
        with log.open('xb') as stream:
            result = subprocess.run(command, cwd=source, env=env, stdout=stream, stderr=subprocess.STDOUT)
        rows.append({'name': name, 'command': command, 'exit_code': result.returncode,
                     'log_sha256': digest(log)})
        (args.output / 'steps.json').write_text(json.dumps(rows, indent=2) + '\n')
        if result.returncode:
            raise RuntimeError(name + ' failed; see ' + str(log))
        return log

    execute('source-controls', [sys.executable, '-B', str(ROOT / 'tests/request-json/source_controls.py'),
                                '--vendor', str(args.vendor), '--output', str(args.output / 'source-controls')])
    # Isolated test workspace resolution may trim unrelated packages, never update versions.
    execute('prepare-test-lock', [str(args.cargo), 'metadata', '--offline', '--format-version', '1'])
    original = {(row['name'], row['version']) for row in tomllib.loads(args.lock.read_text())['package']}
    resolved = tomllib.loads((source / 'Cargo.lock').read_text())['package']
    if any((row['name'], row['version']) not in original for row in resolved):
        raise ValueError('test workspace introduced a dependency version')
    expected_source = audit(source)
    (args.output / 'compiler-source-manifest.json').write_text(json.dumps(expected_source, indent=2) + '\n')
    manifest = source / 'common/Cargo.toml'
    wrapper = [sys.executable, '-B', str(ROOT / 'scripts/run-request-json-cargo.py'),
               '--cargo', str(args.cargo), '--manifest-path', str(manifest),
               '--build-root', str(args.output / 'json-source'), '--']
    base = ['--locked', '--offline', '--manifest-path', str(manifest), '--features', 'request-json-tests', '--lib']
    discovery = execute('request-discovery', wrapper + ['test', *base, 'attest::request_tests::',
                                                       '--', '--list', '--format=json', '-Z', 'unstable-options'])
    records = [json.loads(line) for line in discovery.read_text().splitlines() if line.startswith('{')]
    tests = [row for row in records if row.get('event') == 'discovered' and row.get('type') == 'test']
    if len(tests) != 6 or any(row['ignore'] for row in tests):
        raise ValueError('request admission discovery differs')
    execution = execute('request-admission', wrapper + ['test', *base, 'attest::request_tests::',
                                                      '--', '--test-threads=1'])
    if '6 passed; 0 failed; 0 ignored' not in execution.read_text():
        raise ValueError('request admission execution count differs')
    execute('common-library-strict', wrapper + ['clippy', '--locked', '--offline', '--manifest-path', str(manifest),
                                                '--features', 'crypto', '--lib', '--', '-D', 'warnings'])
    execute('request-all-targets-strict', wrapper + ['clippy', '--locked', '--offline', '--manifest-path', str(manifest),
                                                    '--features', 'request-json-tests', '--all-targets', '--', '-D', 'warnings'])
    if expected_source != audit(source):
        raise ValueError('compiler source changed during qualification')
    (args.output / 'receipt.json').write_text(json.dumps({'status': 'PASS', 'discovered': 6, 'executed': 6,
                                                        'lock_input_sha256': digest(args.lock),
                                                        'resolved_lock_sha256': digest(source / 'Cargo.lock'),
                                                        'compiler_source_unchanged': True,
                                                        'claim': 'native request admission only; no endpoint/target/whole-parser qualification'}, indent=2) + '\n')
    print('REQUEST-JSON-ADMISSION PASS discovered=6 executed=6')


if __name__ == '__main__':
    main()
