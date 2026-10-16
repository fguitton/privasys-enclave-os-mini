#!/usr/bin/env python3
"""Exercise actual native parser source routing, refusal and repeat invocation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cargo', type=Path, required=True)
    parser.add_argument('--manifest-path', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    runner = ROOT / 'scripts/run-request-json-cargo.py'
    env = os.environ.copy()
    env.pop('HONEST_REQUEST_JSON_SOURCE_RECEIPT', None)
    records = []

    def execute(name, command, success=True, diagnostic=None):
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        (args.output / (name + '.stdout')).write_text(result.stdout)
        (args.output / (name + '.stderr')).write_text(result.stderr)
        if (result.returncode == 0) != success:
            raise AssertionError(name + ': ' + result.stderr)
        if diagnostic and diagnostic not in result.stderr:
            raise AssertionError(name + ': missing diagnostic')
        records.append({'name': name, 'command': list(map(str, command)), 'exit_code': result.returncode})

    base = ['check', '--locked', '--offline', '--manifest-path', str(args.manifest_path),
            '--features', 'request-json-parser', '--lib']
    execute('direct-cargo-refuses-unprepared-parser', [str(args.cargo), *base], False,
            'request-json-parser requires its verified supplier')
    wrapped = [sys.executable, '-B', str(runner), '--cargo', str(args.cargo),
               '--build-root', str(args.output / 'supplier'), '--']
    execute('native-parser-route', wrapped + base)
    source = args.output / 'supplier'
    generated = list(source.glob('serde_json-*/Cargo.toml'))
    if len(generated) != 1:
        raise AssertionError('native route did not produce one supplier')
    manifest = generated[0].parent / 'request-json-source-receipt.json'
    before = hashlib.sha256(manifest.read_bytes()).hexdigest()
    execute('repeated-native-parser-route', wrapped + base)
    if hashlib.sha256(manifest.read_bytes()).hexdigest() != before:
        raise AssertionError('repeat invocation changed supplier identity')
    config = __import__('tomllib').loads((source / 'cargo-source.toml').read_text())
    if config['paths'] != [str(generated[0].parent)]:
        raise AssertionError('source route accumulated duplicate supplier paths')
    fixture = args.output / 'ordinary'
    fixture.mkdir()
    ordinary = fixture / 'Cargo.toml'
    ordinary.write_text('[workspace]\n[package]\nname="native-json-route-control"\nversion="0.0.0"\nedition="2021"\n[lib]\npath="lib.rs"\n')
    (fixture / 'lib.rs').write_text('pub fn unrelated() {}\n')
    execute('ordinary-lock', [str(args.cargo), 'generate-lockfile', '--offline', '--manifest-path', str(ordinary)])
    execute('ordinary-native-without-parser', wrapped + ['check', '--locked', '--offline', '--manifest-path', str(ordinary)])
    execute('different-manifest-refused', [sys.executable, '-B', str(runner), '--cargo', str(args.cargo),
            '--manifest-path', str(args.manifest_path), '--build-root', str(args.output / 'wrong'), '--',
            'check', '--locked', '--offline', '--manifest-path', str(ordinary)], False,
            'source owner and Cargo command select different manifests')
    (args.output / 'receipt.json').write_text(json.dumps({'status': 'PASS', 'controls': records,
                                                       'supplier_receipt_sha256': before}, indent=2) + '\n')
    print('REQUEST-JSON-NATIVE-SOURCE PASS controls=' + str(len(records)))


if __name__ == '__main__':
    main()
