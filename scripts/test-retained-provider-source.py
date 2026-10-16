#!/usr/bin/env python3
"""Finite source/profile/cache refusal tests; no compiler or TLS authority claim."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import shutil
import sys


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(source, output):
    if not source.is_absolute() or not output.is_absolute() or output.exists():
        raise ValueError('absolute acquired source and new output directory required')
    output.mkdir(parents=True)
    scripts = Path(__file__).resolve().parent
    functions = runpy.run_path(str(scripts / 'prepare-retained-provider.py'))
    runner = runpy.run_path(str(scripts / 'run-retained-provider-cargo.py'))
    before = json.loads((source / '.cargo-checksum.json').read_text())
    for name, expected in before['files'].items():
        functions['verified'](source / functions['relative'](name), expected)
    rows = []

    def refused(name, action):
        try:
            action()
        except ValueError as error:
            rows.append({'name': name, 'status': 'PASS', 'refusal': str(error)})
        else:
            raise AssertionError('missing source refusal: ' + name)

    destination = output / 'valid'
    functions['prepare'](source, destination)
    runner['verify'](source, destination, functions)
    rows.append({'name': 'verified-acquisition', 'status': 'PASS'})
    refused('destination-exists', lambda: functions['prepare'](source, destination))
    refused('destination-inside-source',
            lambda: functions['prepare'](source, source / 'must-not-create-provider'))
    wrong_source = output / 'wrong-source'
    shutil.copytree(source, wrong_source, symlinks=True)
    target = Path('src/crypto/ring/mod.rs')
    (wrong_source / target).write_bytes((wrong_source / target).read_bytes() + b'\n')
    refused('acquired-source-mutation',
            lambda: functions['prepare'](wrong_source, output / 'must-not-publish-mutation'))
    wrong_identity = output / 'wrong-identity'
    wrong_identity.mkdir()
    (wrong_identity / '.cargo-checksum.json').write_text('{}\n')
    refused('acquired-identity',
            lambda: functions['prepare'](wrong_identity, output / 'must-not-publish-identity'))
    wrong_profile = output / 'wrong-profile'
    shutil.copytree(functions['PROFILE'], wrong_profile)
    patch = wrong_profile / 'profile.patch'
    patch.write_bytes(patch.read_bytes() + b'\n')
    globals_ = functions['prepare'].__globals__
    original_profile = globals_['PROFILE']
    try:
        globals_['PROFILE'] = wrong_profile
        refused('profile-patch-mutation',
                lambda: functions['prepare'](source, output / 'must-not-publish-profile'))
    finally:
        globals_['PROFILE'] = original_profile
    valid = (destination / target).read_bytes()
    (destination / target).write_bytes(valid + b'\n')
    refused('generated-cache-mutation', lambda: runner['verify'](source, destination, functions))
    (destination / target).write_bytes(valid)
    mode = (destination / target).stat().st_mode & 0o777
    (destination / target).chmod(mode ^ 0o100)
    refused('generated-cache-mode', lambda: runner['verify'](source, destination, functions))
    (destination / target).chmod(mode)
    runner['verify'](source, destination, functions)
    for name, expected in before['files'].items():
        functions['verified'](source / functions['relative'](name), expected)
    result = {'status': 'PASS', 'scope': __doc__, 'rows': rows,
              'script_sha256': digest(Path(__file__).resolve()),
              'generator_sha256': digest(scripts / 'prepare-retained-provider.py'),
              'runner_sha256': digest(scripts / 'run-retained-provider-cargo.py'),
              'profile_manifest_sha256': digest(functions['PROFILE'] / 'manifest.json'),
              'python': str(Path(sys.executable).resolve()),
              'python_sha256': digest(Path(sys.executable).resolve())}
    (output / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.source, args.output)
    print('RETAINED-PROVIDER-SOURCE-TESTS', len(result['rows']), 'PASS')


if __name__ == '__main__':
    main()
