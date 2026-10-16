#!/usr/bin/env python3
"""Exercise current SDK ownership bodies with explicit native backend shims.

This is not SGX execution. The signed SIM registry owns genuine SDK execution;
this focused entry deterministically exercises queue/backend failure races.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

MINI = Path(__file__).resolve().parents[1]
HELPER = '''
#[cfg(test)]
pub fn native_adapter_unstarted(allocator: AllocationCapability) -> Thread {
    Thread {
        native: Arc::try_new_in(
            Native(SpinMutex::new(Inner {
                state: State::Preparing,
                creater: tcs::current().id(),
                joiner: None,
                retval: ptr::null_mut(),
            }), allocator.clone()), allocator,
        ).unwrap(),
    }
}
'''


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
        parser.error('--rustc must name an acquired absolute compiler')
    if not args.output.is_absolute() or args.output.exists() or args.output.is_symlink():
        parser.error('--output must be a new absolute task-owned directory')
    sdk = args.sdk_source.resolve(strict=True)
    profile = MINI / 'patches/teaclave/fallible-allocation-v1/manifest.json'
    manifest = json.loads(profile.read_text())
    required = {
        'sgx_types/src/memory.rs', 'sgx_alloc/src/fallible.rs',
        'sgx_trts/src/thread/native.rs', 'sgx_trts/src/thread/task.rs',
        'sgx_trts/src/thread/allocator.rs',
    }
    rows = {row['path']: row for row in manifest['files']}
    if manifest['profile'] != 'fallible-allocation-v1' or not required <= rows.keys():
        parser.error('current typed-thread source profile is required')
    args.output.mkdir(parents=True, mode=0o700)
    result = {
        'scope': 'Current SDK source-native failure/refcount regression; '
                 'no SGX, hardware, global allocator or authority qualification.',
        'profile_manifest_sha256': digest(profile),
        'runner_sha256': digest(Path(__file__)),
        'rustc': str(args.rustc), 'rustc_sha256': digest(args.rustc),
        'rustc_version': subprocess.check_output([str(args.rustc), '-vV'], text=True),
        'sdk_source': str(sdk), 'rows': [],
    }

    def audit(phase):
        for name, row in rows.items():
            path = sdk / name
            if path.is_symlink() or digest(path) != row['after_sha256']:
                raise ValueError('SDK source differs: ' + name)
        record = {'status': 'PASS', 'files': len(rows),
                  'profile_manifest_sha256': digest(profile)}
        (args.output / ('audit-' + phase + '.json')).write_text(
            json.dumps(record, indent=2) + '\n')

    env = os.environ.copy()
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER',
                'RUSTC_WORKSPACE_WRAPPER', 'LD_PRELOAD', 'LD_AUDIT'):
        env.pop(key, None)
    try:
        audit('before')
        for name, expected in [('native', 4), ('fallible', 2)]:
            work = args.output / name
            work.mkdir()
            (work / 'thread').mkdir()
            (work / 'sdk_alloc').mkdir()
            fixture = MINI / 'tests/typed-thread' / (name + '.rs')
            shutil.copy2(fixture, work / 'main.rs')
            for relative in sorted(required):
                destination = work / 'sdk' / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(sdk / relative, destination)
                assert digest(destination) == rows[relative]['after_sha256']
            if name == 'native':
                target = work / 'sdk/sgx_trts/src/thread/native.rs'
                prefix = target.read_bytes()
                target.write_bytes(prefix + HELPER.encode())
                (work / 'sdk-fixture-join.json').write_text(json.dumps({
                    'original_prefix_sha256': hashlib.sha256(prefix).hexdigest(),
                    'appended_inert_constructor_sha256': hashlib.sha256(HELPER.encode()).hexdigest(),
                    'scope': 'Only the test crate appends an inert queue fixture; '
                             'the prepared SDK is never modified.'}, indent=2) + '\n')
            planned = re.findall(r'#\[test\]\s*fn\s+(\w+)', fixture.read_text())
            assert len(planned) == len(set(planned)) == expected
            commands = [
                ('compile', [str(args.rustc), '--edition=2021', '--test',
                             str(work / 'main.rs'), '-o', str(work / 'tests')]),
                ('discovery', [str(work / 'tests'), '--list']),
                ('bodies', [str(work / 'tests'), '--test-threads=1']),
            ]
            for action, command in commands:
                started = time.monotonic()
                log = work / (action + '.log')
                with log.open('xb') as stream:
                    process = subprocess.run(command, cwd=work, env=env, stdout=stream,
                                             stderr=subprocess.STDOUT, timeout=60, check=False)
                row = {'owner': name, 'action': action, 'command': command,
                       'exit_code': process.returncode,
                       'seconds': time.monotonic() - started,
                       'log_sha256': digest(log), 'fixture_sha256': digest(fixture)}
                result['rows'].append(row)
                if process.returncode:
                    raise RuntimeError(name + '/' + action + ' failed')
                text = log.read_text(errors='replace')
                if action == 'discovery':
                    actual = re.findall(r'^(\S+): test$', text, re.MULTILINE)
                    if sorted(actual) != sorted(planned) or len(actual) != expected:
                        raise RuntimeError(name + ' independent discovery mismatch')
                    row['actual_names'] = actual
                if action == 'bodies':
                    actual = re.findall(r'^test (\S+) \.\.\. ok$', text, re.MULTILINE)
                    if sorted(actual) != sorted(planned) or len(actual) != expected:
                        raise RuntimeError(name + ' execution identity mismatch')
                    if f'test result: ok. {expected} passed; 0 failed; 0 ignored;' not in text:
                        raise RuntimeError(name + ' result mismatch')
                    row['executed'] = expected
        result['status'] = 'PASS'
    except Exception as error:
        result['status'] = 'FAIL'
        result['error'] = str(error)
        raise
    finally:
        try:
            audit('after')
        except Exception as error:
            result['status'] = 'FAIL'
            result['after_audit_error'] = str(error)
            raise
        finally:
            (args.output / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')
    print('SDK-TYPED-THREAD-NATIVE: 4 queue/native + 2 backend-cancel owners PASS')


if __name__ == '__main__':
    main()
