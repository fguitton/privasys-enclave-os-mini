#!/usr/bin/env python3
"""Exercise actual liballoc node reservation and original-pool backing on native std."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    'tests::ordered_all_split_levels_and_each_reservation_failure',
    'tests::reverse_all_split_levels_and_each_reservation_failure',
    'tests::shuffled_all_split_levels_and_each_reservation_failure',
    'tests::first_leaf_refusal_retains_owned_pair_and_zero_backing',
    'paid_owner_tests::exact_alignment_original_pool_and_final_alias_refund',
    'paid_owner_tests::admission_and_actual_backend_refusal_refund_before_publication',
    'paid_owner_tests::shared_clone_refusal_keeps_original_then_fallible_copy_uses_same_pool',
    'paid_owner_tests::partial_physical_node_reservations_refund_without_mutation',
}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def events(path):
    result = []
    for line in path.read_text().splitlines():
        try:
            result.append(json.loads(line))
        except ValueError:
            pass
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cargo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.cargo.is_absolute() or not args.output.is_absolute():
        parser.error('Cargo and new retained output directory must be absolute')
    args.output.mkdir()
    manifest = ROOT / 'Cargo.toml'
    functions = runpy.run_path(str(ROOT / 'scripts/run-fallible-btree-cargo.py'))
    common = ['test', '--locked', '--offline', '--manifest-path', str(manifest),
              '-p', 'enclave-os-common', '--features', 'enclave-os-common/fallible-allocation-v1',
              '--test', 'btree_node_allocation']
    record = {'scope': 'native liballoc physical node reservation; no trusted target claim',
              'status': 'FAIL', 'rows': [], 'tests': sorted(EXPECTED)}
    target = os.environ.get('CARGO_TARGET_DIR')
    if target is None:
        metadata = subprocess.check_output([str(args.cargo), 'metadata', '--locked', '--offline',
                                           '--no-deps', '--format-version', '1',
                                           '--manifest-path', str(manifest)], text=True)
        target = json.loads(metadata)['target_directory']
    # Reuse the existing target-owned compiler source across focused runs.
    # Each output still retains the exact source/producer receipts and logs.
    source_root = Path(target).absolute() / 'fallible-btree-source'
    try:
        with functions['source_context'](manifest, source_root, common) as admitted:
            for name, suffix in [('discovery', ['--', '--list', '--format=json', '-Z', 'unstable-options']),
                                 ('body', ['--', '--format=json', '-Z', 'unstable-options', '--nocapture', '--test-threads=1'])]:
                command = [str(args.cargo), *admitted, *suffix]
                log = args.output / (name + '.log')
                start = time.monotonic()
                with log.open('xb') as output:
                    result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=1800)
                record['rows'].append({'name': name, 'command': command, 'exit_code': result.returncode,
                                       'seconds': time.monotonic() - start, 'log_sha256': digest(log)})
                if result.returncode:
                    raise RuntimeError(name + ' failed; retained log: ' + str(log))
                selected = [item for item in events(log) if item.get('type') == 'test'
                            and item.get('event') == ('discovered' if name == 'discovery' else 'ok')]
                names = [item['name'] for item in selected]
                if len(names) != len(EXPECTED) or set(names) != EXPECTED or any(item.get('ignore') for item in selected):
                    raise RuntimeError('node owner discovery/execution differs; retained log: ' + str(log))
            record['source_receipt'] = os.environ['HONEST_BTREE_SOURCE_RECEIPT']
            record['source_receipt_sha256'] = digest(Path(record['source_receipt']))
        source_receipt = Path(record['source_receipt'])
        shutil.copy2(source_receipt, args.output / 'source-receipt.json')
        shutil.copy2(source_receipt.parent / 'producer.json', args.output / 'producer.json')
        record['status'] = 'PASS'
    finally:
        (args.output / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')
        print('BTREE-NODE-ALLOCATION', record['status'], args.output, flush=True)


if __name__ == '__main__':
    main()
