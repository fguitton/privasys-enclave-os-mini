#!/usr/bin/env python3
"""Real source-generation acceptance and refusal controls for request JSON."""
import argparse
import json
from pathlib import Path
import runpy
import shutil

ROOT = Path(__file__).resolve().parents[2]


def controls(vendor, output):
    output.mkdir(mode=0o700)
    functions = runpy.run_path(str(ROOT / 'scripts/prepare-request-json.py'))
    prepare = functions['prepare']
    profile = json.loads((functions['PROFILE'] / 'manifest.json').read_text())
    positives = []
    for supplier in profile['suppliers']:
        source = vendor / ('serde_json-' + supplier['version'])
        receipt = prepare(source, output / ('generated-' + supplier['version']))
        positives.append(receipt['version'])
    source = vendor / ('serde_json-' + profile['suppliers'][0]['version'])
    rows = []

    def refuse(name, acquired, destination):
        try:
            prepare(acquired, destination)
        except ValueError as error:
            rows.append({'name': name, 'status': 'PASS', 'reason': str(error)})
            return
        raise AssertionError(name + ' was accepted')

    existing = output / 'existing'
    existing.mkdir()
    (existing / 'sentinel').write_text('preserve')
    refuse('existing-destination', source, existing)
    assert (existing / 'sentinel').read_text() == 'preserve'
    # Exercise containment on an exact private copy so even a regressed guard
    # cannot write into the shared acquired supplier.
    contained_source = output / 'contained-source'
    shutil.copytree(source, contained_source)
    refused_child = contained_source / 'request-json-control-refused-child'
    assert not refused_child.exists()
    refuse('source-contained-destination', contained_source, refused_child)
    assert not refused_child.exists()
    mutations = [
        ('changed-checksum-manifest', lambda root: (root / '.cargo-checksum.json').write_text('{}')),
        ('changed-compiler-source', lambda root: (root / 'src/de.rs').write_text('changed')),
        ('missing-compiler-source', lambda root: (root / 'src/de.rs').unlink()),
        ('symlink-compiler-source', lambda root: ((root / 'src/de.rs').unlink(),
                                                 (root / 'src/de.rs').symlink_to(source / 'src/de.rs'))),
    ]
    for name, mutate in mutations:
        acquired = output / name
        shutil.copytree(source, acquired)
        mutate(acquired)
        destination = output / (name + '-result')
        refuse(name, acquired, destination)
        assert not destination.exists()
    altered = output / 'altered-profile'
    shutil.copytree(functions['PROFILE'], altered)
    # Only the isolated function's globals change; canonical profile is untouched.
    prepare.__globals__['PROFILE'] = altered
    (altered / 'profile.patch').write_text('changed')
    destination = output / 'changed-profile-result'
    refuse('changed-profile-patch', source, destination)
    assert not destination.exists()
    assert [row['name'] for row in rows] == [
        'existing-destination', 'source-contained-destination', 'changed-checksum-manifest',
        'changed-compiler-source', 'missing-compiler-source', 'symlink-compiler-source', 'changed-profile-patch']
    (output / 'receipt.json').write_text(json.dumps({'status': 'PASS', 'current_suppliers': positives,
                                                   'refusals': rows}, indent=2) + '\n')
    print('REQUEST-JSON-SOURCE-CONTROLS PASS current-suppliers=' + str(len(positives)) + ' refusals=' + str(len(rows)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    controls(args.vendor, args.output)


if __name__ == '__main__':
    main()
