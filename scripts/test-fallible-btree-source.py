#!/usr/bin/env python3
"""Exercise guarded acquisition and runner refusal; these controls do not qualify a compiler."""
import argparse
import json
from pathlib import Path
import runpy
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Controls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='btree-source-control-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'supplier'
        self.source.mkdir()
        self.profile = self.root / 'profile'
        shutil.copytree(ROOT / 'patches/rust/fallible-btree-insertion', self.profile)
        self.manifest = json.loads((self.profile / 'manifest.json').read_text())
        for row in self.manifest['files']:
            target = self.source / row['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ARGS.source / row['path'], target)
        functions = runpy.run_path(str(ROOT / 'scripts/prepare-fallible-btree-source.py'))
        self.prepare = functions['prepare']
        self.prepare.__globals__['PROFILE'] = self.profile
        self.destination = self.root / 'generated'

    def save(self):
        (self.profile / 'manifest.json').write_text(json.dumps(self.manifest))

    def test_current_source_exact_afterimages_and_modes(self):
        receipt = self.prepare(self.source, self.destination)
        self.assertEqual(len(receipt['generated_inputs']), len(self.manifest['files']))
        self.assertNotEqual(receipt['original_inputs'], receipt['generated_inputs'])
        for before, after in zip(receipt['original_inputs'], receipt['generated_inputs']):
            self.assertEqual(before['path'], after['path'])
            self.assertEqual(before['mode'], after['mode'])

    def test_unknown_profile_refuses(self):
        self.manifest['schema'] += 1
        self.save()
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            self.prepare(self.source, self.destination)

    def test_substituted_patch_refuses(self):
        with (self.profile / 'profile.patch').open('a') as stream:
            stream.write('substituted')
        with self.assertRaisesRegex(ValueError, 'patch differs'):
            self.prepare(self.source, self.destination)

    def test_substituted_supplier_refuses(self):
        path = self.source / self.manifest['files'][0]['path']
        with path.open('ab') as stream:
            stream.write(b'substituted')
        with self.assertRaisesRegex(ValueError, 'input differs'):
            self.prepare(self.source, self.destination)

    def test_unsafe_owner_path_refuses(self):
        self.manifest['files'][0]['path'] = '../outside'
        self.save()
        with self.assertRaisesRegex(ValueError, 'invalid'):
            self.prepare(self.source, self.destination)

    def test_duplicate_owner_refuses(self):
        self.manifest['files'][1] = self.manifest['files'][0]
        self.save()
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            self.prepare(self.source, self.destination)

    def test_in_place_destination_refuses(self):
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.prepare(self.source, self.source / 'generated')

    def test_runner_final_audit_cannot_record_pass(self):
        # Exercise the real runner after successful discovery/execution: its
        # source-context exit must still be allowed to reject the result.
        from contextlib import contextmanager
        from unittest.mock import patch
        import os
        import sys
        functions = runpy.run_path(str(ROOT / 'scripts/test-btree-node-allocation.py'))
        runner = functions['main']
        names = sorted(functions['EXPECTED'])
        cargo = self.root / 'cargo'
        cargo.write_text('#!' + sys.executable + '\nimport sys,json\n'
                         + 'names=' + repr(names) + '\n'
                         + 'for name in names:print(json.dumps(dict(type="test",event="discovered" if "--list" in sys.argv else "ok",name=name,ignore=False)))\n')
        cargo.chmod(0o755)
        receipt = self.root / 'source-receipt.json'
        receipt.write_text('{}')
        selected_roots = []
        @contextmanager
        def refused_audit(_manifest, source_root, _arguments):
            selected_roots.append(source_root)
            yield []
            raise ValueError('actual final source audit refused')
        output = self.root / 'runner-output'
        with patch.object(sys, 'argv', ['runner', '--cargo', str(cargo), '--output', str(output)]), \
             patch.dict(os.environ, HONEST_BTREE_SOURCE_RECEIPT=str(receipt),
                        CARGO_TARGET_DIR=str(self.root / 'target')), \
             patch.object(runpy, 'run_path', return_value={'source_context': refused_audit}):
            with self.assertRaisesRegex(ValueError, 'final source audit refused'):
                runner()
        self.assertEqual(json.loads((output / 'receipt.json').read_text())['status'], 'FAIL')
        self.assertEqual(selected_roots, [self.root / 'target/fallible-btree-source'])

    def test_existing_destination_refuses(self):
        self.destination.mkdir()
        with self.assertRaisesRegex(ValueError, 'must be new'):
            self.prepare(self.source, self.destination)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True,
                        help='original acquired Rust library source')
    ARGS = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Controls)
    names = [test.id() for test in suite]
    if not names:
        raise SystemExit('empty source controls')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun != len(names) or result.skipped:
        raise SystemExit(1)
    print(json.dumps({'status': 'PASS', 'scope': 'source controls only',
                      'collected': len(names), 'executed': result.testsRun,
                      'tests': names}))
