#!/usr/bin/env python3
"""Exercise actual Cargo argv-zero dispatch through a configured rustup shim."""
import argparse
import json
from pathlib import Path
import runpy
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cargo-shim', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.output.is_absolute() or not args.cargo_shim.is_absolute():
        parser.error('inputs and output must be absolute')
    args.output.mkdir(mode=0o700)
    functions = runpy.run_path(str(ROOT / 'scripts/run-request-json-cargo.py'))
    identity = functions['cargo_identity'](args.cargo_shim)
    if not identity['symlinks'] or Path(identity['resolved_path']).name != 'rustup':
        raise ValueError('control requires an actual rustup Cargo symlink')
    manifest = args.output / 'Cargo.toml'
    manifest.write_text('[workspace]\n[package]\nname = \"request-json-cargo-dispatch-control\"\n'
                        'version = \"0.0.0\"\nedition = \"2021\"\n[lib]\npath = \"lib.rs\"\n')
    (args.output / 'lib.rs').write_text('')
    subprocess.run([identity['invoked_path'], 'generate-lockfile', '--offline',
                    '--manifest-path', str(manifest)], check=True)
    # Use the exact invocation path selected by the producer, not its hash owner.
    result = subprocess.run([identity['invoked_path'], 'locate-project', '--workspace',
                             '--manifest-path', str(manifest), '--message-format', 'plain'],
                            text=True, capture_output=True)
    if result.returncode or Path(result.stdout.strip()) != manifest:
        raise ValueError('configured Cargo shim did not locate its workspace')
    metadata = functions['metadata'](Path(identity['invoked_path']), manifest, [])
    if Path(metadata['workspace_root']) != args.output:
        raise ValueError('Cargo shim metadata selected a different workspace')
    # The previously used resolved executable must fail this Cargo-only command.
    predecessor = subprocess.run([identity['resolved_path'], 'locate-project', '--workspace',
                                  '--manifest-path', str(manifest), '--message-format', 'plain'],
                                 text=True, capture_output=True)
    if predecessor.returncode == 0:
        raise ValueError('control did not distinguish rustup dispatch from Cargo')
    receipt = {'status': 'PASS', 'cargo': identity,
               'workspace_located': True, 'metadata_selected_workspace': True,
               'resolved_executable_refused_cargo_command': True,
               'resolved_exit_code': predecessor.returncode}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    (args.output / 'resolved-command.stderr').write_text(predecessor.stderr)
    print('REQUEST-JSON-CARGO-SHIM PASS actual-locate-project actual-metadata resolved-dispatch-refused')


if __name__ == '__main__':
    main()
