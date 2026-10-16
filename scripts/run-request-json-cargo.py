#!/usr/bin/env python3
"""Build trusted code with the verified, graph-preserving JSON source override."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

GENERATOR = Path(__file__).with_name('prepare-request-json.py')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def cargo_identity(cargo):
    """Retain argv[0] dispatch while recording the executable behind the shim."""
    if not cargo.is_absolute():
        raise ValueError('Cargo invocation must be absolute')
    resolved = cargo.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError('Cargo executable is not a regular file')
    links = []
    current = cargo
    while current.is_symlink():
        target = os.readlink(current)
        links.append({'path': str(current), 'target': target,
                      'mode': current.lstat().st_mode & 0o777})
        current = Path(os.path.abspath(current.parent / target))
    return {'invoked_path': str(cargo), 'resolved_path': str(resolved),
            'resolved_sha256': digest(resolved), 'symlinks': links}


def metadata(cargo, manifest, selectors, config=None):
    command = [str(cargo)]
    if config is not None:
        command += ['--config', str(config)]
    command += ['metadata', '--locked', '--offline', '--format-version', '1',
                '--manifest-path', str(manifest), *selectors]
    return json.loads(subprocess.check_output(command, text=True))


def feature_selectors(arguments):
    selectors = []
    iterator = iter(arguments)
    for value in iterator:
        if value in ('--features', '-F'):
            selectors += [value, next(iterator)]
        elif value in ('--all-features', '--no-default-features') or value.startswith('--features='):
            selectors.append(value)
    return selectors


def graph(value):
    json_ids = {row['id'] for row in value['packages'] if row['name'] == 'serde_json'}

    def identity(item):
        if isinstance(item, str):
            return 'request-json' if item in json_ids else item
        if isinstance(item, list):
            return sorted((identity(child) for child in item), key=lambda child: json.dumps(child, sort_keys=True))
        if isinstance(item, dict):
            return {key: identity(child) for key, child in item.items()}
        return item

    nodes = identity(value['resolve']['nodes'])
    nodes.sort(key=lambda node: node['id'])
    return nodes


def verify_profile(source, destination, functions):
    manifest = json.loads((functions['PROFILE'] / 'manifest.json').read_text())
    checksum = source / '.cargo-checksum.json'
    suppliers = [row for row in manifest['suppliers']
                 if row['base_checksum_manifest_sha256'] == digest(checksum)]
    if len(suppliers) != 1:
        raise ValueError('acquired JSON identity differs')
    supplier = suppliers[0]
    functions['verified'](checksum, supplier['base_checksum_manifest_sha256'])
    functions['verified'](functions['PROFILE'] / 'profile.patch', manifest['patch_sha256'])
    checks = json.loads(checksum.read_text())
    expected = dict(checks['files'])
    expected.update({row['path']: row['after_sha256'] for row in supplier['files']})
    actual = set()
    for path in destination.rglob('*'):
        if path.is_symlink():
            raise ValueError('generated JSON symlink')
        if path.is_file():
            actual.add(str(path.relative_to(destination)))
    if actual != set(expected) | {'request-json-source-receipt.json'}:
        raise ValueError('generated JSON file inventory differs')
    for name, before in checks['files'].items():
        relative = functions['relative'](name)
        functions['verified'](source / relative, before)
        functions['verified'](destination / relative, expected[name])
        if (source / relative).stat().st_mode & 0o777 != (destination / relative).stat().st_mode & 0o777:
            raise ValueError('generated JSON source mode differs')
    receipt = json.loads((destination / 'request-json-source-receipt.json').read_text())
    if receipt['profile_manifest_sha256'] != digest(functions['PROFILE'] / 'manifest.json'):
        raise ValueError('generated JSON profile differs')
    # Dependency and feature declarations are intentionally the acquired bytes.
    for name in ('Cargo.toml', 'Cargo.toml.orig'):
        if digest(source / name) != digest(destination / name):
            raise ValueError('JSON source override changes dependency declarations')
    return receipt


def run(cargo, manifest, build_root, arguments):
    if not cargo.is_absolute() or not manifest.is_absolute() or not build_root.is_absolute():
        raise ValueError('build inputs must be absolute')
    cargo_input = cargo_identity(cargo)
    manifest = manifest.resolve(strict=True)
    locate = subprocess.check_output([str(cargo), 'locate-project', '--workspace',
                                      '--manifest-path', str(manifest),
                                      '--message-format', 'plain'], text=True).strip()
    lock = Path(locate).with_name('Cargo.lock')
    lock_before = digest(lock)
    selectors = feature_selectors(arguments)
    original = metadata(cargo, manifest, selectors)
    packages = [row for row in original['packages'] if row['name'] == 'serde_json']
    if len(packages) != 1:
        raise ValueError('trusted build needs exactly one current JSON supplier')
    source = Path(packages[0]['manifest_path']).parent.resolve(strict=True)
    functions = runpy.run_path(str(GENERATOR))
    profile_hash = digest(functions['PROFILE'] / 'manifest.json')
    build_root.mkdir(parents=True, exist_ok=True)
    recipe_hash = hashlib.sha256((profile_hash + digest(GENERATOR) + digest(functions['PATCH'])).encode()).hexdigest()
    destination = build_root / ('serde_json-' + packages[0]['version'] + '-' + recipe_hash)
    if not destination.exists():
        functions['prepare'](source, destination)
    receipt = verify_profile(source, destination, functions)
    config = build_root / 'cargo-source.toml'
    config.write_text('paths = ' + json.dumps([str(destination)]) + '\n')
    consumed = metadata(cargo, manifest, selectors, config)
    adopted = [row for row in consumed['packages'] if row['name'] == 'serde_json']
    if (len(adopted) != 1 or Path(adopted[0]['manifest_path']).resolve() != destination / 'Cargo.toml'
            or adopted[0]['version'] != packages[0]['version'] or graph(original) != graph(consumed)):
        raise ValueError('trusted JSON source/dependency graph adoption failed')
    if digest(lock) != lock_before:
        raise ValueError('JSON preparation changed the locked workspace')
    # External subcommands such as cargo-clippy must receive this option too.
    # A global Cargo option before the subcommand is not forwarded to its child.
    command = [str(cargo), arguments[0], '--config', str(config), *arguments[1:]]
    provenance = {'schema': 1, 'profile': 'request-json', 'supplier_version': receipt['version'],
                  'profile_manifest_sha256': profile_hash,
                  'generated_receipt_sha256': digest(destination / 'request-json-source-receipt.json'),
                  'workspace_lock_sha256': lock_before, 'command': command,
                  'cargo': cargo_input, 'cargo_sha256': cargo_input['resolved_sha256'],
                  'rustup_toolchain': os.environ.get('RUSTUP_TOOLCHAIN'),
                  'generator_sha256': digest(GENERATOR),
                  'runner_sha256': digest(Path(__file__)),
                  'python': str(Path(sys.executable).resolve()),
                  'python_sha256': digest(Path(sys.executable).resolve()),
                  'resolved_graph_unchanged': True, 'status': 'RUNNING'}
    record = build_root / 'request-json-build.json'
    record.write_text(json.dumps(provenance, indent=2) + '\n')
    print('REQUEST-JSON-BUILD', receipt['version'], profile_hash, file=sys.stderr, flush=True)
    environment = os.environ.copy()
    environment['HONEST_REQUEST_JSON_SOURCE_RECEIPT'] = str(destination / 'request-json-source-receipt.json')
    result = subprocess.run(command, env=environment)
    verify_profile(source, destination, functions)
    if digest(lock) != lock_before:
        raise ValueError('trusted build changed the locked workspace')
    provenance.update(exit_code=result.returncode, status='PASS' if result.returncode == 0 else 'FAIL')
    record.write_text(json.dumps(provenance, indent=2) + '\n')
    return result.returncode


def command_manifest(arguments):
    manifests = []
    iterator = iter(arguments)
    for argument in iterator:
        if argument == '--':
            break
        if argument == '--manifest-path':
            manifests.append(Path(next(iterator)))
        elif argument.startswith('--manifest-path='):
            manifests.append(Path(argument.partition('=')[2]))
    if len(manifests) > 1:
        raise ValueError('multiple Cargo manifests are unsupported')
    return (manifests[0] if manifests else Path.cwd() / 'Cargo.toml').resolve(strict=True)


def native_run(cargo, build_root, arguments):
    """Route actual parser consumers through the existing verified source owner."""
    if not arguments or arguments[0] not in ('check', 'clippy', 'build', 'test'):
        return subprocess.run([str(cargo), *arguments]).returncode
    manifest = command_manifest(arguments)
    resolved = metadata(cargo, manifest, feature_selectors(arguments))
    packages = {row['id']: row for row in resolved['packages']}
    required = any(packages[node['id']]['name'] == 'enclave-os-common'
                   and 'request-json-parser' in node['features']
                   for node in resolved['resolve']['nodes'])
    if not required:
        # No admitted parser is compiled; no supplier qualification is claimed.
        return subprocess.run([str(cargo), *arguments]).returncode
    if build_root is None:
        build_root = Path(resolved['target_directory']) / 'request-json-source'
    build_root = build_root.absolute()
    retained = any(packages[node['id']]['name'] in ('enclave-os-egress', 'enclave-os-enclave')
                   and 'fallible-allocation-v1' in node['features']
                   for node in resolved['resolve']['nodes'])
    if retained:
        # Reuse the current outer composition: rustls first, then this JSON owner.
        provider = runpy.run_path(str(Path(__file__).with_name('run-retained-provider-cargo.py')))
        return provider['run'](cargo, manifest, build_root / 'retained-provider', arguments)
    return run(cargo, manifest, build_root, arguments)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cargo', type=Path, required=True)
    parser.add_argument('--manifest-path', type=Path,
                        help='explicit trusted source owner; native calls infer Cargo manifest')
    parser.add_argument('--build-root', type=Path)
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = args.arguments
    if arguments[:1] == ['--']:
        arguments = arguments[1:]
    if not arguments:
        parser.error('Cargo command is required')
    cargo_identity(args.cargo)
    if args.manifest_path is None:
        return native_run(args.cargo, args.build_root, arguments)
    if args.build_root is None:
        parser.error('explicit trusted manifest requires --build-root')
    if command_manifest(arguments) != args.manifest_path.resolve(strict=True):
        parser.error('source owner and Cargo command select different manifests')
    return run(args.cargo, args.manifest_path, args.build_root, arguments)


if __name__ == '__main__':
    sys.exit(main())
