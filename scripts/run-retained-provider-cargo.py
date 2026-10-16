#!/usr/bin/env python3
"""Compose the retained-provider and admitted-JSON build-owned source routes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

GENERATOR = Path(__file__).with_name('prepare-retained-provider.py')
JSON_RUNNER = Path(__file__).with_name('run-request-json-cargo.py')
SDK_RUNNER = Path(__file__).with_name('fallible-sdk-app-source.py')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def metadata(cargo, manifest, selectors, target=None):
    return json.loads(subprocess.check_output(
        [str(cargo), 'metadata', '--offline', '--locked', '--format-version', '1',
         '--manifest-path', str(manifest), *selectors,
         *(['-Zjson-target-spec', '--filter-platform', str(target)] if target else [])],
        text=True))


def graph(value):
    supplier_ids = {row['id'] for row in value['packages'] if row['name'] == 'rustls'}

    def identity(item):
        if isinstance(item, str):
            return 'retained-provider' if item in supplier_ids else item
        if isinstance(item, list):
            return sorted((identity(child) for child in item),
                          key=lambda child: json.dumps(child, sort_keys=True))
        if isinstance(item, dict):
            return {key: identity(child) for key, child in item.items()}
        return item

    return sorted(identity(value['resolve']['nodes']), key=lambda node: node['id'])


def verify(source, destination, functions):
    profile = functions['PROFILE']
    manifest = json.loads((profile / 'manifest.json').read_text())
    checksum = source / '.cargo-checksum.json'
    matches = [row for row in manifest['suppliers']
               if row['base_checksum_manifest_sha256'] == digest(checksum)]
    if len(matches) != 1:
        raise ValueError('acquired rustls identity differs')
    supplier = matches[0]
    functions['verified'](profile / 'profile.patch', manifest['patch_sha256'])
    checks = json.loads(checksum.read_text())
    expected = dict(checks['files'])
    expected.update({row['path']: row['after_sha256'] for row in supplier['files']})
    actual = set()
    for path in destination.rglob('*'):
        if path.is_symlink():
            raise ValueError('generated rustls symlink')
        if path.is_file():
            actual.add(str(path.relative_to(destination)))
    if actual != set(expected) | {'retained-provider-source-receipt.json'}:
        raise ValueError('generated rustls inventory differs')
    for name, before in checks['files'].items():
        relative = functions['relative'](name)
        functions['verified'](source / relative, before)
        functions['verified'](destination / relative, expected[name])
        if (source / relative).stat().st_mode & 0o777 != (destination / relative).stat().st_mode & 0o777:
            raise ValueError('generated rustls mode differs')
    for row in supplier['files']:
        if row['before_sha256'] is None:
            path = destination / functions['relative'](row['path'])
            functions['verified'](path, row['after_sha256'])
            if path.stat().st_mode & 0o777 != row['mode']:
                raise ValueError('new generated rustls mode differs')
    for name in ('Cargo.toml', 'Cargo.toml.orig'):
        if digest(source / name) != digest(destination / name):
            raise ValueError('rustls dependency declarations changed')
    receipt = json.loads((destination / 'retained-provider-source-receipt.json').read_text())
    if receipt['profile_manifest_sha256'] != digest(profile / 'manifest.json'):
        raise ValueError('generated rustls profile differs')
    return receipt


def run(cargo, manifest, build_root, arguments):
    if not cargo.is_absolute() or not manifest.is_absolute() or not build_root.is_absolute():
        raise ValueError('build inputs must be absolute')
    json_runner = runpy.run_path(str(JSON_RUNNER))
    cargo_input = json_runner['cargo_identity'](cargo)
    manifest = manifest.resolve(strict=True)
    selectors = json_runner['feature_selectors'](arguments)
    sdk_functions = runpy.run_path(str(SDK_RUNNER))
    target_path = sdk_functions['target'](arguments)
    original = metadata(cargo, manifest, selectors, target_path)
    sdk_route = (sdk_functions['verify'](original, os.environ.get(
        'HONEST_TEACLAVE_FALLIBLE_SOURCE'), target_path) if target_path else None)
    matches = [row for row in original['packages'] if row['name'] == 'rustls']
    if len(matches) != 1:
        raise ValueError('trusted build needs exactly one current rustls supplier')
    source = Path(matches[0]['manifest_path']).parent.resolve(strict=True)
    locate = subprocess.check_output([str(cargo), 'locate-project', '--workspace',
                                      '--manifest-path', str(manifest),
                                      '--message-format', 'plain'], text=True).strip()
    lock = Path(locate).with_name('Cargo.lock')
    lock_before = digest(lock)
    functions = runpy.run_path(str(GENERATOR))
    profile_hash = digest(functions['PROFILE'] / 'manifest.json')
    recipe_hash = hashlib.sha256((profile_hash + digest(GENERATOR)
                                 + digest(functions['PATCH'])).encode()).hexdigest()
    build_root.mkdir(parents=True, exist_ok=True)
    destination = build_root / ('rustls-' + matches[0]['version'] + '-' + recipe_hash)
    if not destination.exists():
        functions['prepare'](source, destination)
    receipt = verify(source, destination, functions)
    config = build_root / 'retained-provider-source.toml'
    config.write_text('paths = ' + json.dumps([str(destination)]) + '\n')
    # This private Cargo entry forwards the source selection after the subcommand
    # too, including external cargo-clippy. JSON's route remains independent.
    wrapper = build_root / 'cargo-retained-provider'
    wrapper_code = """#!{python}
import json,os,sys,tomllib
from pathlib import Path
arguments=sys.argv[1:]
paths={paths}
forward=[]
index=0
while index<len(arguments):
    value=arguments[index]
    if value=='--config' and index+1<len(arguments):
        candidate=Path(arguments[index+1])
        if candidate.is_file():
            data=tomllib.loads(candidate.read_text())
            if set(data)=={{'paths'}}:
                paths.extend(data['paths'])
                index+=2
                continue
    forward.append(value)
    index+=1
commands={{'metadata','locate-project','clippy','check','build','test'}}
command=next((i for i,x in enumerate(forward) if x in commands),None)
if command is None: raise SystemExit('unsupported trusted Cargo command')
config=Path({combined})
config.write_text('paths = '+json.dumps(list(dict.fromkeys(paths)))+'\\n')
forward[command+1:command+1]=['--config',str(config)]
os.environ['HONEST_RETAINED_PROVIDER_SOURCE_RECEIPT']={source_receipt}
os.execv({cargo},[{cargo},*forward])
""".format(python=sys.executable, paths=repr([str(destination),
              *(sdk_route['paths'] if sdk_route else [])]),
           combined=repr(str(build_root / 'combined-source.toml')), cargo=repr(str(cargo)),
           source_receipt=repr(str(destination / 'retained-provider-source-receipt.json')))
    wrapper.write_text(wrapper_code)
    wrapper.chmod(0o700)
    consumed = metadata(wrapper, manifest, selectors, target_path)
    if sdk_route:
        sdk_functions['adopted'](consumed, sdk_route)
        (build_root / 'sdk-app-graph-before.json').write_text(
            json.dumps(original, indent=2) + '\n')
        (build_root / 'sdk-app-graph-after.json').write_text(
            json.dumps(consumed, indent=2) + '\n')
    original_graph = (sdk_functions['graph'](original, sdk_route['names'])
                      if sdk_route else graph(original))
    consumed_graph = (sdk_functions['graph'](consumed, sdk_route['names'])
                      if sdk_route else graph(consumed))
    adopted = [row for row in consumed['packages'] if row['name'] == 'rustls']
    if (len(adopted) != 1 or Path(adopted[0]['manifest_path']).resolve() != destination / 'Cargo.toml'
            or adopted[0]['version'] != matches[0]['version'] or original_graph != consumed_graph):
        raise ValueError('trusted rustls source/dependency graph adoption failed')
    if digest(lock) != lock_before:
        raise ValueError('rustls preparation changed the locked workspace')
    provenance = {'schema': 1, 'profile': 'retained-provider', 'status': 'RUNNING',
                  'supplier_version': receipt['version'], 'cargo': cargo_input,
                  'cargo_entry_sha256': digest(wrapper),
                  'profile_manifest_sha256': profile_hash,
                  'generated_receipt_sha256': digest(destination / 'retained-provider-source-receipt.json'),
                  'generator_sha256': digest(GENERATOR), 'runner_sha256': digest(Path(__file__)),
                  'workspace_lock_sha256': lock_before, 'resolved_graph_unchanged': True,
                  'rustup_toolchain': os.environ.get('RUSTUP_TOOLCHAIN'),
                  'sdk_application_route': sdk_route,
                  'sdk_runner_sha256': digest(SDK_RUNNER),
                  'sdk_graph_before_sha256': (digest(build_root / 'sdk-app-graph-before.json')
                                               if sdk_route else None),
                  'sdk_graph_after_sha256': (digest(build_root / 'sdk-app-graph-after.json')
                                              if sdk_route else None)}
    record = build_root / 'retained-provider-build.json'
    record.write_text(json.dumps(provenance, indent=2) + '\n')
    print('RETAINED-PROVIDER-BUILD', receipt['version'], profile_hash, flush=True)
    result = json_runner['run'](wrapper, manifest, build_root / 'request-json', arguments)
    verify(source, destination, functions)
    if sdk_route:
        if sdk_functions['verify'](original, sdk_route['mirror'], target_path) != sdk_route:
            raise ValueError('SDK application source changed during compilation')
    if digest(lock) != lock_before:
        raise ValueError('trusted build changed the locked workspace')
    provenance.update(exit_code=result, status='PASS' if result == 0 else 'FAIL')
    record.write_text(json.dumps(provenance, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cargo', type=Path, required=True)
    parser.add_argument('--manifest-path', type=Path, required=True)
    parser.add_argument('--build-root', type=Path, required=True)
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = args.arguments
    if arguments[:1] == ['--']:
        arguments = arguments[1:]
    if not arguments:
        parser.error('Cargo command is required')
    return run(args.cargo, args.manifest_path, args.build_root, arguments)


if __name__ == '__main__':
    sys.exit(main())
