"""Verify the selected application's one build-owned SDK family before Cargo."""
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / 'patches/teaclave/fallible-allocation-v1'
SDK_URL = 'https://github.com/Privasys/teaclave-sgx-sdk'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative(value):
    path = Path(value)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('invalid SDK source path')
    return path


def target(arguments):
    front = arguments[:arguments.index('--')] if '--' in arguments else arguments
    values = []
    for index, argument in enumerate(front):
        if argument == '--target':
            values.append(front[index + 1])
        elif argument.startswith('--target='):
            values.append(argument.partition('=')[2])
    if len(values) > 1:
        raise ValueError('multiple SDK application targets')
    if not values or not values[0].endswith('.json'):
        return None
    path = Path(values[0]).resolve(strict=True)
    return path if json.loads(path.read_text()).get('vendor') == 'teaclave' else None


def graph(value, names):
    ids = {row['id']: 'sdk:' + row['name'] + '@' + row['version']
           for row in value['packages'] if row['name'] in names}
    ids.update({row['id']: 'retained-provider'
                for row in value['packages'] if row['name'] == 'rustls'})

    def normalized(item):
        if isinstance(item, str):
            return ids.get(item, item)
        if isinstance(item, list):
            return sorted((normalized(child) for child in item),
                          key=lambda child: json.dumps(child, sort_keys=True))
        if isinstance(item, dict):
            return {key: normalized(child) for key, child in item.items()}
        return item

    return sorted(normalized(value['resolve']['nodes']), key=lambda node: node['id'])


def verify(original, mirror, target_path):
    if not mirror or not Path(mirror).is_absolute():
        raise ValueError('selected Teaclave application needs its verified SDK mirror')
    mirror = Path(mirror).resolve(strict=True)
    if target_path != mirror / 'rustlib/x86_64-unknown-linux-sgx.json':
        raise ValueError('application target is not the selected SDK target')
    profile = json.loads((PROFILE / 'manifest.json').read_text())
    receipt_path = mirror / 'fallible-allocation-source-receipt-v1.json'
    receipt = json.loads(receipt_path.read_text())
    if (receipt['profile'] != 'fallible-allocation-v1'
            or receipt['base_sdk_commit'] != profile['base_sdk_commit']
            or receipt['manifest_sha256'] != digest(PROFILE / 'manifest.json')):
        raise ValueError('SDK application source profile differs')
    for row in profile['patches']:
        path = PROFILE / relative(row['path'])
        if path.is_symlink() or digest(path) != row['sha256']:
            raise ValueError('SDK application source patch differs')
    expected = {row['path']: row['sha256'] for row in receipt['copied_inputs']}
    after = {row['path']: row['after_sha256'] for row in profile['files']}
    if receipt['afterimages'] != [dict(path=row['path'], sha256=row['after_sha256'])
                                 for row in profile['files']]:
        raise ValueError('SDK application afterimage receipt differs')
    expected.update(after)
    family = [row for row in original['packages']
              if row.get('source') and SDK_URL in row['source']]
    if not family or len({row['name'] for row in family}) != len(family):
        raise ValueError('SDK application family is absent or duplicated')
    roots = set()
    source_root = Path(family[0]['manifest_path']).resolve(strict=True).parent.parent
    tree = subprocess.check_output(['git', '-C', str(source_root), 'ls-tree', '-rz',
                                    profile['base_sdk_commit']])
    modes = {entry.split(b'\t', 1)[1].decode(): int(entry.split(b' ', 1)[0], 8) & 0o777
             for entry in tree.split(b'\0') if entry}
    paths = []
    files = []
    for package in family:
        source_id = 'git+' + SDK_URL + '?rev=' + profile['base_sdk_commit'] + '#'
        if not package['source'].startswith(source_id):
            raise ValueError('SDK application uses another SDK revision')
        source = Path(package['manifest_path']).resolve(strict=True).parent
        crate = relative(source.name)
        roots.add(source.parent)
        destination = mirror / crate
        if source.is_symlink() or destination.is_symlink():
            raise ValueError('SDK application crate symlink')
        if digest(source / 'Cargo.toml') != digest(destination / 'Cargo.toml'):
            raise ValueError('SDK application changes dependency declarations')
        declaration = tomllib.loads((destination / 'Cargo.toml').read_text())['package']
        if (declaration['name'] != package['name']
                or declaration['version'] != package['version']):
            raise ValueError('SDK application package identity differs')
        prefix = str(crate) + '/'
        selected = {name: value for name, value in expected.items()
                    if name.startswith(prefix)}
        actual = set()
        for path in destination.rglob('*'):
            if path.is_symlink():
                raise ValueError('SDK application source symlink')
            if path.is_file():
                actual.add(str(path.relative_to(mirror)))
        if actual != set(selected):
            raise ValueError('SDK application source inventory differs')
        for name, value in selected.items():
            path = mirror / relative(name)
            original_path = source.parent / relative(name)
            if digest(path) != value:
                raise ValueError('SDK application source bytes differ: ' + name)
            if original_path.is_file():
                mode = modes[name] if name in after else original_path.stat().st_mode & 0o777
                if path.stat().st_mode & 0o777 != mode:
                    raise ValueError('SDK application source mode differs: ' + name)
                before = next((row['before_sha256'] for row in profile['files']
                               if row['path'] == name), value)
                if before is None or digest(original_path) != before:
                    raise ValueError('SDK application acquired source differs: ' + name)
            files.append(dict(path=name, sha256=value, mode=path.stat().st_mode & 0o777))
        paths.append(str(destination))
    if len(roots) != 1:
        raise ValueError('SDK application mixes acquired SDK roots')
    revision = subprocess.check_output(
        ['git', '-C', str(next(iter(roots))), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != profile['base_sdk_commit']:
        raise ValueError('SDK application acquired identity differs')
    target_name = str(target_path.relative_to(mirror))
    if digest(target_path) != expected[target_name]:
        raise ValueError('SDK application target source differs')
    return dict(paths=paths, names=sorted(row['name'] for row in family),
                profile_manifest_sha256=digest(PROFILE / 'manifest.json'),
                sdk_receipt_sha256=digest(receipt_path), base_sdk_commit=revision,
                acquired_root=str(next(iter(roots))), mirror=str(mirror),
                target_sha256=digest(target_path), files=files)


def adopted(value, route):
    names = set(route['names'])
    family = [row for row in value['packages'] if row['name'] in names
              or row.get('source') and SDK_URL in row['source']]
    if len(family) != len(names) or {row['name'] for row in family} != names:
        raise ValueError('SDK application adopted a mixed or duplicate family')
    for row in family:
        path = Path(row['manifest_path']).resolve(strict=True)
        if row.get('source') is not None or str(path.parent) not in route['paths']:
            raise ValueError('SDK application did not adopt its selected mirror')
