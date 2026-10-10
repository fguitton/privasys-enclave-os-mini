#!/usr/bin/env python3
"""Versioned data-only owner: Rust generation and Python geometry bindings.
No geometry or digest supplies caller, source, reader or custody authority.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import sys
import sysconfig
def require_supported_python():
    if (sys.implementation.name != 'cpython' or not (3, 10) <= sys.version_info[:2] < (3, 15)
            or sys.version_info.releaselevel != 'final'):
        raise ValueError('source wire generation requires final CPython >=3.10,<3.15')

require_supported_python()

CONTRACT_PATH = Path(__file__).with_name('source-upload-wire-v1.json')
SCALARS = ('source_aead_tag_bytes', 'batch_item_prefix_bytes')
LAYOUTS = ('frame', 'batch', 'peer', 'single_peer', 'push')
FIELD_NAMES = {
    'frame': ('magic', 'ticket', 'session', 'ordinal', 'offset', 'page_length', 'data_length'),
    'batch': ('magic', 'count'),
    'peer': ('magic', 'expected', 'ticket', 'session', 'manifest_length'),
    'single_peer': ('magic', 'expected', 'manifest_length'),
    'push': ('magic', 'expected', 'manifest_length', 'count'),
}

def load_contract():
    raw = CONTRACT_PATH.read_bytes()
    if len(raw) > 8192:
        raise ValueError('wire contract too large')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate wire field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    expected = {'schema_version', 'contract', *SCALARS, *(name+'_fields' for name in LAYOUTS)}
    if set(value) != expected or type(value['schema_version']) is not int or value['schema_version'] != 1 or value['contract'] != 'honest-source-upload-wire-geometry-v1':
        raise ValueError('unsupported wire contract')
    result = {'contract_sha256': hashlib.sha256(raw).hexdigest()}
    for key in SCALARS:
        n = value[key]
        if type(n) is not int or not 0 < n <= 2**31-1:
            raise ValueError('invalid wire scalar')
        result[key.upper()] = n
    for layout in LAYOUTS:
        fields = value[layout+'_fields']
        if (not isinstance(fields, list)
                or any(not isinstance(row, list) or len(row) != 2 for row in fields)
                or tuple(row[0] for row in fields) != FIELD_NAMES[layout]):
            raise ValueError('missing, unknown or reordered wire layout field')
        offset = 0
        names = set()
        for row in fields:
            if not isinstance(row, list) or len(row) != 2:
                raise ValueError('invalid wire layout field')
            name, width = row
            if (not isinstance(name, str) or not name.isidentifier() or name in names
                    or type(width) is not int or not 0 < width <= 32):
                raise ValueError('invalid wire layout width')
            names.add(name)
            result[(layout+'_'+name+'_start').upper()] = offset
            offset += width
            result[(layout+'_'+name+'_end').upper()] = offset
        result[(layout+'_header_bytes').upper()] = offset
    return result

def load_producer_geometry(path):
    raw = Path(path).read_bytes()
    if len(raw) > 8192:
        raise ValueError('producer geometry too large')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate producer field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    fields = ('default_plaintext_bytes', 'largest_plaintext_bytes', 'maximum_page_bytes', 'maximum_manifest_bytes')
    if (set(value) != {'schema_version', 'contract', *fields}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['contract'] != 'honest-source-upload-producer-geometry-v1'):
        raise ValueError('unsupported producer geometry')
    result = load_contract()
    result['producer_sha256'] = hashlib.sha256(raw).hexdigest()
    for key in fields:
        n = value[key]
        if type(n) is not int or not 0 < n <= 2**31-1:
            raise ValueError('invalid producer geometry scalar')
        result[key.upper()] = n
    width = result['PEER_MANIFEST_LENGTH_END'] - result['PEER_MANIFEST_LENGTH_START']
    if result['MAXIMUM_MANIFEST_BYTES'] >= 1 << (8 * width):
        raise ValueError('producer manifest exceeds wire length field')
    if result['DEFAULT_PLAINTEXT_BYTES'] > result['LARGEST_PLAINTEXT_BYTES']:
        raise ValueError('invalid producer profile ordering')
    for profile in ('DEFAULT', 'LARGEST'):
        item = frame_item_bytes(result, result[profile+'_PLAINTEXT_BYTES'])
        if item > 2**31-1:
            raise ValueError('producer frame overflow')
        result[profile+'_FRAME_ITEM_BYTES'] = item
    return result

def frame_item_bytes(contract, plaintext):
    if type(plaintext) is not int or plaintext not in (contract['DEFAULT_PLAINTEXT_BYTES'], contract['LARGEST_PLAINTEXT_BYTES']):
        raise ValueError('unsupported source frame profile')
    return contract['BATCH_ITEM_PREFIX_BYTES'] + contract['FRAME_HEADER_BYTES'] + contract['MAXIMUM_PAGE_BYTES'] + plaintext + contract['SOURCE_AEAD_TAG_BYTES']

def rust_bindings(contract):
    lines = ['// Generated from the versioned data-only owner; do not edit.',
        '/// Digest of the exact geometry owner bytes; no authorization claim.',
        'pub const CONTRACT_SHA256: &str = "'+contract['contract_sha256']+'";']
    for key in sorted(contract):
        if key not in ('contract_sha256', 'producer_sha256'):
            number = format(contract[key], '_d')
            lines += ['/// Pure wire field geometry or separate producer geometry; no admission.', 'pub const '+key+': usize = '+number+';']
            if key in ('DEFAULT_PLAINTEXT_BYTES', 'LARGEST_PLAINTEXT_BYTES'):
                # Both typed bindings come from the same checked policy scalar;
                # the encoder's data-length field is explicitly a u32.
                lines += ['/// Same checked plaintext bound in the wire field representation.',
                    'pub const '+key+'_U32: u32 = '+number+';']
    if 'producer_sha256' in contract:
        lines += ['/// Digest of separately owned producer profiles.', 'pub const PRODUCER_SHA256: &str = "'+contract['producer_sha256']+'";']
    return '\n'.join(lines)+'\n'

def file_record(path):
    canonical = Path(path).resolve(strict=True)
    digest = hashlib.sha256()
    with canonical.open('rb') as source:
        for block in iter(lambda: source.read(io.DEFAULT_BUFFER_SIZE), b''):
            digest.update(block)
    return {'path': str(canonical), 'sha256': digest.hexdigest(), 'bytes': canonical.stat().st_size}


def build_provenance(producer_path, expected_interpreter, rust_bytes, bindings):
    executable = Path(sys.executable).resolve(strict=True)
    if executable != Path(expected_interpreter).resolve(strict=True):
        raise ValueError('selected interpreter differs from actual CPython executable')
    paths = sysconfig.get_paths()
    stdlib = Path(paths['stdlib']).resolve(strict=True)
    modules = []
    tracked = set()
    for name, module in sorted(tuple(sys.modules.items())):
        origin = getattr(getattr(module, '__spec__', None), 'origin', None)
        row = {'module': name, 'origin': origin}
        filename = getattr(module, '__file__', None)
        if filename and Path(filename).is_file():
            row['file'] = file_record(filename)
            tracked.add(row['file']['path'])
            path = Path(row['file']['path'])
            row['classification'] = 'stdlib-file' if path.is_relative_to(stdlib) else 'other-loaded-file'
            cached = getattr(module, '__cached__', None)
            if cached and Path(cached).is_file():
                row['cached_file'] = file_record(cached)
                tracked.add(row['cached_file']['path'])
        else:
            row['classification'] = 'builtin-or-frozen-or-no-file'
        modules.append(row)
    native = []
    mappings = Path('/proc/self/maps')
    if mappings.is_file():
        for line in mappings.read_text().splitlines():
            fields = line.split(None, 5)
            if len(fields) == 6 and 'x' in fields[1] and fields[5].startswith('/'):
                path = Path(fields[5])
                if not path.is_file():
                    raise ValueError('loaded native code file unavailable for provenance')
                record = file_record(path)
                if record['path'] not in {row['path'] for row in native}:
                    native.append(record)
                    tracked.add(record['path'])
        native_status = 'RECORDED executable mappings; not an acquired closure'
    else:
        native_status = 'UNAVAILABLE executable mapping capture on this platform'
    inputs = {'generator': file_record(__file__), 'wire_owner': file_record(CONTRACT_PATH),
              'producer_owner': file_record(producer_path) if producer_path else None}
    if inputs['wire_owner']['sha256'] != bindings['contract_sha256']:
        raise ValueError('wire owner changed during generation')
    if producer_path and inputs['producer_owner']['sha256'] != bindings['producer_sha256']:
        raise ValueError('producer owner changed during generation')
    for record in inputs.values():
        if record:
            tracked.add(record['path'])
    interpreter = file_record(executable)
    tracked.add(interpreter['path'])
    for path in sorted(tracked):
        if '\n' in path or '\r' in path:
            raise ValueError('invalid build input path')
        print('cargo:rerun-if-changed='+path, file=sys.stderr)
    return {'schema_version': 1,
        'qualification': 'RECORDED_NATIVE_BUILD_INPUTS_ONLY; acquired/pinned closure PENDING',
        'interpreter': interpreter, 'python_version': sys.version,
        'implementation': sys.implementation.name,
        'supported_rule': 'final CPython >=3.10,<3.15',
        'isolation': {'isolated': sys.flags.isolated, 'ignore_environment': sys.flags.ignore_environment,
                      'no_user_site': sys.flags.no_user_site, 'no_site': sys.flags.no_site,
                      'dont_write_bytecode': sys.flags.dont_write_bytecode},
        'stdlib_root': str(stdlib), 'loaded_modules': modules,
        'native_code_capture': native_status, 'loaded_native_code': sorted(native, key=lambda row: row['path']),
        'source_inputs': inputs, 'rust_bindings_sha256': hashlib.sha256(rust_bytes).hexdigest(),
        'limits': ['capture is not a hermetic/release pin',
                   'loaded module source/cache files are conservative relevant inputs, not proof which cache executed',
                   'frozen/builtin code is covered by captured executable/native mappings where available',
                   'site hooks and dependencies not represented by loaded files remain outside acquired closure']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rust', action='store_true', required=True)
    parser.add_argument('producer_path', nargs='?')
    parser.add_argument('--provenance', type=Path)
    parser.add_argument('--interpreter', type=Path)
    args = parser.parse_args()
    if (args.provenance is None) != (args.interpreter is None):
        raise ValueError('provenance requires exact selected interpreter')
    bindings = load_contract() if args.producer_path is None else load_producer_geometry(args.producer_path)
    rust = rust_bindings(bindings)
    if args.provenance is not None:
        provenance = build_provenance(args.producer_path, args.interpreter, rust.encode('utf-8'), bindings)
        args.provenance.write_text(json.dumps(provenance, indent=2, sort_keys=True)+'\n')
    sys.stdout.write(rust)
