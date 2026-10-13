#!/usr/bin/env python3
"""Bind requested host capabilities to their Cargo owner and actual binary."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import tomllib
import xml.etree.ElementTree as ET


def require(value, message):
    if not value:
        raise ValueError(message)


def names(text):
    if not text:
        return []
    result = text.split(',')
    require(all(name and name.strip() == name for name in result)
            and len(set(result)) == len(result), 'malformed/duplicate host feature list')
    return sorted(result)


def cargo_tables(path, owners):
    # Cargo accepts TOML1.1 multiline dependency inline tables. The protocol
    # owns only feature arrays/metadata; parse those exact original sections,
    # retaining the complete Cargo file hash as a build input.
    lines, selected = [], False
    for line in path.read_text().splitlines(keepends=True):
        if line.lstrip().startswith('['):
            table = line.split('#', 1)[0].strip().strip('[]')
            selected = any(table == owner or table.startswith(owner + '.') for owner in owners)
        if selected:
            lines.append(line)
    return tomllib.loads(''.join(lines))


def feature_closure(features, selected):
    require(set(selected) <= set(features), 'unknown selected feature')
    pending = list(selected)
    if 'default' in features:
        pending.append('default')
    closure = set()
    while pending:
        feature = pending.pop()
        if feature in closure:
            continue
        closure.add(feature)
        pending += [name for name in features[feature] if name in features]
    return closure


def declaration(args):
    cargo = cargo_tables(args.manifest, ['features'])
    available = cargo.get('features', {})
    selected, required = names(args.features), names(args.required)
    inputs = [args.manifest, Path(__file__).resolve()]
    if args.enclave_manifest:
        inputs.append(args.enclave_manifest)
        composition = cargo_tables(args.enclave_manifest, ['features', 'package.metadata.honest-host-protocol'])
        features = composition.get('features', {})
        # Explicit enclave tuples use --no-default-features in this producer.
        requested = names(args.enclave_features)
        closure = feature_closure(features, requested)
        if requested and 'default' not in requested:
            closure = feature_closure({key: value for key, value in features.items()
                                       if key != 'default'}, requested)
        contract = composition.get('package', {}).get('metadata', {}).get('honest-host-protocol')
        if contract:
            require(contract.get('schema-version') == 1, 'unsupported producer host contract')
            for rule in contract['requirements']:
                require(rule['when-feature'] in features, 'producer rule names unknown feature')
                if rule['when-feature'] in closure:
                    required.append(rule['host-feature'])
    required = sorted(set(required))
    require(set(selected) | set(required) <= set(available), 'unknown host feature')
    closure = feature_closure(available, selected)
    require(set(required) <= closure, 'required host capability omitted')
    normalized = [name.lower().replace('_', '-') for name in available]
    require(len(set(normalized)) == len(normalized), 'ambiguous Cargo feature spelling')
    enclave_policy = None
    if args.enclave_config:
        inputs.append(args.enclave_config)
        values = ET.parse(args.enclave_config).getroot().findall('DisableDebug')
        require(len(values) == 1 and values[0].text in ('0', '1'), 'invalid enclave debug policy')
        enclave_policy = dict(disable_debug=values[0].text == '1',
                              sha256=hashlib.sha256(args.enclave_config.read_bytes()).hexdigest())
    expected_debug = args.release_debug_assertions == 'true' if args.build_type == 'Release' else True
    require(not enclave_policy or not enclave_policy['disable_debug'] or not expected_debug,
            'host debug request contradicts DisableDebug enclave policy')
    return dict(schema_version=1, enclave_policy=enclave_policy, features=sorted(name.lower().replace('_', '-') for name in closure),
                requested_features=selected, required_features=required,
                debug_assertions=expected_debug, sgx_mode=args.sgx_mode,
                python=dict(path=str(Path(sys.executable).resolve()),
                            sha256=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()),
                inputs=[dict(path=str(path.resolve()), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                        for path in inputs])


def validate_actual(declared, observed):
    require(type(observed.get('schema_version')) is int, 'invalid compiled schema type')
    require(observed.get('schema_version') == declared['schema_version']
            and sorted(observed.get('features', [])) == declared['features']
            and observed.get('debug_assertions') is declared['debug_assertions']
            and observed.get('sgx_mode') == declared['sgx_mode'],
            'compiled host capability/profile differs from declared build')


def actual(args):
    declared = json.loads(args.declared.read_text())
    result = subprocess.run([str(args.actual), '--build-contract'], check=True,
                            capture_output=True, text=True, timeout=10)
    observed = json.loads(result.stdout)
    if args.enclave_config:
        require(declared.get('enclave_policy') is not None and
                hashlib.sha256(args.enclave_config.read_bytes()).hexdigest() ==
                declared['enclave_policy']['sha256'], 'signing XML differs from host protocol declaration')
    require(not declared.get('enclave_policy') or
            not declared['enclave_policy']['disable_debug'] or
            observed.get('debug_assertions') is False,
            'compiled host requests debug from DisableDebug enclave')
    validate_actual(declared, observed)
    return dict(status='PASS_COMPILED_HOST_CONTRACT', declared=declared, actual=observed,
                declared_sha256=hashlib.sha256(args.declared.read_bytes()).hexdigest(),
                host_sha256=hashlib.sha256(args.actual.read_bytes()).hexdigest())



def self_test():
    refusals = 0
    def reject(callback):
        nonlocal refusals
        try:
            callback()
        except (ValueError, TypeError):
            refusals += 1
        else:
            raise AssertionError('invalid host contract accepted')
    for value in ['x,x', ' x', 'x,', 'x,,y']:
        reject(lambda value=value: names(value))
    with tempfile.TemporaryDirectory(prefix='host-contract-guard-') as tmp:
        root = Path(tmp)
        cargo = root / 'Cargo.toml'
        cargo.write_text('[features] # actual owner\ndefault = ["alias"]\nalias = ["stream-read-credit"]\nstream-read-credit = []\nfuture = []\n')
        xml = root / 'enclave.xml'
        xml.write_text('<EnclaveConfiguration><DisableDebug>1</DisableDebug></EnclaveConfiguration>')
        args = SimpleNamespace(manifest=cargo, features='', required='stream-read-credit',
                               enclave_manifest=None, enclave_features='', enclave_config=xml,
                               release_debug_assertions='false', build_type='Release', sgx_mode='HW')
        baseline = declaration(args)
        assert baseline['features'] == ['alias', 'default', 'stream-read-credit']
        args.features = 'future'
        assert 'future' in declaration(args)['features']
        args.features = ''
        for field, value in [('features', 'unknown'), ('features', 'alias,alias'),
                             ('required', 'unknown'), ('release_debug_assertions', 'true'),
                             ('build_type', 'Debug')]:
            original = getattr(args, field)
            setattr(args, field, value)
            reject(lambda: declaration(args))
            setattr(args, field, original)
        cargo.write_text('[features]\nstream-read-credit = []\n')
        reject(lambda: declaration(args))
        cargo.write_text('[features]\nstream-read-credit = []\nstream_read_credit = []\n')
        args.features = 'stream-read-credit'
        reject(lambda: declaration(args))
        cargo.write_text('[features]\nstream-read-credit = []\n')
        for text in ['<E/>', '<E><DisableDebug>2</DisableDebug></E>',
                     '<E><DisableDebug>1</DisableDebug><DisableDebug>0</DisableDebug></E>']:
            xml.write_text(text)
            reject(lambda: declaration(args))
        observed = {key: baseline[key] for key in ['schema_version', 'features', 'debug_assertions', 'sgx_mode']}
        validate_actual(baseline, observed)
        for field, value in [('schema_version', 2), ('schema_version', True),
                             ('features', []), ('features', ['alias', 'default', 'stream-read-credit', 'future']),
                             ('features', ['alias', 'default', 'stream-read-credit', 'stream-read-credit']),
                             ('debug_assertions', True), ('debug_assertions', 0),
                             ('sgx_mode', 'SIM')]:
            wrong = dict(observed)
            wrong[field] = value
            reject(lambda: validate_actual(baseline, wrong))
    assert refusals == 22, refusals
    return dict(status='PASS_HOST_CONTRACT_GUARDS', refusal_mutations=refusals,
                scope='Synthetic parser/profile refusals only; actual binary compilation is separate')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--features', default='')
    parser.add_argument('--required', default='')
    parser.add_argument('--enclave-manifest', type=Path)
    parser.add_argument('--enclave-features', default='')
    parser.add_argument('--enclave-config', type=Path)
    parser.add_argument('--release-debug-assertions', choices=['true', 'false'], default='false')
    parser.add_argument('--build-type', default='Release')
    parser.add_argument('--sgx-mode', choices=['HW', 'SIM'], default='HW')
    parser.add_argument('--actual', type=Path)
    parser.add_argument('--declared', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.self_test:
        require(args.actual is None and args.manifest is None and args.declared is None, 'self-test refuses build inputs')
        value = self_test()
    elif args.actual:
        require(args.declared is not None and args.manifest is None, 'actual check requires declaration')
        value = actual(args)
    else:
        require(args.manifest is not None and args.declared is None, 'configuration requires Cargo owner')
        value = declaration(args)
    args.output.write_text(json.dumps(value, indent=2) + '\n')


if __name__ == '__main__':
    main()
