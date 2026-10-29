#!/usr/bin/env python3
"""Deterministic ZIPs, every-member receipts and comparison of real archive bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

EPOCH = (1980, 1, 1, 0, 0, 0)
MAX_PACKAGE_BYTES = 128 * 1024 * 1024
MAX_MEMBERS = 4096


def sha(data):
    return hashlib.sha256(data).hexdigest()


def files(root):
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('Symlink in package inputs: ' + str(path))
        if path.is_file():
            result[path.relative_to(root).as_posix()] = path.read_bytes()
    return result


def write_zip(dest, members):
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, 'w', compression=zipfile.ZIP_STORED) as zipped:
        # SDK3 requires manifest first. All remaining names have a fixed lexical order.
        for name in sorted(members, key=lambda name: (name != 'manifest.json', name)):
            info = zipfile.ZipInfo(name, EPOCH)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            zipped.writestr(info, members[name])


def read_zip(path):
    if path.stat().st_size > MAX_PACKAGE_BYTES:
        raise ValueError('Package exceeds comparison byte limit')
    with zipfile.ZipFile(path) as zipped:
        infos = zipped.infolist()
        names = [i.filename for i in infos if not i.is_dir()]
        if len(infos) > MAX_MEMBERS or len(set(names)) != len(names):
            raise ValueError('Too many or duplicate ZIP members')
        if sum(i.file_size for i in infos) > MAX_PACKAGE_BYTES:
            raise ValueError('Package expands beyond comparison byte limit')
        return {i.filename: zipped.read(i) for i in infos if not i.is_dir()}


def compare(committed, rebuilt):
    old, new = read_zip(committed), read_zip(rebuilt)
    changed = sorted(name for name in set(old) | set(new) if old.get(name) != new.get(name))
    if changed:
        raise ValueError('Committed package differs from fresh build: ' + ', '.join(changed))
    if 'classes.dex' not in old:
        raise ValueError('Package has no classes.dex')
    print('PASS actual package members match, including classes.dex and any worker DEX')


def json_write(path, content):
    path.write_text(json.dumps(content, indent=2, sort_keys=True) + '\n')


def package(stage, output, root):
    members = files(stage)
    if 'classes.dex' not in members or 'manifest.json' not in members or 'assets/scanner-worker.dex' not in members:
        raise ValueError('SDK3 package requires manifest.json, classes.dex and freshly compiled assets/scanner-worker.dex')
    manifest = json.loads(members['manifest.json'])
    if manifest.get('pluginID') != 'mt.safety.scanner' or manifest.get('pluginSdkVersion') != 3 or manifest.get('minAndroidVersion') != 24 or manifest.get('dexMode') is not True:
        raise ValueError('Unexpected SDK3 manifest identity/compatibility')
    output.mkdir(parents=True, exist_ok=True)
    artifact = output / 'mt-safety-scanner.mtp'
    write_zip(artifact, members)
    hashes = {name: sha(data) for name, data in sorted(members.items())}
    (output / 'CONTENTS.txt').write_text(''.join('{}  {}\n'.format(name, value) for name, value in hashes.items()))
    lock = json.loads((root / 'tools/toolchain-lock.json').read_text())
    # Receipts include exact source/resource/build inputs, including untracked new source files.
    sources = {}
    for base in ['plugin', 'tools']:
        for path in sorted((root / base).rglob('*')):
            if path.is_file() and not path.is_symlink() and '__pycache__' not in path.parts:
                sources[path.relative_to(root).as_posix()] = sha(path.read_bytes())
    revision = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    compiler = subprocess.run(['javac', '-version'], capture_output=True, text=True, check=True)
    runtime = subprocess.run(['java', '-version'], capture_output=True, text=True, check=True)
    json_write(output / 'PROVENANCE.json', {
        'schemaVersion': 1, 'artifact': {'name': artifact.name, 'sha256': sha(artifact.read_bytes())},
        'members': hashes, 'sourceRevision': revision, 'sources': sources,
        'toolchain': lock, 'toolVersions': {'javac': (compiler.stdout + compiler.stderr).strip(),
            'java': (runtime.stdout + runtime.stderr).strip()}, 'build': {'javaSourceTarget': 8, 'minApi': 24,
            'zipTimestamp': '1980-01-01T00:00:00Z', 'compression': 'stored',
            'hostApi': 'compile-only', 'workerAsset': 'assets/scanner-worker.dex', 'workerEntry': 'mt.safety.scanner.ui.AndroidWorkerMain',
            'workerSources': ['plugin/src', 'plugin/ui-v3/mt/safety/scanner/ui/AndroidWorkerMain.java'],
            'command': 'bash tools/build.sh package'}})
    json_write(output / 'SBOM.cdx.json', {
        'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
        'metadata': {'component': {'type': 'application', 'name': 'mt.safety.scanner', 'version': manifest['versionName']}},
        'components': [{'type': 'library', 'name': item['name'], 'version': item['version'],
            'scope': 'excluded' if item['scope'] in ('build', 'compile-only') else 'required',
            'hashes': [{'alg': 'SHA-256', 'content': item['sha256']}],
            'properties': [{'name': 'mt:scope', 'value': item['scope']}, {'name': 'mt:license', 'value': item['license']}],
            'externalReferences': [{'type': 'distribution', 'url': item['url']}]} for item in lock['inputs']]})
    receipts = ['mt-safety-scanner.mtp', 'CONTENTS.txt', 'PROVENANCE.json', 'SBOM.cdx.json']
    (output / 'SHA256SUMS').write_text(''.join('{}  {}\n'.format(sha((output / n).read_bytes()), n) for n in receipts))
    print('{} sha256 {}'.format(artifact, sha(artifact.read_bytes())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['jar', 'package', 'compare'])
    parser.add_argument('paths', nargs='+', type=Path)
    args = parser.parse_args()
    if args.mode == 'jar':
        write_zip(args.paths[1], files(args.paths[0]))
    elif args.mode == 'compare':
        compare(*args.paths)
    else:
        package(*args.paths)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, zipfile.BadZipFile) as error:
        sys.exit(str(error))
