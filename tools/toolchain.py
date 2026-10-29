#!/usr/bin/env python3
"""Fetch only lockfile inputs; verify caches and downloads before extraction/use."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from package_integrity import write_zip

MAX_EXTRACTED = 100 * 1024 * 1024


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else _digest(stream)


def _digest(stream):
    result = hashlib.sha256()
    for chunk in iter(lambda: stream.read(65536), b''):
        result.update(chunk)
    return result.hexdigest()


def verify(path, expected):
    actual = digest(path)
    if actual != expected:
        raise ValueError('SHA256 mismatch: {} (expected {}, got {})'.format(path, expected, actual))


def fetch(item, cache, downloader=None):
    dest = cache / item['file']
    if dest.exists():
        verify(dest, item['sha256'])  # Corrupt cache fails closed; never silently replace it.
        return dest
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=cache, prefix='.download-', delete=False) as stream:
        temporary = Path(stream.name)
    try:
        if downloader:
            downloader(item['url'], temporary)
        else:
            subprocess.run(['curl', '--fail', '--silent', '--show-error', '--location',
                            '--proto', '=https', '--proto-redir', '=https', '--retry', '3',
                            '--max-time', '300', '--output', str(temporary), item['url']], check=True)
        verify(temporary, item['sha256'])
        temporary.replace(dest)
    finally:
        temporary.unlink(missing_ok=True)
    return dest


def extract(item, archive, cache):
    spec = item.get('extract')
    if not spec:
        return
    dest = cache / spec['file']
    if dest.exists():
        verify(dest, spec['sha256'])
        return
    with zipfile.ZipFile(archive) as zipped:
        members = [x for x in zipped.infolist() if x.filename == spec['member']]
        if len(members) != 1 or members[0].file_size > MAX_EXTRACTED:
            raise ValueError('Missing, duplicate or oversized locked member: ' + spec['member'])
        # Read one fixed name into a temporary file; never extract paths from an archive.
        with tempfile.NamedTemporaryFile(dir=cache, prefix='.extract-', delete=False) as stream:
            temporary = Path(stream.name)
            try:
                with zipped.open(members[0]) as source:
                    total = 0
                    for chunk in iter(lambda: source.read(65536), b''):
                        total += len(chunk)
                        if total > MAX_EXTRACTED:
                            raise ValueError('Locked member exceeds extraction bound')
                        stream.write(chunk)
                stream.close()
                verify(temporary, spec['sha256'])
                temporary.replace(dest)
            finally:
                temporary.unlink(missing_ok=True)


def flatten_java8(item, archive, cache):
    spec = item.get('flatten')
    if not spec:
        return
    dest = cache / spec['file']
    if dest.exists():
        verify(dest, spec['sha256'])
        return
    with zipfile.ZipFile(archive) as source:
        classes = {}
        for info in source.infolist():
            name = info.filename
            if name.endswith('.class') and not name.startswith('META-INF/versions/') and name != 'module-info.class':
                data = source.read(info)
                if len(data) < 8 or data[:4] != b'\xca\xfe\xba\xbe' or int.from_bytes(data[6:8], 'big') > 52:
                    raise ValueError('Runtime dependency contains non-Java8 class: ' + name)
                classes[name] = data
        if not classes:
            raise ValueError('Runtime dependency has no base classes')
    with tempfile.NamedTemporaryFile(dir=cache, prefix='.flatten-', delete=False) as stream:
        temporary = Path(stream.name)
    try:
        write_zip(temporary, classes)
        verify(temporary, spec['sha256'])
        temporary.replace(dest)
    finally:
        temporary.unlink(missing_ok=True)


def prepare(lock, cache, scope=None):
    for item in lock['inputs']:
        if scope == 'worker':
            if item['name'] == 'mt-plugin-api':
                continue
        elif scope and item['scope'] != scope:
            continue
        archive = fetch(item, cache)
        extract(item, archive, cache)
        flatten_java8(item, archive, cache)
        print('verified {} {}'.format(item['file'], item['sha256']))


if __name__ == '__main__':
    try:
        prepare(json.loads(Path(__file__).with_name('toolchain-lock.json').read_text()), Path(sys.argv[1]),
                sys.argv[2] if len(sys.argv) > 2 else None)
    except (ValueError, OSError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        sys.exit(str(error))
