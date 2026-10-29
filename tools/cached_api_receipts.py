#!/usr/bin/env python3
"""Stage only independently hash-verified locked MT API bytes; never download anything."""
import json
from pathlib import Path
import shutil
import sys

from toolchain import verify


def stage_api(lock, sources, cache, receipts):
    item = next(x for x in lock['inputs'] if x['name'] == 'mt-plugin-api')
    specs = [(item['file'], item['sha256']), (item['extract']['file'], item['extract']['sha256'])]
    verified = {}
    # Validate all available candidates before publishing anything. A corrupt restored cache fails closed.
    for name, expected in specs:
        for source in sources:
            candidate = source / name
            if candidate.exists():
                verify(candidate, expected)
                verified.setdefault(name, candidate)
    for name, source in verified.items():
        cache.mkdir(parents=True, exist_ok=True)
        receipts.mkdir(parents=True, exist_ok=True)
        if source.resolve() != (cache / name).resolve():
            shutil.copyfile(source, cache / name)
        shutil.copyfile(source, receipts / name)
        verify(receipts / name, dict(specs)[name])
        print('verified cached build input ' + name)
    return sorted(verified)


if __name__ == '__main__':
    try:
        lock = json.loads(Path(__file__).with_name('toolchain-lock.json').read_text())
        # Current cache, original historical-cache path, verified-only artifact staging directory.
        stage_api(lock, [Path(sys.argv[1]), Path(sys.argv[2])], Path(sys.argv[1]), Path(sys.argv[3]))
    except (ValueError, OSError) as error:
        sys.exit(str(error))
