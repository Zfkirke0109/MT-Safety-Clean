#!/usr/bin/env python3
"""Developer-only pinned secret and AST checks; no cloud upload, dependencies or runtime use."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import zipfile

from toolchain import fetch

ROOT = Path(__file__).resolve().parents[1]


def run_core(binary, target):
    result = subprocess.run([str(binary), '-rules', str(ROOT / 'tools/security/semgrep.yml'),
        '-lang', 'java', '-json_nodots', '-j', '1', '-timeout', '10', '-max_memory', '1024', str(target)],
        capture_output=True, text=True, timeout=45)
    # Always inspect engine/parser errors; an empty result is not sufficient for a passing scan.
    if result.returncode != 0:
        raise ValueError('Semgrep engine failed on ' + str(target))
    output = json.loads(result.stdout)
    if output.get('errors') or output.get('skipped_rules') or not output.get('paths', {}).get('scanned'):
        raise ValueError('Semgrep incomplete on ' + str(target))
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'AMD64'):
        sys.exit('Pinned standalone checks support Linux x86_64 only; not run')
    lock = json.loads((ROOT / 'tools/security/scanners-lock.json').read_text())
    cache = Path(os.environ.get('TMPDIR', '/tmp')) / 'mt-security-tools'
    binaries = {}
    for item in lock['inputs']:
        archive = fetch(item, cache)
        # Re-read a single reviewed member from the verified archive each time. No tar/ZIP path extraction.
        if item['file'].endswith('.whl'):
            with zipfile.ZipFile(archive) as source:
                content = source.read(item['member'])
        else:
            with tarfile.open(archive, 'r:gz') as source:
                member = source.getmember(item['member'])
                if not member.isfile() or member.size > 128 * 1024 * 1024:
                    raise ValueError('Unexpected scanner executable member')
                content = source.extractfile(member).read()
        binary = cache / item['name']
        binary.write_bytes(content)
        binary.chmod(0o755)
        binaries[item['name']] = binary
    gitleaks = subprocess.run([str(binaries['gitleaks']), 'dir', '--redact=100', '--no-banner',
        '--config', str(ROOT / 'tools/security/gitleaks.toml'),
        '--report-format', 'json', '--report-path', str(args.output / 'gitleaks-redacted.json'), '.'],
        cwd=ROOT, capture_output=True, text=True, timeout=120)
    print('gitleaks exit {}'.format(gitleaks.returncode))
    if gitleaks.returncode not in (0, 1):
        raise ValueError('Gitleaks engine failed')
    # Synthetic controls contain no live credentials and never enter source control or reports.
    with tempfile.TemporaryDirectory(dir=cache) as temporary:
        control = Path(temporary) / 'credential.txt'
        control.write_text('aws_access_key_id = "' + 'AKIA' + 'M7X2E4QK6V3AW5ND' + '"')
        positive = subprocess.run([str(binaries['gitleaks']), 'dir', '--redact=100', '--no-banner',
            '--config', str(ROOT / 'tools/security/gitleaks.toml'),
            '--report-format', 'json', '--report-path', str(args.output / 'gitleaks-control-redacted.json'), temporary],
            capture_output=True, text=True, timeout=45)
        if positive.returncode != 1:
            raise ValueError('Gitleaks positive control failed')
    print('Gitleaks positive control PASS')
    # A synthetic positive control ensures that these exact AST rules are active in the real engine.
    with tempfile.TemporaryDirectory(dir=cache) as temporary:
        control = Path(temporary) / 'Positive.java'
        control.write_text('class Positive { void f() { new dalvik.system.DexClassLoader("x", "y", null, null); } }')
        result = run_core(binaries['semgrep-core'], control)
        if not any(r['check_id'] == 'java-dynamic-code-loader' for r in result['results']):
            raise ValueError('Semgrep positive control failed')
    reports = []
    targets = sorted((ROOT / 'plugin').rglob('*.java'))
    for target in targets:
        result = run_core(binaries['semgrep-core'], target)
        reports.extend(result['results'])
    # Store content-free locations only; scanner sources can themselves contain credential fixtures.
    findings = [{'rule': x['check_id'], 'file': str(Path(x['path']).relative_to(ROOT)),
                 'line': x['start']['line']} for x in reports]
    (args.output / 'semgrep-summary.json').write_text(json.dumps({
        'version': '1.138.0', 'filesScanned': len(targets), 'ruleCount': 5,
        'positiveControl': 'PASS', 'errors': 0, 'findings': findings}, indent=2) + '\n')
    print('Semgrep: {} Java files, 5 focused AST rules, {} findings; positive control PASS'.format(len(targets), len(findings)))
    # Command-launch rule is review-only: legitimate scanner-owned OS helpers need a manual assessment.
    errors = [x for x in findings if x['rule'] != 'java-process-from-scanned-content']
    for finding in findings:
        print('{rule} {file}:{line}'.format(**finding))
    if gitleaks.returncode or errors:
        sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, zipfile.BadZipFile, tarfile.TarError) as error:
        sys.exit(str(error))
