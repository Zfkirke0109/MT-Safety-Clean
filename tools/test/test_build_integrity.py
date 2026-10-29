"""Behavioral cache/download and real ZIP/DEX tamper regressions (no network)."""
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
import zipfile

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))


def module(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / (name + '.py'))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


toolchain = module('toolchain')
package = module('package_integrity')
api_receipts = module('cached_api_receipts')


class BuildIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.content = b'reviewed toolchain bytes'
        self.item = {'file': 'tool.jar', 'url': 'https://invalid.test/tool.jar',
                     'sha256': hashlib.sha256(self.content).hexdigest()}

    def test_valid_cached_input_uses_no_network(self):
        (self.root / 'tool.jar').write_bytes(self.content)
        self.assertEqual(toolchain.fetch(self.item, self.root,
                         lambda *_: self.fail('unexpected download')).read_bytes(), self.content)

    def test_corrupt_cache_is_rejected_without_network(self):
        (self.root / 'tool.jar').write_bytes(b'tampered cached executable')
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            toolchain.fetch(self.item, self.root, lambda *_: self.fail('corrupt cache silently repaired'))

    def test_download_checked_before_publish_and_temp_removed(self):
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            toolchain.fetch(self.item, self.root, lambda _, p: p.write_bytes(b'tampered download'))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_good_download_published_only_after_hash(self):
        self.assertEqual(toolchain.fetch(self.item, self.root,
                         lambda _, p: p.write_bytes(self.content)).read_bytes(), self.content)

    def test_extracted_cache_independently_verified(self):
        spec = dict(self.item, extract={'member': 'classes.jar', 'file': 'api.jar',
                                       'sha256': self.item['sha256']})
        (self.root / 'api.jar').write_bytes(b'corrupted extracted jar')
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            toolchain.extract(spec, self.root / 'not-even-opened.zip', self.root)

    def test_extraction_hash_and_exact_member(self):
        archive = self.root / 'api.aar'
        package.write_zip(archive, {'classes.jar': self.content, '../escape': b'unrelated path'})
        spec = dict(self.item, extract={'member': 'classes.jar', 'file': 'api.jar',
                                       'sha256': self.item['sha256']})
        toolchain.extract(spec, archive, self.root)
        self.assertEqual((self.root / 'api.jar').read_bytes(), self.content)
        self.assertFalse((self.root.parent / 'escape').exists())
        (self.root / 'api.jar').unlink()
        spec['extract']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            toolchain.extract(spec, archive, self.root)
        self.assertFalse((self.root / 'api.jar').exists())

    def test_runtime_flatten_excludes_multi_release_and_module_classes(self):
        archive, expected = self.root / 'runtime.jar', self.root / 'expected.jar'
        java8 = b'\xca\xfe\xba\xbe\x00\x00\x00\x34test'
        package.write_zip(archive, {'org/example/Base.class': java8,
            'module-info.class': b'not Java8', 'META-INF/versions/9/org/example/Base.class': b'newer'})
        package.write_zip(expected, {'org/example/Base.class': java8})
        spec = dict(self.item, flatten={'file': 'runtime-java8.jar', 'sha256': toolchain.digest(expected)})
        toolchain.flatten_java8(spec, archive, self.root)
        flattened = self.root / 'runtime-java8.jar'
        self.assertEqual(package.read_zip(flattened), {'org/example/Base.class': java8})
        flattened.write_bytes(b'cached runtime tamper')
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            toolchain.flatten_java8(spec, archive, self.root)

    def test_runtime_newer_base_class_refused(self):
        archive = self.root / 'runtime.jar'
        package.write_zip(archive, {'org/example/Base.class': b'\xca\xfe\xba\xbe\x00\x00\x00\x35newer'})
        spec = dict(self.item, flatten={'file': 'runtime-java8.jar', 'sha256': '0' * 64})
        with self.assertRaisesRegex(ValueError, 'non-Java8'):
            toolchain.flatten_java8(spec, archive, self.root)
        self.assertFalse((self.root / 'runtime-java8.jar').exists())

    def test_real_dex_tamper_detected_despite_identical_unhashed_manifest(self):
        old, new = self.root / 'old.mtp', self.root / 'new.mtp'
        # CONTENTS deliberately has the historical un-hashed DEX entry in both packages.
        entries = {'manifest.json': b'{}', 'classes.dex': b'dex\n035\x00old',
                   'CONTENTS.txt': b'classes.dex  (compiled; not hashed)\n'}
        package.write_zip(old, entries)
        entries['classes.dex'] = b'dex\n035\x00fresh'
        package.write_zip(new, entries)
        with self.assertRaisesRegex(ValueError, 'classes.dex'):
            package.compare(old, new)
        entries['classes.dex'] = b'dex\n035\x00old'
        entries['assets/scanner-worker.dex'] = b'worker'
        package.write_zip(new, entries)
        with self.assertRaisesRegex(ValueError, 'assets/scanner-worker.dex'):
            package.compare(old, new)

    def test_verified_legacy_api_receipts_recover_missing_current_cache(self):
        old, current, receipts = self.root / 'legacy', self.root / 'current', self.root / 'receipts'
        old.mkdir()
        (old / 'mt-api.aar').write_bytes(b'approved aar')
        (old / 'mt-plugin-api.jar').write_bytes(b'approved jar')
        lock = {'inputs': [{'name': 'mt-plugin-api', 'file': 'mt-api.aar',
            'sha256': package.sha(b'approved aar'), 'extract': {'file': 'mt-plugin-api.jar',
            'sha256': package.sha(b'approved jar')}}]}
        self.assertEqual(api_receipts.stage_api(lock, [current, old], current, receipts),
                         ['mt-api.aar', 'mt-plugin-api.jar'])
        self.assertEqual((current / 'mt-api.aar').read_bytes(), b'approved aar')
        self.assertEqual((receipts / 'mt-plugin-api.jar').read_bytes(), b'approved jar')

    def test_corrupt_legacy_api_does_not_publish_receipt(self):
        old, current, receipts = self.root / 'legacy', self.root / 'current', self.root / 'receipts'
        old.mkdir()
        (old / 'mt-api.aar').write_bytes(b'corrupt cached aar')
        lock = {'inputs': [{'name': 'mt-plugin-api', 'file': 'mt-api.aar', 'sha256': '0' * 64,
                           'extract': {'file': 'mt-plugin-api.jar', 'sha256': '0' * 64}}]}
        with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
            api_receipts.stage_api(lock, [current, old], current, receipts)
        self.assertFalse(receipts.exists())
        self.assertFalse(current.exists())
        (old / 'mt-api.aar').unlink()
        self.assertEqual(api_receipts.stage_api(lock, [current, old], current, receipts), [])
        self.assertFalse(receipts.exists())

    def test_actual_committed_dex_mutation_is_rejected(self):
        committed = TOOLS.parent / 'dist/mt-safety-scanner.mtp'
        members = package.read_zip(committed)
        self.assertTrue(members['classes.dex'].startswith(b'dex\n'))
        # Flip an actual compiled DEX byte; preserve every other checked-in member verbatim.
        dex = bytearray(members['classes.dex'])
        dex[-1] ^= 1
        members['classes.dex'] = bytes(dex)
        changed = self.root / 'changed.mtp'
        package.write_zip(changed, members)
        with self.assertRaisesRegex(ValueError, 'classes.dex'):
            package.compare(committed, changed)

    def test_zip_repeatability_sorted_names_fixed_timestamp(self):
        a, b = self.root / 'a.mtp', self.root / 'b.mtp'
        package.write_zip(a, {'z': b'z', 'manifest.json': b'{}', 'classes.dex': b'dex'})
        package.write_zip(b, {'classes.dex': b'dex', 'manifest.json': b'{}', 'z': b'z'})
        self.assertEqual(a.read_bytes(), b.read_bytes())
        with zipfile.ZipFile(a) as zipped:
            self.assertEqual(zipped.namelist(), ['manifest.json', 'classes.dex', 'z'])
            self.assertTrue(all(i.date_time == package.EPOCH for i in zipped.infolist()))
        package.compare(a, b)

    def test_receipts_cover_every_dex_and_repeated_build_ignores_mtime(self):
        stage = self.root / 'stage'
        (stage / 'assets').mkdir(parents=True)
        (stage / 'manifest.json').write_text(json.dumps({'pluginID': 'mt.safety.scanner',
            'pluginSdkVersion': 3, 'minAndroidVersion': 24, 'dexMode': True, 'versionName': 'test'}))
        (stage / 'classes.dex').write_bytes(b'dex main')
        (stage / 'assets/scanner-worker.dex').write_bytes(b'dex worker')
        first, second = self.root / 'first', self.root / 'second'
        package.package(stage, first, TOOLS.parent)
        for path in stage.rglob('*'):
            os.utime(path, (1700000000, 1700000000))
        package.package(stage, second, TOOLS.parent)
        self.assertEqual((first / 'mt-safety-scanner.mtp').read_bytes(),
                         (second / 'mt-safety-scanner.mtp').read_bytes())
        receipt = json.loads((first / 'PROVENANCE.json').read_text())
        self.assertEqual(receipt['build']['workerAsset'], 'assets/scanner-worker.dex')
        for name, content in package.files(stage).items():
            self.assertEqual(receipt['members'][name], package.sha(content))
            self.assertIn(name + '  ' + package.sha(content), (first / 'CONTENTS.txt').read_text())
        self.assertIn('tools/toolchain-lock.json', receipt['sources'])
        for line in (first / 'SHA256SUMS').read_text().splitlines():
            expected, name = line.split('  ', 1)
            self.assertEqual(expected, package.sha((first / name).read_bytes()))
        sbom = json.loads((first / 'SBOM.cdx.json').read_text())
        self.assertTrue(all(x['scope'] == ('required' if x['name'] == 'xz' else 'excluded') for x in sbom['components']))

    def test_duplicate_dex_refused(self):
        path = self.root / 'duplicate.mtp'
        with zipfile.ZipFile(path, 'w') as zipped:
            zipped.writestr('classes.dex', b'old')
            with self.assertWarns(UserWarning):
                zipped.writestr('classes.dex', b'new')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            package.read_zip(path)


if __name__ == '__main__':
    unittest.main()
