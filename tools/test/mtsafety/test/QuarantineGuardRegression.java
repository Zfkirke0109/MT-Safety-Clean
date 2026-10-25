package mtsafety.test;

import java.io.File;
import java.io.RandomAccessFile;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import mt.safety.scanner.Quarantine;
import mt.safety.scanner.ScanRunner;
import mt.safety.scanner.core.PluginManifest;
import mt.safety.scanner.core.PluginPackage;
import mt.safety.scanner.core.ScanBudget;
import mt.safety.scanner.core.ScanReport;

/** Regressions for callable guards and refusing non-atomic copy/delete moves. */
public final class QuarantineGuardRegression {
    private QuarantineGuardRegression() {
    }

    public static void main(String[] args) throws Exception {
        final int[] failed = {0};
        run(new ActionsTest.Checker() {
            @Override
            public void that(String description, boolean condition, String context) {
                System.out.println((condition ? "PASS " : "FAIL ") + description + ": " + context);
                if (!condition) {
                    failed[0]++;
                }
            }
        });
        if (failed[0] != 0) {
            throw new AssertionError(failed[0] + " quarantine guard regressions failed");
        }
    }

    static void run(ActionsTest.Checker check) throws Exception {
        File root = new File(System.getProperty("java.io.tmpdir"),
                "mtsafety-quarantine-guard-" + System.nanoTime());
        if (!root.mkdirs()) {
            throw new IllegalStateException("could not create " + root);
        }
        Fixtures fixtures = new Fixtures(root);
        Map<String, byte[]> members = new LinkedHashMap<String, byte[]>();
        members.put("manifest.json", Fixtures.bytes(Fixtures.manifest("guard.victim", "Guard", "x.A")));
        members.put("src/x/A.java", Fixtures.bytes("package x; public class A {}"));
        Map<String, byte[]> siblings = new LinkedHashMap<String, byte[]>();
        siblings.put("extracted.txt", Fixtures.bytes("must not be moved without an identity"));
        Quarantine quarantine = new Quarantine(new File(root, "store"));
        File unguarded = fixtures.installedArchive("unguarded", members, siblings);
        Quarantine.Result refusedNull = quarantine.quarantine(unguarded, "mt.safety.scanner", null);
        check.that("three-argument null guard cannot move an archive and uninspected siblings",
                !refusedNull.ok && unguarded.isDirectory()
                        && new File(unguarded, "extracted.txt").isFile(), refusedNull.message);

        Quarantine.MoveGuard sourceOnly = new Quarantine.MoveGuard() {
            @Override
            public boolean allow(File source) {
                return true;
            }
        };
        check.that("a source guard does not implicitly authorize a copied target",
                !sourceOnly.allowCopyTarget(unguarded, new File(root, "other")),
                "default copy-target approval");

        File unpacked = fixtures.directoryPlugin("unguarded-unpacked",
                Fixtures.manifest("unpacked.victim", "Unpacked", "x.A"), Collections.<String, String>emptyMap());
        Quarantine.Result refusedLegacy = quarantine.quarantine(unpacked, "mt.safety.scanner");
        check.that("legacy unpacked quarantine cannot bypass the scan guard",
                !refusedLegacy.ok && unpacked.isDirectory(), refusedLegacy.message);
        File unpackedNull = fixtures.directoryPlugin("unguarded-unpacked-null",
                Fixtures.manifest("unpacked.victim2", "Unpacked2", "x.A"), Collections.<String, String>emptyMap());
        Quarantine.Result refusedUnpackedNull = quarantine.quarantine(unpackedNull, "mt.safety.scanner", null);
        check.that("three-argument unpacked quarantine cannot bypass the scan guard",
                !refusedUnpackedNull.ok && unpackedNull.isDirectory(), refusedUnpackedNull.message);

        File reserved = fixtures.directoryPlugin("reserved-metadata",
                Fixtures.manifest("reserved.victim", "Reserved", "x.A"), Collections.<String, String>emptyMap());
        Fixtures.write(new File(reserved, "quarantine-info.json"), "original plugin data");
        Quarantine.Result refusedMetadata = quarantine.quarantine(reserved, "mt.safety.scanner", sourceOnly);
        check.that("quarantine does not overwrite a plugin's reserved metadata filename",
                !refusedMetadata.ok && new File(reserved, "quarantine-info.json").isFile(),
                refusedMetadata.message);

        String property = "mtsafety.forceCopyFallback";
        String previous = System.getProperty(property);
        File copySource = fixtures.installedArchive("copy-source", members, null);
        Quarantine.Result parked;
        try {
            System.setProperty(property, "true");
            Quarantine.Result refusedCopy = quarantine.quarantine(copySource, "mt.safety.scanner", sourceOnly);
            check.that("failed quarantine rename refuses copy-delete and preserves the complete source",
                    !refusedCopy.ok && copySource.isDirectory()
                            && new File(copySource, "plugin.mtp").isFile()
                            && quarantine.list().isEmpty(), refusedCopy.message);
            System.clearProperty(property);
            File restoreSource = fixtures.installedArchive("restore-source", members, null);
            parked = quarantine.quarantine(restoreSource, "mt.safety.scanner", sourceOnly);
            check.that("same-volume guarded rename remains available", parked.ok && parked.location != null,
                    parked.message);
            if (parked.ok) {
                System.setProperty(property, "true");
                Quarantine.Result refusedRestore = quarantine.restore(parked.location.getName());
                check.that("failed restore rename preserves quarantine data and its restore note",
                        !refusedRestore.ok && parked.location.isDirectory()
                                && new File(parked.location, "quarantine-info.json").isFile()
                                && !restoreSource.exists(), refusedRestore.message);
                System.clearProperty(property);
                Quarantine.Result restored = quarantine.restore(parked.location.getName());
                check.that("a refused restore remains retryable", restored.ok && restoreSource.isDirectory(),
                        restored.message);
            }
        } finally {
            if (previous == null) {
                System.clearProperty(property);
            } else {
                System.setProperty(property, previous);
            }
        }

        File large = fixtures.directoryPlugin("large-identity",
                Fixtures.manifest("large.identity", "Large", "x.A"), Collections.<String, String>emptyMap());
        RandomAccessFile sparse = new RandomAccessFile(new File(large, "large.bin"), "rw");
        try {
            sparse.setLength(25L * 1024 * 1024);
        } finally {
            sparse.close();
        }
        PluginPackage pkg = PluginPackage.open(large);
        ScanReport largeReport;
        try {
            largeReport = new ScanReport("Large", large.getAbsolutePath(), false, true,
                    PluginManifest.parse(Fixtures.bytes(Fixtures.manifest("large.identity", "Large", "x.A"))),
                    pkg.contentHash(ScanBudget.unlimited()));
            largeReport.setDestructiveActionIdentity(pkg.destructiveActionIdentityComplete(),
                    pkg.actionIdentityPath());
        } finally {
            pkg.close();
        }
        Method verify = ScanRunner.class.getDeclaredMethod("verifyActionIdentity", ScanReport.class);
        verify.setAccessible(true);
        Object outcome = verify.invoke(null, largeReport);
        check.that("action identity rehash refuses input larger than its action hash allowance",
                largeReport.contentHash.length() > 0 && "IDENTITY_UNAVAILABLE".equals(String.valueOf(outcome)),
                String.valueOf(outcome));

        File outerStore = new File(root, "bounded-store");
        File wide = new File(outerStore, "wide");
        if (!wide.mkdirs()) {
            throw new IllegalStateException("could not create " + wide);
        }
        for (int i = 0; i < 8001; i++) {
            if (!new File(wide, "entry-" + i).mkdir()) {
                throw new IllegalStateException("could not create wide fixture entry " + i);
            }
        }
        Quarantine wideListing = new Quarantine(wide);
        check.that("quarantine listing rejects an over-limit result instead of retaining it",
                wideListing.list().isEmpty() && wideListing.listingProblem() != null,
                String.valueOf(wideListing.listingProblem()));
        Quarantine.Result refusedPurge = new Quarantine(outerStore).purge("wide");
        check.that("purge refuses an over-limit safety preflight before deleting any entry",
                !refusedPurge.ok && new File(wide, "entry-0").isDirectory()
                        && new File(wide, "entry-8000").isDirectory(), refusedPurge.message);
    }
}
