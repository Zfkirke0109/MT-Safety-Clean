package mtsafety.test;

import java.io.File;
import java.nio.file.Files;
import java.util.Collections;
import java.util.Map;

import mt.safety.scanner.Quarantine;

/** A caller-supplied guard, old test property, or identifier cannot bypass delegation. */
public final class QuarantineGuardRegression {
    private QuarantineGuardRegression() { }

    public static void main(String[] args) throws Exception {
        final int[] counts = {0, 0};
        run(new ActionsTest.Checker() {
            @Override
            public void that(String description, boolean condition, String context) {
                counts[condition ? 0 : 1]++;
                System.out.println((condition ? "PASS " : "FAIL ") + description + ": " + context);
            }
        });
        System.out.println(counts[0] + " passed, " + counts[1] + " failed");
        if (counts[1] != 0) { throw new AssertionError("guard policy failures: " + counts[1]); }
    }

    static void run(ActionsTest.Checker c) throws Exception {
        File root = Files.createTempDirectory("mtsafety-guard-policy-").toFile();
        File source = new Fixtures(root).directoryPlugin("source",
                Fixtures.manifest("guard.victim", "Guard", "x.A"),
                Collections.singletonMap("src/x/A.java", "package x; public class A {}"));
        File store = new File(root, "store");
        File held = new File(store, "old-held");
        File recovery = new File(root, "missing-parent/recovery");
        Fixtures.write(new File(held, "quarantine-info.json"), "{\"pluginId\":\"guard.old\",\"originalPath\":"
                + mt.safety.scanner.core.Json.quote(recovery.getAbsolutePath()) + ",\"quarantinedAt\":\"old\"}");
        Fixtures.write(new File(held, "keep.bin"), "held data");
        Map<String, String> beforeSource = DelegatedActionPolicyRegression.snapshot(source);
        Map<String, String> beforeStore = DelegatedActionPolicyRegression.snapshot(store);
        Quarantine quarantine = new Quarantine(store);
        final int[] calls = {0};
        Quarantine.MoveGuard permissive = new Quarantine.MoveGuard() {
            @Override
            public boolean allow(File directory) { calls[0]++; return true; }
            @Override
            public boolean allowCopyTarget(File from, File to) { calls[0]++; return true; }
        };
        for (int i = 0; i < 8; i++) {
            Quarantine.Result refused;
            if (i == 0) { refused = quarantine.quarantine(source, "mt.safety.scanner"); }
            else if (i == 1) { refused = quarantine.quarantine(source, "mt.safety.scanner", null); }
            else if (i == 2) { refused = quarantine.quarantine(source, "mt.safety.scanner", permissive); }
            else if (i == 3) { refused = quarantine.quarantine(null, null, permissive); }
            else if (i == 4) { refused = quarantine.restore("guard.old"); }
            else if (i == 5) { refused = quarantine.restore(held.getName()); }
            else if (i == 6) { refused = quarantine.purge("guard.old"); }
            else { refused = quarantine.purge(null); }
            c.that("quarantine public entry " + i + " refuses with explicit delegated outcome",
                    !refused.ok && refused.location == null && DelegatedActionPolicyRegression.delegated(refused.message),
                    refused.message);
            DelegatedActionPolicyRegression.survives(c, "quarantine entry " + i, source, store, recovery,
                    beforeSource, beforeStore);
        }
        c.that("delegation does not invoke caller-controlled guards", calls[0] == 0, "calls=" + calls[0]);
        String property = "mtsafety.forceCopyFallback";
        String previous = System.getProperty(property);
        try {
            for (String value : new String[] {"true", "false"}) {
                System.setProperty(property, value);
                Quarantine.Result refused = quarantine.quarantine(source, "mt.safety.scanner", permissive);
                c.that("legacy copy fallback setting " + value + " cannot enable mutation",
                        !refused.ok && DelegatedActionPolicyRegression.delegated(refused.message), refused.message);
                DelegatedActionPolicyRegression.survives(c, "copy property " + value, source, store, recovery,
                        beforeSource, beforeStore);
            }
        } finally {
            if (previous == null) { System.clearProperty(property); }
            else { System.setProperty(property, previous); }
        }
        c.that("historical metadata remains readable", quarantine.list().size() == 1
                && "guard.old".equals(quarantine.list().get(0).pluginId)
                && recovery.getAbsolutePath().equals(quarantine.list().get(0).originalPath)
                && "old".equals(quarantine.list().get(0).quarantinedAt), "historical fields");
        File fresh = new File(root, "not-created");
        Quarantine absent = new Quarantine(fresh);
        c.that("reading or refusing actions never creates a quarantine store", absent.list().isEmpty()
                && !absent.quarantine(source, "mt.safety.scanner", permissive).ok
                && !absent.restore("any").ok && !absent.purge("any").ok && !fresh.exists(), "absent store");
        File linkedStore = new File(root, "linked-store");
        Files.createSymbolicLink(linkedStore.toPath(), store.toPath());
        Map<String, String> linkBefore = DelegatedActionPolicyRegression.snapshot(linkedStore);
        Quarantine linked = new Quarantine(linkedStore);
        c.that("linked historical store refuses listing", linked.list().isEmpty()
                && linked.listingProblem() != null, String.valueOf(linked.listingProblem()));
        c.that("linked store actions delegate without touching link or destination", !linked.restore("guard.old").ok
                && !linked.purge("guard.old").ok
                && linkBefore.equals(DelegatedActionPolicyRegression.snapshot(linkedStore))
                && beforeStore.equals(DelegatedActionPolicyRegression.snapshot(store)), "link and store survive");
        File wide = new File(root, "wide");
        if (!wide.mkdir()) { throw new IllegalStateException("could not create wide fixture"); }
        for (int i = 0; i < 8001; i++) {
            if (!new File(wide, "entry-" + i).mkdir()) { throw new IllegalStateException("wide fixture entry"); }
        }
        Quarantine bounded = new Quarantine(wide);
        c.that("historical listing retains its entry bound", bounded.list().isEmpty()
                && bounded.listingProblem() != null && new File(wide, "entry-0").isDirectory()
                && new File(wide, "entry-8000").isDirectory(), String.valueOf(bounded.listingProblem()));
    }
}
