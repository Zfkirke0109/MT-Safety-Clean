package mtsafety.test;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import mt.safety.scanner.core.Json;

/** Checks the CLI's public exit and discovery-report contracts in separate JVMs. */
public final class CliRegression {
    private CliRegression() {
    }

    public static void run(ActionsTest.Checker c, Fixtures fixtures) throws Exception {
        File clean = fixtures.archivePlugin("cli-clean.mtp",
                Fixtures.manifest("demo.cli", "CLI Control", "demo.A"),
                Fixtures.sources("src/demo/A.java", "package demo; public class A {}"));
        File files = new File(fixtures.root(), "cli-files");
        Fixtures.write(new File(files, "sample.txt"), "SPEC_HIT");
        File db = new File(fixtures.root(), "cli.ndb");
        Fixtures.write(db, "SpecHit:0:*:535045435f484954\n");
        Result combined = run(fixtures, false, "--files", files.getPath(), "--signatures", db.getPath(),
                clean.getPath());
        c.that("CLI keeps file signature hits when package scanning follows",
                combined.exit == 2 && combined.output.contains("SpecHit"), combined.toString());
        Result incomplete = run(fixtures, true, "--files", files.getPath(), "--signatures", db.getPath());
        c.that("CLI fails incomplete file scans with no matches", incomplete.exit == 1, incomplete.toString());

        File search = new File(fixtures.root(), "cli-search");
        File deep = new File(search, "1/2/3/4/5/6");
        if (!deep.mkdirs()) {
            throw new IllegalStateException("could not create depth fixture");
        }
        Files.copy(clean.toPath(), new File(search, "visible.mtp").toPath());
        Result discovery = run(fixtures, false, "--json", "--scan-dir", search.getPath());
        Map<String, Object> json = Json.parseObject(discovery.output);
        c.that("CLI exposes incomplete discovery without changing individual package coverage",
                discovery.exit == 1 && Boolean.FALSE.equals(json.get("discoveryComplete"))
                        && !Json.stringList(json, "discoveryProblems").isEmpty()
                        && discovery.output.contains("\"coverage\": \"COMPLETE\""), discovery.toString());

        java.util.LinkedHashMap<String, byte[]> members = new java.util.LinkedHashMap<String, byte[]>();
        members.put("manifest.json", Fixtures.bytes(Fixtures.manifest("demo.partial.cli", "Partial", "demo.A")));
        members.put("src/demo/A.java", Fixtures.bytes("package demo; public class A {}"));
        members.put("libs/broken.jar", new byte[] {'P', 'K', 3, 4});
        File partial = fixtures.rawArchive("cli-partial.mtp", members, false);
        Result partialResult = run(fixtures, false, "--json", partial.getPath());
        c.that("CLI fails a partial package even when its legacy verdict is CLEAN",
                partialResult.exit == 1 && partialResult.output.contains("\"coverage\": \"PARTIAL\""),
                partialResult.toString());
        Result cleanResult = run(fixtures, false, "--json", clean.getPath());
        c.that("CLI complete benign control still exits zero", cleanResult.exit == 0, cleanResult.toString());
        File missing = new File(fixtures.root(), "does-not-exist");
        Result missingFiles = run(fixtures, false, "--files", missing.getPath(), "--signatures", db.getPath());
        c.that("CLI reports an unavailable explicit file root", missingFiles.exit == 1,
                missingFiles.toString());
        Result missingDiscovery = run(fixtures, false, "--json", "--scan-dir", missing.getPath(), clean.getPath());
        Map<String, Object> missingJson = Json.parseObject(missingDiscovery.output);
        c.that("CLI reports unavailable explicit discovery roots alongside clean targets",
                missingDiscovery.exit == 1 && Boolean.FALSE.equals(missingJson.get("discoveryComplete")),
                missingDiscovery.toString());
        Result redaction = runMain(fixtures, false, "mtsafety.test.ReviewRegression", 5);
        c.that("credential-like inputs cannot stall bounded evidence rendering",
                redaction.exit == 0, redaction.toString());
    }

    private static Result run(Fixtures fixtures, boolean unsupported, String... args) throws Exception {
        return runMain(fixtures, unsupported, "mtsafety.cli.MtSafetyCli", 20, args);
    }

    private static Result runMain(Fixtures fixtures, boolean unsupported, String mainClass, int timeout,
            String... args) throws Exception {
        List<String> command = new ArrayList<String>();
        command.add(new File(System.getProperty("java.home"), "bin/java").getPath());
        if (unsupported) {
            command.add("-Dmtsafety.forceDirectoryStreamUnsupported=true");
        }
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add(mainClass);
        command.addAll(Arrays.asList(args));
        File out = File.createTempFile("cli-out-", ".txt", fixtures.root());
        File err = File.createTempFile("cli-err-", ".txt", fixtures.root());
        Process process = new ProcessBuilder(command).redirectOutput(out).redirectError(err).start();
        if (!process.waitFor(timeout, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            process.waitFor(5L, TimeUnit.SECONDS);
            return new Result(-1, "", "process timed out: " + mainClass);
        }
        if (out.length() > 1024 * 1024 || err.length() > 1024 * 1024) {
            throw new AssertionError("unbounded CLI fixture output");
        }
        return new Result(process.exitValue(), new String(Files.readAllBytes(out.toPath()), "UTF-8"),
                new String(Files.readAllBytes(err.toPath()), "UTF-8"));
    }

    private static final class Result {
        final int exit;
        final String output;
        final String error;

        Result(int exit, String output, String error) {
            this.exit = exit;
            this.output = output;
            this.error = error;
        }

        @Override
        public String toString() {
            return "exit=" + exit + " stdout=" + output + " stderr=" + error;
        }
    }
}
