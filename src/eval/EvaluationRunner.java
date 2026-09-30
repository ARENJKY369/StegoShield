package eval;

import analysis.AnalysisConstants;
import analysis.ScanReport;
import analysis.StegoScanner;
import eof.PngEofStego;
import image.LSBImageStego;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * Generates an on-disk evaluation corpus from a folder of clean PNG/BMP images,
 * runs the live scanner over each generated specimen, and saves measured
 * detection and false-positive rates. It never supplies fabricated outcomes.
 * LSB payloads are placed sequentially by default, or password-scattered with
 * a fixed public evaluation password when requested; the scanner never learns
 * the password or the placement mode.
 */
public final class EvaluationRunner {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int[] LSB_PERCENTAGES = {10, 25, 50, 100};
    /**
     * Fixed password used only to place payload bits in scattered mode. It is
     * public knowledge by design: a real scanner never receives the password,
     * so measuring detection must not either. Changing it changes scattered
     * bit positions and therefore measured rates.
     */
    private static final String SCATTERED_EVAL_PASSWORD = "stegoshield-eval-scattered-v1";

    private final StegoScanner scanner;
    private final boolean scattered;

    /**
     * Creates an evaluation runner with a default scanner and sequential placement.
     */
    public EvaluationRunner() {
        this(new StegoScanner(), false);
    }

    /**
     * Creates an evaluation runner with a supplied scanner and sequential placement.
     *
     * @param scanner scanner used for all measured outcomes
     */
    public EvaluationRunner(StegoScanner scanner) {
        this(scanner, false);
    }

    /**
     * Creates an evaluation runner with a supplied scanner and placement mode.
     *
     * @param scanner scanner used for all measured outcomes
     * @param scattered whether LSB payloads are placed password-scattered with
     *        the fixed evaluation password, which is never given to the scanner
     */
    public EvaluationRunner(StegoScanner scanner, boolean scattered) {
        this.scanner = Objects.requireNonNull(scanner, "scanner must not be null");
        this.scattered = scattered;
    }

    /**
     * Generates runtime test cases in a newly created subdirectory of
     * {@code outputRoot}, scans them, prints a table, and saves the same table
     * as UTF-8 {@code evaluation-results.txt}.
     *
     * @param cleanImageFolder folder containing clean PNG or BMP image carriers
     * @param outputRoot directory outside the clean-image folder for artifacts
     * @return measured results
     * @throws IOException if source discovery or output setup fails
     */
    public EvaluationResult run(File cleanImageFolder, File outputRoot) throws IOException {
        validateInputDirectories(cleanImageFolder, outputRoot);
        List<String> warnings = new ArrayList<>();
        List<File> cleanImages = discoverCleanImages(cleanImageFolder, warnings);
        if (cleanImages.isEmpty()) {
            throw new IOException("no readable PNG or BMP images were found in: " + cleanImageFolder);
        }
        File runDirectory = createRunDirectory(outputRoot);
        EnumMap<EvaluationScenario, Counter> counters = counters();
        int imageIndex = 1;
        for (File cleanImage : cleanImages) {
            String prefix = String.format("%04d_%s", imageIndex++, safeBaseName(cleanImage.getName()));
            scanAndCount(EvaluationScenario.CLEAN, cleanImage, counters, warnings);
            try {
                BufferedImage carrier = LSBImageStego.readCarrier(cleanImage);
                generateLsbCases(carrier, prefix, runDirectory, counters, warnings);
                File normalizedPng = new File(runDirectory, prefix + "_normalized.png");
                normalizedPng = LSBImageStego.writePng(carrier, normalizedPng);
                generateAppendedCase(normalizedPng, prefix, runDirectory, counters, warnings);
                generateWrongExtensionCase(normalizedPng, prefix, runDirectory, counters, warnings);
            } catch (IOException | IllegalArgumentException exception) {
                warnings.add("Could not generate all cases for " + cleanImage.getAbsolutePath() + ": "
                        + safeMessage(exception));
            }
        }
        Map<EvaluationScenario, EvaluationMetrics> metrics = freezeMetrics(counters);
        File reportFile = new File(runDirectory, "evaluation-results.txt");
        EvaluationResult result = new EvaluationResult(metrics, warnings, runDirectory, reportFile, Instant.now(),
                scattered);
        Files.writeString(reportFile.toPath(), result.toTable(), StandardCharsets.UTF_8);
        System.out.print(result.toTable());
        return result;
    }

    /**
     * Command-line entry point for offline runtime evaluation.
     *
     * @param arguments {@code <clean-image-folder> [output-root] [sequential|scattered]}
     */
    public static void main(String[] arguments) {
        if (arguments.length < 1 || arguments.length > 3) {
            System.err.println("Usage: java -cp out eval.EvaluationRunner <clean-image-folder>"
                    + " [output-root] [sequential|scattered]");
            return;
        }
        File input = new File(arguments[0]);
        File output = arguments.length >= 2 ? new File(arguments[1]) : new File("stegoshield-evaluation-output");
        boolean scattered = false;
        if (arguments.length == 3) {
            String mode = arguments[2].toLowerCase(java.util.Locale.ROOT);
            if (!mode.equals("sequential") && !mode.equals("scattered")) {
                System.err.println("Unknown placement mode: " + arguments[2] + " (expected sequential or scattered)");
                return;
            }
            scattered = mode.equals("scattered");
        }
        try {
            EvaluationResult result = new EvaluationRunner(new StegoScanner(), scattered).run(input, output);
            System.out.println("Saved measured evaluation report to: " + result.reportFile().getAbsolutePath());
        } catch (IOException | IllegalArgumentException exception) {
            System.err.println("Evaluation failed: " + safeMessage(exception));
        }
    }

    private void generateLsbCases(BufferedImage carrier, String prefix, File runDirectory,
            Map<EvaluationScenario, Counter> counters, List<String> warnings) {
        try (LSBImageStego stego = scattered
                ? LSBImageStego.passwordScattered(SCATTERED_EVAL_PASSWORD.toCharArray())
                : LSBImageStego.sequential()) {
            long capacity = stego.capacityBytes(carrier);
            for (int percentage : LSB_PERCENTAGES) {
                EvaluationScenario scenario = scenarioForPercentage(percentage);
                long bytes = capacity * percentage / 100L;
                if (bytes == 0L) {
                    warnings.add(prefix + ": skipped " + scenario.displayName()
                            + " because carrier capacity is below one byte at that rate.");
                    continue;
                }
                if (bytes > Integer.MAX_VALUE) {
                    warnings.add(prefix + ": skipped " + scenario.displayName()
                            + " because payload allocation would exceed Java array limits.");
                    continue;
                }
                byte[] payload = new byte[(int) bytes];
                RANDOM.nextBytes(payload);
                BufferedImage stegoImage = stego.embed(carrier, payload);
                File output = new File(runDirectory, prefix + "_lsb_" + percentage + ".png");
                File written = LSBImageStego.writePng(stegoImage, output);
                scanAndCount(scenario, written, counters, warnings);
            }
        } catch (IOException | IllegalArgumentException exception) {
            warnings.add(prefix + ": LSB test generation failed: " + safeMessage(exception));
        }
    }

    private void generateAppendedCase(File normalizedPng, String prefix, File runDirectory,
            Map<EvaluationScenario, Counter> counters, List<String> warnings) {
        byte[] appended = new byte[4_096];
        RANDOM.nextBytes(appended);
        appended[0] = 0x50;
        appended[1] = 0x4B;
        appended[2] = 0x03;
        appended[3] = 0x04;
        File output = new File(runDirectory, prefix + "_appended.png");
        try {
            File written = PngEofStego.appendAfterIend(normalizedPng, appended, output);
            scanAndCount(EvaluationScenario.PNG_APPENDED_DATA, written, counters, warnings);
        } catch (IOException | IllegalArgumentException exception) {
            warnings.add(prefix + ": appended-data generation failed: " + safeMessage(exception));
        }
    }

    private void generateWrongExtensionCase(File normalizedPng, String prefix, File runDirectory,
            Map<EvaluationScenario, Counter> counters, List<String> warnings) {
        File output = new File(runDirectory, prefix + "_wrong_extension.txt");
        try {
            Files.copy(normalizedPng.toPath(), output.toPath());
            scanAndCount(EvaluationScenario.WRONG_EXTENSION, output, counters, warnings);
        } catch (IOException exception) {
            warnings.add(prefix + ": wrong-extension generation failed: " + safeMessage(exception));
        }
    }

    private void scanAndCount(EvaluationScenario scenario, File specimen,
            Map<EvaluationScenario, Counter> counters, List<String> warnings) {
        try {
            ScanReport report = scanner.scan(specimen);
            counters.get(scenario).add(report.riskScore() > AnalysisConstants.CLEAN_MAX_SCORE);
        } catch (IOException | IllegalArgumentException exception) {
            warnings.add("Scanner could not evaluate " + specimen.getAbsolutePath() + " ("
                    + scenario.displayName() + "): " + safeMessage(exception));
        }
    }

    private static EnumMap<EvaluationScenario, Counter> counters() {
        EnumMap<EvaluationScenario, Counter> counters = new EnumMap<>(EvaluationScenario.class);
        for (EvaluationScenario scenario : EvaluationScenario.values()) {
            counters.put(scenario, new Counter());
        }
        return counters;
    }

    private static Map<EvaluationScenario, EvaluationMetrics> freezeMetrics(
            Map<EvaluationScenario, Counter> counters) {
        EnumMap<EvaluationScenario, EvaluationMetrics> metrics = new EnumMap<>(EvaluationScenario.class);
        for (EvaluationScenario scenario : EvaluationScenario.values()) {
            Counter counter = counters.get(scenario);
            metrics.put(scenario, new EvaluationMetrics(scenario, counter.total, counter.flagged));
        }
        return metrics;
    }

    private static EvaluationScenario scenarioForPercentage(int percentage) {
        return switch (percentage) {
            case 10 -> EvaluationScenario.LSB_10_PERCENT;
            case 25 -> EvaluationScenario.LSB_25_PERCENT;
            case 50 -> EvaluationScenario.LSB_50_PERCENT;
            case 100 -> EvaluationScenario.LSB_100_PERCENT;
            default -> throw new IllegalArgumentException("unsupported LSB evaluation percentage: " + percentage);
        };
    }

    private static List<File> discoverCleanImages(File folder, List<String> warnings) throws IOException {
        List<File> images = new ArrayList<>();
        try (Stream<Path> paths = Files.walk(folder.toPath())) {
            paths.filter(Files::isRegularFile).forEach(path -> {
                String name = path.getFileName().toString().toLowerCase(java.util.Locale.ROOT);
                if (!name.endsWith(".png") && !name.endsWith(".bmp")) {
                    return;
                }
                try {
                    LSBImageStego.readCarrier(path.toFile());
                    images.add(path.toFile());
                } catch (IOException | IllegalArgumentException exception) {
                    warnings.add("Skipped invalid PNG/BMP candidate " + path + ": " + safeMessage(exception));
                }
            });
        }
        images.sort(Comparator.comparing(File::getAbsolutePath));
        return List.copyOf(images);
    }

    private static File createRunDirectory(File outputRoot) throws IOException {
        Files.createDirectories(outputRoot.toPath());
        File directory = new File(outputRoot, "run-" + System.currentTimeMillis());
        int suffix = 1;
        while (directory.exists()) {
            directory = new File(outputRoot, "run-" + System.currentTimeMillis() + "-" + suffix++);
        }
        Files.createDirectory(directory.toPath());
        return directory;
    }

    private static void validateInputDirectories(File cleanImageFolder, File outputRoot) throws IOException {
        if (cleanImageFolder == null || outputRoot == null) {
            throw new IllegalArgumentException("clean-image folder and output root must not be null");
        }
        if (!cleanImageFolder.isDirectory()) {
            throw new IOException("clean-image input is not a directory: " + cleanImageFolder);
        }
        Path input = cleanImageFolder.getCanonicalFile().toPath();
        Path output = outputRoot.getCanonicalFile().toPath();
        if (output.startsWith(input)) {
            throw new IOException("evaluation output root must be outside the clean-image folder");
        }
    }

    private static String safeBaseName(String fileName) {
        int dot = fileName.lastIndexOf('.');
        String base = dot > 0 ? fileName.substring(0, dot) : fileName;
        return base.replaceAll("[^A-Za-z0-9_-]", "_");
    }

    private static String safeMessage(Exception exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank() ? exception.getClass().getSimpleName() : message;
    }

    private static final class Counter {
        private int total;
        private int flagged;

        private void add(boolean isFlagged) {
            total++;
            if (isFlagged) {
                flagged++;
            }
        }
    }
}
