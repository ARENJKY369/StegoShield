package eval;

import java.io.File;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalDouble;

/**
 * Immutable runtime measurement result from {@link EvaluationRunner}. It
 * exposes scenario totals, measured flag rates, warnings, and the saved table;
 * it never substitutes fabricated values for skipped or failed cases.
 */
public final class EvaluationResult {
    private final Map<EvaluationScenario, EvaluationMetrics> metrics;
    private final List<String> warnings;
    private final File outputDirectory;
    private final File reportFile;
    private final Instant completedAt;
    private final boolean scatteredPlacement;

    EvaluationResult(Map<EvaluationScenario, EvaluationMetrics> metrics, List<String> warnings,
            File outputDirectory, File reportFile, Instant completedAt, boolean scatteredPlacement) {
        Objects.requireNonNull(metrics, "metrics must not be null");
        EnumMap<EvaluationScenario, EvaluationMetrics> copy = new EnumMap<>(EvaluationScenario.class);
        copy.putAll(metrics);
        this.metrics = Map.copyOf(copy);
        this.warnings = List.copyOf(Objects.requireNonNull(warnings, "warnings must not be null"));
        this.outputDirectory = Objects.requireNonNull(outputDirectory, "output directory must not be null");
        this.reportFile = Objects.requireNonNull(reportFile, "report file must not be null");
        this.completedAt = Objects.requireNonNull(completedAt, "completion time must not be null");
        this.scatteredPlacement = scatteredPlacement;
    }

    /** @return immutable scenario metrics */
    public Map<EvaluationScenario, EvaluationMetrics> metrics() {
        return metrics;
    }

    /** @return generation or scan warnings that affected sample availability */
    public List<String> warnings() {
        return warnings;
    }

    /** @return directory containing generated specimens and table */
    public File outputDirectory() {
        return outputDirectory;
    }

    /** @return UTF-8 report table saved at runtime */
    public File reportFile() {
        return reportFile;
    }

    /** @return runtime completion timestamp */
    public Instant completedAt() {
        return completedAt;
    }

    /** @return whether LSB payloads were placed password-scattered */
    public boolean scatteredPlacement() {
        return scatteredPlacement;
    }

    /**
     * Returns measured detection percentage across all successful positive cases.
     *
     * @return optional detection rate when at least one positive case was scanned
     */
    public OptionalDouble overallDetectionPercent() {
        return combinedPercent(true);
    }

    /**
     * Returns measured false-positive percentage across clean baseline images.
     *
     * @return optional rate when at least one clean image was scanned
     */
    public OptionalDouble falsePositivePercent() {
        return combinedPercent(false);
    }

    /**
     * Renders a plain-text table of measured counts and percentages.
     *
     * @return UTF-8-safe textual report content
     */
    public String toTable() {
        StringBuilder table = new StringBuilder();
        table.append("StegoShield runtime evaluation\n");
        table.append("Completed: ").append(completedAt).append("\n");
        table.append("Output directory: ").append(outputDirectory.getAbsolutePath()).append("\n");
        table.append("Embedding placement: ")
                .append(scatteredPlacement ? "password-scattered (evaluation password never given to the scanner)"
                        : "sequential")
                .append("\n\n");
        table.append(String.format("%-34s %10s %10s %16s%n", "Scenario", "Samples", "Flagged", "Rate"));
        table.append("--------------------------------------------------------------------------\n");
        for (EvaluationScenario scenario : EvaluationScenario.values()) {
            EvaluationMetrics metric = metrics.get(scenario);
            if (metric == null) {
                continue;
            }
            table.append(String.format("%-34s %10d %10d %16s%n", scenario.displayName(scatteredPlacement),
                    metric.total(),
                    metric.flagged(), metric.formattedPercent()));
        }
        table.append("\nOverall detection rate: ").append(format(overallDetectionPercent())).append("\n");
        table.append("False-positive rate: ").append(format(falsePositivePercent())).append("\n");
        table.append("Flagged means risk score >= 25 (SUSPICIOUS or LIKELY CONTAINS HIDDEN DATA).\n");
        if (!warnings.isEmpty()) {
            table.append("\nWarnings / skipped cases:\n");
            for (String warning : warnings) {
                table.append("- ").append(warning).append("\n");
            }
        }
        return table.toString();
    }

    private OptionalDouble combinedPercent(boolean positives) {
        int total = 0;
        int flagged = 0;
        for (EvaluationScenario scenario : EvaluationScenario.values()) {
            if (scenario.positiveCase() != positives) {
                continue;
            }
            EvaluationMetrics metric = metrics.get(scenario);
            if (metric != null) {
                total += metric.total();
                flagged += metric.flagged();
            }
        }
        return total == 0 ? OptionalDouble.empty() : OptionalDouble.of(100.0d * flagged / total);
    }

    private static String format(OptionalDouble percentage) {
        return percentage.isPresent() ? String.format(java.util.Locale.ROOT, "%.2f%%", percentage.getAsDouble())
                : "N/A (no eligible samples)";
    }
}
