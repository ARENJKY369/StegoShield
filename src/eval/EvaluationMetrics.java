package eval;

import java.util.Locale;
import java.util.Objects;
import java.util.OptionalDouble;

/**
 * Measured scanner outcomes for one generated evaluation scenario. No rate is
 * invented when a scenario has no eligible generated samples.
 */
public final class EvaluationMetrics {
    private final EvaluationScenario scenario;
    private final int total;
    private final int flagged;

    EvaluationMetrics(EvaluationScenario scenario, int total, int flagged) {
        if (total < 0 || flagged < 0 || flagged > total) {
            throw new IllegalArgumentException("invalid evaluation counts");
        }
        this.scenario = Objects.requireNonNull(scenario, "scenario must not be null");
        this.total = total;
        this.flagged = flagged;
    }

    /** @return measured scenario */
    public EvaluationScenario scenario() {
        return scenario;
    }

    /** @return successfully scanned specimen count */
    public int total() {
        return total;
    }

    /** @return specimens with SUSPICIOUS or LIKELY risk labels */
    public int flagged() {
        return flagged;
    }

    /**
     * Returns the measured flagged percentage only when eligible samples exist.
     *
     * @return optional percentage from zero through one hundred
     */
    public OptionalDouble flaggedPercent() {
        return total == 0 ? OptionalDouble.empty() : OptionalDouble.of(100.0d * flagged / total);
    }

    /**
     * Formats the measured percentage or N/A for a zero-sample scenario.
     *
     * @return display-ready percentage
     */
    public String formattedPercent() {
        OptionalDouble percentage = flaggedPercent();
        return percentage.isPresent() ? String.format(Locale.ROOT, "%.2f%%", percentage.getAsDouble()) : "N/A";
    }
}
