package sanitize;

import analysis.ScanReport;
import java.io.File;
import java.util.Objects;

/**
 * Describes a non-destructive cleaning operation and its before/after scanner
 * reports. A reduced score is useful feedback, not proof that every possible
 * hidden channel has been removed.
 */
public final class SanitizationResult {
    private final File source;
    private final File output;
    private final String strategy;
    private final ScanReport before;
    private final ScanReport after;

    /**
     * Creates a cleaning result.
     *
     * @param source original untouched file
     * @param output newly written sanitized file
     * @param strategy user-facing cleaning strategy
     * @param before report on original
     * @param after report on sanitized copy
     */
    public SanitizationResult(File source, File output, String strategy, ScanReport before,
            ScanReport after) {
        this.source = Objects.requireNonNull(source, "source file must not be null");
        this.output = Objects.requireNonNull(output, "output file must not be null");
        this.strategy = Objects.requireNonNull(strategy, "cleaning strategy must not be null");
        this.before = Objects.requireNonNull(before, "before report must not be null");
        this.after = Objects.requireNonNull(after, "after report must not be null");
    }

    /** @return untouched original file */
    public File source() {
        return source;
    }

    /** @return newly written sanitized file */
    public File output() {
        return output;
    }

    /** @return applied cleaning strategy */
    public String strategy() {
        return strategy;
    }

    /** @return original-file scan report */
    public ScanReport before() {
        return before;
    }

    /** @return post-clean scan report */
    public ScanReport after() {
        return after;
    }

    /**
     * Returns before score minus after score. A negative result means the
     * heuristic score increased and should be reviewed rather than hidden.
     *
     * @return score change
     */
    public int scoreReduction() {
        return before.riskScore() - after.riskScore();
    }
}
