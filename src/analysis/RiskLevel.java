package analysis;

/**
 * User-facing risk labels derived from the scanner's zero-to-one-hundred score.
 */
public enum RiskLevel {
    /** No implemented heuristic materially triggered. */
    CLEAN("CLEAN"),
    /** One or more indicators deserve review. */
    SUSPICIOUS("SUSPICIOUS"),
    /** Multiple or high-confidence indicators suggest hidden data. */
    LIKELY_CONTAINS_HIDDEN_DATA("LIKELY CONTAINS HIDDEN DATA");

    private final String displayName;

    RiskLevel(String displayName) {
        this.displayName = displayName;
    }

    /**
     * Maps a bounded risk score to its published label.
     *
     * @param score score from zero through one hundred
     * @return corresponding risk level
     */
    public static RiskLevel fromScore(int score) {
        if (score < 0 || score > 100) {
            throw new IllegalArgumentException("risk score must be between 0 and 100");
        }
        if (score <= AnalysisConstants.CLEAN_MAX_SCORE) {
            return CLEAN;
        }
        if (score <= AnalysisConstants.SUSPICIOUS_MAX_SCORE) {
            return SUSPICIOUS;
        }
        return LIKELY_CONTAINS_HIDDEN_DATA;
    }

    /**
     * Returns the exact label used in reports and the AWT user interface.
     *
     * @return display label
     */
    public String displayName() {
        return displayName;
    }
}
