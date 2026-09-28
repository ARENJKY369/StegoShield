package analysis;

/**
 * Result of the pair-of-values chi-square image test. Degrees of freedom equal
 * the number of non-empty adjacent-value pairs because each pair estimates one
 * expected count from its own observed total.
 *
 * @param statistic chi-square statistic
 * @param degreesOfFreedom active pair count
 * @param zScore normal approximation (statistic - df) / sqrt(2 * df)
 */
public record ChiSquareResult(double statistic, int degreesOfFreedom, double zScore) {
    /**
     * Validates result ranges.
     */
    public ChiSquareResult {
        if (!Double.isFinite(statistic) || statistic < 0.0d || degreesOfFreedom < 0
                || !Double.isFinite(zScore)) {
            throw new IllegalArgumentException("invalid chi-square result");
        }
    }
}
