package analysis;

/**
 * Summary of least-significant-bit balance and block-wise behavior. A balance
 * close to one-half is not proof of steganography; it is one weak, explainable
 * indicator considered alongside structural evidence.
 *
 * @param totalBits number of analyzed LSBs
 * @param oneBits number of LSBs equal to one
 * @param balanceZ z-score against a fair 0.5 Bernoulli distribution
 * @param blockCount number of analyzed blocks
 * @param balancedBlockCount blocks whose absolute balance z-score is within threshold
 * @param meanOneFraction average block one-bit fraction
 * @param oneFractionVariance variance of block one-bit fractions
 */
public record LsbStatistics(long totalBits, long oneBits, double balanceZ, int blockCount,
        int balancedBlockCount, double meanOneFraction, double oneFractionVariance) {
    /**
     * Validates numerical ranges.
     */
    public LsbStatistics {
        if (totalBits < 0L || oneBits < 0L || oneBits > totalBits || blockCount < 0
                || balancedBlockCount < 0 || balancedBlockCount > blockCount
                || !Double.isFinite(balanceZ) || !Double.isFinite(meanOneFraction)
                || !Double.isFinite(oneFractionVariance) || meanOneFraction < 0.0d
                || meanOneFraction > 1.0d || oneFractionVariance < 0.0d) {
            throw new IllegalArgumentException("invalid LSB statistics");
        }
    }

    /**
     * Returns global fraction of analyzed LSBs set to one.
     *
     * @return one-bit fraction, or zero for no samples
     */
    public double oneFraction() {
        return totalBits == 0L ? 0.0d : (double) oneBits / totalBits;
    }

    /**
     * Returns fraction of blocks classified as balanced.
     *
     * @return balanced-block fraction, or zero when no blocks exist
     */
    public double balancedBlockFraction() {
        return blockCount == 0 ? 0.0d : (double) balancedBlockCount / blockCount;
    }
}
