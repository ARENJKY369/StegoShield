package analysis;

import java.awt.image.BufferedImage;
import java.util.Objects;

/**
 * Implements image-oriented statistical indicators used by the scanner. The
 * results are heuristics, especially on processed, noisy, or very small images.
 */
public final class ImageStatistics {
    private ImageStatistics() {
        // Utility class.
    }

    /**
     * Runs the adjacent pair-of-values chi-square test across combined RGB
     * sample values. LSB replacement tends to equalize each pair such as 42/43,
     * giving an unusually low statistic and negative z-score.
     *
     * @param image image to analyze
     * @return chi-square statistic, degrees of freedom, and z-score
     */
    public static ChiSquareResult pairOfValuesChiSquare(BufferedImage image) {
        Objects.requireNonNull(image, "image must not be null");
        long[] histogram = new long[256];
        int width = image.getWidth();
        int height = image.getHeight();
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int rgb = image.getRGB(x, y);
                histogram[(rgb >>> 16) & 0xFF]++;
                histogram[(rgb >>> 8) & 0xFF]++;
                histogram[rgb & 0xFF]++;
            }
        }
        double statistic = 0.0d;
        int degreesOfFreedom = 0;
        for (int value = 0; value < histogram.length; value += 2) {
            long first = histogram[value];
            long second = histogram[value + 1];
            long pairTotal = first + second;
            if (pairTotal == 0) {
                continue;
            }
            double expected = pairTotal / 2.0d;
            double firstDifference = first - expected;
            double secondDifference = second - expected;
            statistic += firstDifference * firstDifference / expected;
            statistic += secondDifference * secondDifference / expected;
            degreesOfFreedom++;
        }
        double zScore = degreesOfFreedom == 0 ? 0.0d
                : (statistic - degreesOfFreedom) / Math.sqrt(2.0d * degreesOfFreedom);
        return new ChiSquareResult(statistic, degreesOfFreedom, zScore);
    }

    /**
     * Calculates global and block-wise RGB LSB statistics for an image.
     *
     * @param image image to analyze
     * @param blockSize positive square block side length
     * @return LSB statistics
     */
    public static LsbStatistics lsbStatistics(BufferedImage image, int blockSize) {
        Objects.requireNonNull(image, "image must not be null");
        if (blockSize <= 0) {
            throw new IllegalArgumentException("block size must be positive");
        }
        int width = image.getWidth();
        int height = image.getHeight();
        long totalBits = 0L;
        long oneBits = 0L;
        int blockCount = 0;
        int balancedBlocks = 0;
        double fractionSum = 0.0d;
        double fractionSquareSum = 0.0d;
        for (int startY = 0; startY < height; startY += blockSize) {
            int endY = Math.min(height, startY + blockSize);
            for (int startX = 0; startX < width; startX += blockSize) {
                int endX = Math.min(width, startX + blockSize);
                long blockBits = 0L;
                long blockOnes = 0L;
                for (int y = startY; y < endY; y++) {
                    for (int x = startX; x < endX; x++) {
                        int rgb = image.getRGB(x, y);
                        blockOnes += (rgb >>> 16) & 1;
                        blockOnes += (rgb >>> 8) & 1;
                        blockOnes += rgb & 1;
                        blockBits += 3L;
                    }
                }
                totalBits += blockBits;
                oneBits += blockOnes;
                double fraction = (double) blockOnes / blockBits;
                fractionSum += fraction;
                fractionSquareSum += fraction * fraction;
                if (Math.abs(balanceZ(blockOnes, blockBits)) <= AnalysisConstants.LSB_BALANCE_Z_LIMIT) {
                    balancedBlocks++;
                }
                blockCount++;
            }
        }
        double mean = blockCount == 0 ? 0.0d : fractionSum / blockCount;
        double variance = blockCount == 0 ? 0.0d
                : Math.max(0.0d, fractionSquareSum / blockCount - mean * mean);
        return new LsbStatistics(totalBits, oneBits, balanceZ(oneBits, totalBits), blockCount,
                balancedBlocks, mean, variance);
    }

    /**
     * Computes z-score for a count of one bits against an expected probability of one-half.
     *
     * @param oneBits count of ones
     * @param totalBits number of bits
     * @return finite z-score, or zero when no bits exist
     */
    public static double balanceZ(long oneBits, long totalBits) {
        if (totalBits <= 0L) {
            return 0.0d;
        }
        double expected = totalBits / 2.0d;
        return (oneBits - expected) / Math.sqrt(totalBits / 4.0d);
    }
}
