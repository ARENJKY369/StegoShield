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
        return pairOfValues(histogram);
    }

    /**
     * Runs the classic Westfeld-Pfitzmann style prefix sweep on each color
     * channel separately. Channel samples are consumed in raster order while
     * a running value histogram is maintained; at every checkpoint the
     * pair-of-values chi-square z-score of the current prefix is computed, and
     * the largest prefix whose z-score is at or below the equalization
     * threshold is recorded. Sequential LSB replacement of random-looking data
     * equalizes adjacent pairs over exactly the embedded prefix, so a large
     * equalized prefix indicates the technique and estimates its coverage.
     *
     * @param image image to analyze
     * @param stepSamples positive checkpoint spacing in per-channel samples
     * @param equalizedZ prefix z-scores at or below this count as equalized
     * @return result for the channel with the largest equalized prefix, or the
     *         most equalized channel when no prefix qualified
     */
    public static ChiSquareSweep pairOfValuesPrefixSweep(BufferedImage image, int stepSamples,
            double equalizedZ) {
        Objects.requireNonNull(image, "image must not be null");
        if (stepSamples <= 0) {
            throw new IllegalArgumentException("step samples must be positive");
        }
        if (!Double.isFinite(equalizedZ)) {
            throw new IllegalArgumentException("equalized z must be finite");
        }
        String[] names = {"red", "green", "blue"};
        ChiSquareSweep best = null;
        for (int channel = 0; channel < names.length; channel++) {
            int shift = 16 - 8 * channel;
            long[] histogram = new long[256];
            int channelSamples = image.getWidth() * image.getHeight();
            int samples = 0;
            int equalizedSamples = 0;
            double zAtEqualized = Double.NaN;
            for (int y = 0; y < image.getHeight(); y++) {
                for (int x = 0; x < image.getWidth(); x++) {
                    histogram[(image.getRGB(x, y) >>> shift) & 0xFF]++;
                    samples++;
                    if (samples % stepSamples == 0 || samples == channelSamples) {
                        double zScore = pairOfValues(histogram).zScore();
                        if (zScore <= equalizedZ) {
                            equalizedSamples = samples;
                            zAtEqualized = zScore;
                        }
                    }
                }
            }
            double fullZ = pairOfValues(histogram).zScore();
            double fraction = (double) equalizedSamples / channelSamples;
            ChiSquareSweep candidate = new ChiSquareSweep(channel, names[channel], channelSamples,
                    equalizedSamples, fraction, Double.isNaN(zAtEqualized) ? fullZ : zAtEqualized);
            if (best == null || candidate.equalizedFraction() > best.equalizedFraction()
                    || (candidate.equalizedFraction() == best.equalizedFraction()
                            && candidate.zScore() < best.zScore())) {
                best = candidate;
            }
        }
        return best;
    }

    private static ChiSquareResult pairOfValues(long[] histogram) {
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
