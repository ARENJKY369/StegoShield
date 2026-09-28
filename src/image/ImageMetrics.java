package image;

import java.awt.image.BufferedImage;
import java.util.Objects;

/**
 * Calculates visual distortion metrics and creates RGB difference images.
 * Metrics compare only red, green, and blue samples; alpha is intentionally
 * ignored because StegoShield image carriers are normalized to TYPE_INT_RGB.
 */
public final class ImageMetrics {
    /** Maximum value of an eight-bit color sample. */
    public static final int MAX_SAMPLE_VALUE = 255;

    private ImageMetrics() {
        // Utility class.
    }

    /**
     * Calculates the mean squared error across all RGB samples in two images.
     *
     * @param original original image
     * @param modified image to compare against the original
     * @return RGB mean squared error
     * @throws IllegalArgumentException if either image is null or dimensions differ
     */
    public static double meanSquaredError(BufferedImage original, BufferedImage modified) {
        validateComparable(original, modified);
        double squaredErrorTotal = 0.0d;
        int width = original.getWidth();
        int height = original.getHeight();
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int originalRgb = original.getRGB(x, y);
                int modifiedRgb = modified.getRGB(x, y);
                squaredErrorTotal += squaredDifference(originalRgb >>> 16, modifiedRgb >>> 16);
                squaredErrorTotal += squaredDifference(originalRgb >>> 8, modifiedRgb >>> 8);
                squaredErrorTotal += squaredDifference(originalRgb, modifiedRgb);
            }
        }
        double sampleCount = (double) width * (double) height * 3.0d;
        return squaredErrorTotal / sampleCount;
    }

    /**
     * Calculates peak signal-to-noise ratio in decibels from RGB MSE.
     *
     * @param original original image
     * @param modified image to compare against the original
     * @return PSNR in dB, or positive infinity for identical RGB images
     * @throws IllegalArgumentException if either image is null or dimensions differ
     */
    public static double peakSignalToNoiseRatio(BufferedImage original, BufferedImage modified) {
        double mse = meanSquaredError(original, modified);
        if (mse == 0.0d) {
            return Double.POSITIVE_INFINITY;
        }
        double peakSquared = (double) MAX_SAMPLE_VALUE * (double) MAX_SAMPLE_VALUE;
        return 10.0d * Math.log10(peakSquared / mse);
    }

    /**
     * Produces an RGB image showing the absolute per-channel difference,
     * multiplied by a caller-selected amplification factor and clamped to 255.
     *
     * @param original original image
     * @param modified modified image
     * @param amplification strictly positive finite multiplier
     * @return a new TYPE_INT_RGB difference image
     * @throws IllegalArgumentException if images cannot be compared or the factor is invalid
     */
    public static BufferedImage amplifiedDifference(BufferedImage original, BufferedImage modified,
            double amplification) {
        validateComparable(original, modified);
        if (!Double.isFinite(amplification) || amplification <= 0.0d) {
            throw new IllegalArgumentException("amplification must be a positive finite value");
        }
        int width = original.getWidth();
        int height = original.getHeight();
        BufferedImage difference = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int originalRgb = original.getRGB(x, y);
                int modifiedRgb = modified.getRGB(x, y);
                int red = amplifiedChannel(originalRgb >>> 16, modifiedRgb >>> 16, amplification);
                int green = amplifiedChannel(originalRgb >>> 8, modifiedRgb >>> 8, amplification);
                int blue = amplifiedChannel(originalRgb, modifiedRgb, amplification);
                difference.setRGB(x, y, (red << 16) | (green << 8) | blue);
            }
        }
        return difference;
    }

    private static double squaredDifference(int firstRgb, int secondRgb) {
        int difference = (firstRgb & 0xFF) - (secondRgb & 0xFF);
        return (double) difference * (double) difference;
    }

    private static int amplifiedChannel(int firstRgb, int secondRgb, double amplification) {
        int difference = Math.abs((firstRgb & 0xFF) - (secondRgb & 0xFF));
        long amplified = Math.round(difference * amplification);
        return (int) Math.min(MAX_SAMPLE_VALUE, amplified);
    }

    private static void validateComparable(BufferedImage original, BufferedImage modified) {
        Objects.requireNonNull(original, "original image must not be null");
        Objects.requireNonNull(modified, "modified image must not be null");
        if (original.getWidth() <= 0 || original.getHeight() <= 0
                || modified.getWidth() <= 0 || modified.getHeight() <= 0) {
            throw new IllegalArgumentException("images must have positive dimensions");
        }
        if (original.getWidth() != modified.getWidth()
                || original.getHeight() != modified.getHeight()) {
            throw new IllegalArgumentException("images must have identical dimensions");
        }
    }
}
