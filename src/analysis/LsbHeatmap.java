package analysis;

import java.awt.image.BufferedImage;
import java.util.Arrays;
import java.util.Objects;

/**
 * Builds block-based LSB-balance heatmaps for image inspection. High intensity
 * means a block's RGB LSB fraction is close to one-half; it is a visualization
 * aid, not proof that a block contains hidden data.
 */
public final class LsbHeatmap {
    private LsbHeatmap() {
        // Utility class.
    }

    /**
     * Calculates a heatmap using square pixel blocks.
     *
     * @param image image to analyze
     * @param blockSize positive block side length in pixels
     * @return immutable-style heatmap data
     */
    public static Heatmap fromImage(BufferedImage image, int blockSize) {
        Objects.requireNonNull(image, "image must not be null");
        if (blockSize <= 0) {
            throw new IllegalArgumentException("heatmap block size must be positive");
        }
        int width = image.getWidth();
        int height = image.getHeight();
        if (width <= 0 || height <= 0) {
            throw new IllegalArgumentException("heatmap image dimensions must be positive");
        }
        int columns = (width + blockSize - 1) / blockSize;
        int rows = (height + blockSize - 1) / blockSize;
        double[] intensities = new double[Math.multiplyExact(columns, rows)];
        for (int row = 0; row < rows; row++) {
            int startY = row * blockSize;
            int endY = Math.min(height, startY + blockSize);
            for (int column = 0; column < columns; column++) {
                int startX = column * blockSize;
                int endX = Math.min(width, startX + blockSize);
                long bits = 0L;
                long ones = 0L;
                for (int y = startY; y < endY; y++) {
                    for (int x = startX; x < endX; x++) {
                        int rgb = image.getRGB(x, y);
                        ones += (rgb >>> 16) & 1;
                        ones += (rgb >>> 8) & 1;
                        ones += rgb & 1;
                        bits += 3L;
                    }
                }
                double fraction = (double) ones / bits;
                double distanceFromBalanced = Math.abs(fraction - 0.5d) * 2.0d;
                intensities[row * columns + column] = 1.0d - Math.min(1.0d, distanceFromBalanced);
            }
        }
        return new Heatmap(width, height, blockSize, columns, rows, intensities);
    }

    /**
     * Block-grid data consumed by the AWT heatmap canvas.
     *
     * @param imageWidth source image width
     * @param imageHeight source image height
     * @param blockSize source block size
     * @param columns number of grid columns
     * @param rows number of grid rows
     * @param intensities values from zero (imbalanced) through one (balanced)
     */
    public record Heatmap(int imageWidth, int imageHeight, int blockSize, int columns, int rows,
            double[] intensities) {
        /**
         * Validates shape and defensively copies values.
         */
        public Heatmap {
            if (imageWidth <= 0 || imageHeight <= 0 || blockSize <= 0 || columns <= 0 || rows <= 0
                    || intensities == null || intensities.length != Math.multiplyExact(columns, rows)) {
                throw new IllegalArgumentException("invalid heatmap dimensions");
            }
            intensities = Arrays.copyOf(intensities, intensities.length);
            for (double intensity : intensities) {
                if (!Double.isFinite(intensity) || intensity < 0.0d || intensity > 1.0d) {
                    throw new IllegalArgumentException("heatmap intensity must be between zero and one");
                }
            }
        }

        /**
         * Returns a defensive copy of grid intensity values.
         *
         * @return intensity copy in row-major order
         */
        @Override
        public double[] intensities() {
            return Arrays.copyOf(intensities, intensities.length);
        }

        /**
         * Returns one block's intensity.
         *
         * @param column zero-based column
         * @param row zero-based row
         * @return intensity from zero through one
         */
        public double intensityAt(int column, int row) {
            if (column < 0 || column >= columns || row < 0 || row >= rows) {
                throw new IndexOutOfBoundsException("heatmap block coordinate is outside the grid");
            }
            return intensities[row * columns + column];
        }
    }
}
