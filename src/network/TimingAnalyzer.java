package network;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Builds an inter-arrival histogram and flags traffic that is both strongly
 * bimodal and unusually regular. It uses simple one-dimensional two-means
 * clustering so the rationale remains inspectable without external libraries.
 */
public final class TimingAnalyzer {
    /** Minimum intervals before timing classification is attempted. */
    public static final int MIN_INTERVALS = 16;
    /** Histogram bucket width in milliseconds. */
    public static final double HISTOGRAM_BIN_MILLIS = 25.0d;
    /** Minimum separation between two cluster centers. */
    public static final double MIN_CLUSTER_SEPARATION_MILLIS = 50.0d;
    /** Minimum fraction of intervals each cluster must contain. */
    public static final double MIN_CLUSTER_FRACTION = 0.20d;
    /** Maximum within-cluster coefficient of variation for regular timing. */
    public static final double MAX_CLUSTER_COEFFICIENT_OF_VARIATION = 0.35d;

    private TimingAnalyzer() {
        // Utility class.
    }

    /**
     * Analyzes inter-arrival intervals measured in nanoseconds.
     *
     * @param intervalsNanos non-negative timing samples
     * @return explainable histogram and classification
     */
    public static TimingAnalysis analyze(List<Long> intervalsNanos) {
        Objects.requireNonNull(intervalsNanos, "interval list must not be null");
        double[] values = new double[intervalsNanos.size()];
        for (int index = 0; index < intervalsNanos.size(); index++) {
            Long nanos = Objects.requireNonNull(intervalsNanos.get(index), "timing interval must not be null");
            if (nanos < 0L) {
                throw new IllegalArgumentException("timing intervals must not be negative");
            }
            values[index] = nanos / 1_000_000.0d;
        }
        return analyzeMillis(values);
    }

    /**
     * Analyzes inter-arrival intervals measured in milliseconds. This overload
     * supports deterministic tests without manufacturing socket timing.
     *
     * @param intervalsMillis non-negative timing samples
     * @return explainable histogram and classification
     */
    public static TimingAnalysis analyzeMillis(double[] intervalsMillis) {
        Objects.requireNonNull(intervalsMillis, "interval array must not be null");
        double[] values = Arrays.copyOf(intervalsMillis, intervalsMillis.length);
        for (double value : values) {
            if (!Double.isFinite(value) || value < 0.0d) {
                throw new IllegalArgumentException("timing intervals must be finite and non-negative");
            }
        }
        List<TimingAnalysis.HistogramBin> histogram = histogram(values);
        if (values.length == 0) {
            return new TimingAnalysis(0, 0.0d, 0.0d, false, false, 0.0d, 0.0d, histogram,
                    List.of("No inter-arrival intervals were available."));
        }
        double mean = mean(values);
        double standardDeviation = standardDeviation(values, mean);
        if (values.length < MIN_INTERVALS) {
            return new TimingAnalysis(values.length, mean, standardDeviation, false, false, 0.0d, 0.0d,
                    histogram, List.of("Only " + values.length + " interval(s) were observed; at least "
                            + MIN_INTERVALS + " are required for bimodality classification."));
        }
        ClusterResult clusters = cluster(values);
        double lowerFraction = (double) clusters.lowerCount / values.length;
        double upperFraction = (double) clusters.upperCount / values.length;
        double separation = clusters.upperMean - clusters.lowerMean;
        boolean bimodal = separation >= MIN_CLUSTER_SEPARATION_MILLIS
                && lowerFraction >= MIN_CLUSTER_FRACTION && upperFraction >= MIN_CLUSTER_FRACTION;
        double lowerCoefficient = coefficientOfVariation(clusters.lowerDeviation, clusters.lowerMean);
        double upperCoefficient = coefficientOfVariation(clusters.upperDeviation, clusters.upperMean);
        boolean regular = bimodal && lowerCoefficient <= MAX_CLUSTER_COEFFICIENT_OF_VARIATION
                && upperCoefficient <= MAX_CLUSTER_COEFFICIENT_OF_VARIATION;
        List<String> reasons = new ArrayList<>();
        reasons.add(String.format(Locale.ROOT,
                "Two-means centers: %.2f ms (%d interval(s)) and %.2f ms (%d interval(s)); separation %.2f ms.",
                clusters.lowerMean, clusters.lowerCount, clusters.upperMean, clusters.upperCount, separation));
        if (bimodal) {
            reasons.add("Intervals are strongly bimodal under configured separation and cluster-size thresholds.");
        } else {
            reasons.add("Intervals do not meet configured strongly bimodal thresholds.");
        }
        if (regular) {
            reasons.add(String.format(Locale.ROOT,
                    "Within-cluster coefficients of variation are %.3f and %.3f, indicating highly regular timing.",
                    lowerCoefficient, upperCoefficient));
        } else {
            reasons.add(String.format(Locale.ROOT,
                    "Within-cluster coefficients of variation are %.3f and %.3f; regularity threshold was not met.",
                    lowerCoefficient, upperCoefficient));
        }
        return new TimingAnalysis(values.length, mean, standardDeviation, bimodal, regular,
                clusters.lowerMean, clusters.upperMean, histogram, reasons);
    }

    private static List<TimingAnalysis.HistogramBin> histogram(double[] values) {
        if (values.length == 0) {
            return List.of();
        }
        double maximum = 0.0d;
        for (double value : values) {
            maximum = Math.max(maximum, value);
        }
        int binCount = Math.max(1, Math.min(200, (int) Math.ceil(maximum / HISTOGRAM_BIN_MILLIS) + 1));
        int[] counts = new int[binCount];
        for (double value : values) {
            int bin = Math.min(binCount - 1, (int) (value / HISTOGRAM_BIN_MILLIS));
            counts[bin]++;
        }
        List<TimingAnalysis.HistogramBin> bins = new ArrayList<>(binCount);
        for (int index = 0; index < binCount; index++) {
            double lower = index * HISTOGRAM_BIN_MILLIS;
            double upper = index == binCount - 1
                    ? Math.max(lower + HISTOGRAM_BIN_MILLIS, maximum + 0.001d)
                    : lower + HISTOGRAM_BIN_MILLIS;
            bins.add(new TimingAnalysis.HistogramBin(lower, upper, counts[index]));
        }
        return List.copyOf(bins);
    }

    private static ClusterResult cluster(double[] values) {
        double minimum = values[0];
        double maximum = values[0];
        for (double value : values) {
            minimum = Math.min(minimum, value);
            maximum = Math.max(maximum, value);
        }
        double lowerMean = minimum;
        double upperMean = maximum;
        int lowerCount = 0;
        int upperCount = 0;
        for (int iteration = 0; iteration < 32; iteration++) {
            double lowerSum = 0.0d;
            double upperSum = 0.0d;
            lowerCount = 0;
            upperCount = 0;
            for (double value : values) {
                if (Math.abs(value - lowerMean) <= Math.abs(value - upperMean)) {
                    lowerSum += value;
                    lowerCount++;
                } else {
                    upperSum += value;
                    upperCount++;
                }
            }
            if (lowerCount == 0 || upperCount == 0) {
                break;
            }
            double newLowerMean = lowerSum / lowerCount;
            double newUpperMean = upperSum / upperCount;
            if (Math.abs(newLowerMean - lowerMean) < 0.0001d
                    && Math.abs(newUpperMean - upperMean) < 0.0001d) {
                lowerMean = newLowerMean;
                upperMean = newUpperMean;
                break;
            }
            lowerMean = newLowerMean;
            upperMean = newUpperMean;
        }
        if (lowerMean > upperMean) {
            double replacement = lowerMean;
            lowerMean = upperMean;
            upperMean = replacement;
        }
        double lowerSumSquares = 0.0d;
        double upperSumSquares = 0.0d;
        lowerCount = 0;
        upperCount = 0;
        for (double value : values) {
            if (Math.abs(value - lowerMean) <= Math.abs(value - upperMean)) {
                lowerSumSquares += square(value - lowerMean);
                lowerCount++;
            } else {
                upperSumSquares += square(value - upperMean);
                upperCount++;
            }
        }
        double lowerDeviation = lowerCount == 0 ? Double.POSITIVE_INFINITY
                : Math.sqrt(lowerSumSquares / lowerCount);
        double upperDeviation = upperCount == 0 ? Double.POSITIVE_INFINITY
                : Math.sqrt(upperSumSquares / upperCount);
        return new ClusterResult(lowerMean, upperMean, lowerCount, upperCount, lowerDeviation, upperDeviation);
    }

    private static double mean(double[] values) {
        double sum = 0.0d;
        for (double value : values) {
            sum += value;
        }
        return sum / values.length;
    }

    private static double standardDeviation(double[] values, double mean) {
        double sumSquares = 0.0d;
        for (double value : values) {
            sumSquares += square(value - mean);
        }
        return Math.sqrt(sumSquares / values.length);
    }

    private static double coefficientOfVariation(double standardDeviation, double mean) {
        return mean <= 0.0d ? Double.POSITIVE_INFINITY : standardDeviation / mean;
    }

    private static double square(double value) {
        return value * value;
    }

    private record ClusterResult(double lowerMean, double upperMean, int lowerCount, int upperCount,
            double lowerDeviation, double upperDeviation) {
    }
}
