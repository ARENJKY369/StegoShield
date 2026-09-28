package network;

import java.util.List;
import java.util.Objects;

/**
 * Explainable timing-channel traffic analysis. Bimodality and regularity are
 * statistical observations only; they can also arise from benign batching,
 * scheduling, and synthetic workloads.
 */
public final class TimingAnalysis {
    private final int intervalCount;
    private final double meanMillis;
    private final double standardDeviationMillis;
    private final boolean stronglyBimodal;
    private final boolean highlyRegular;
    private final boolean suspicious;
    private final double lowerClusterMeanMillis;
    private final double upperClusterMeanMillis;
    private final List<HistogramBin> histogram;
    private final List<String> reasons;

    TimingAnalysis(int intervalCount, double meanMillis, double standardDeviationMillis,
            boolean stronglyBimodal, boolean highlyRegular, double lowerClusterMeanMillis,
            double upperClusterMeanMillis, List<HistogramBin> histogram, List<String> reasons) {
        if (intervalCount < 0 || !Double.isFinite(meanMillis) || !Double.isFinite(standardDeviationMillis)
                || !Double.isFinite(lowerClusterMeanMillis) || !Double.isFinite(upperClusterMeanMillis)) {
            throw new IllegalArgumentException("invalid timing analysis values");
        }
        this.intervalCount = intervalCount;
        this.meanMillis = meanMillis;
        this.standardDeviationMillis = standardDeviationMillis;
        this.stronglyBimodal = stronglyBimodal;
        this.highlyRegular = highlyRegular;
        suspicious = stronglyBimodal && highlyRegular;
        this.lowerClusterMeanMillis = lowerClusterMeanMillis;
        this.upperClusterMeanMillis = upperClusterMeanMillis;
        this.histogram = List.copyOf(Objects.requireNonNull(histogram, "histogram must not be null"));
        this.reasons = List.copyOf(Objects.requireNonNull(reasons, "reasons must not be null"));
    }

    /** @return observed inter-arrival count */
    public int intervalCount() {
        return intervalCount;
    }

    /** @return mean inter-arrival time in milliseconds */
    public double meanMillis() {
        return meanMillis;
    }

    /** @return population standard deviation in milliseconds */
    public double standardDeviationMillis() {
        return standardDeviationMillis;
    }

    /** @return whether two stable timing clusters were found */
    public boolean stronglyBimodal() {
        return stronglyBimodal;
    }

    /** @return whether timing within clusters is highly regular */
    public boolean highlyRegular() {
        return highlyRegular;
    }

    /** @return whether both timing-channel indicators are present */
    public boolean suspicious() {
        return suspicious;
    }

    /** @return lower k-means cluster center in milliseconds */
    public double lowerClusterMeanMillis() {
        return lowerClusterMeanMillis;
    }

    /** @return upper k-means cluster center in milliseconds */
    public double upperClusterMeanMillis() {
        return upperClusterMeanMillis;
    }

    /** @return immutable inter-arrival histogram */
    public List<HistogramBin> histogram() {
        return histogram;
    }

    /** @return immutable explanations of analysis observations */
    public List<String> reasons() {
        return reasons;
    }

    /**
     * One histogram bin with an inclusive lower bound and exclusive upper bound.
     *
     * @param lowerMillis lower bound
     * @param upperMillis upper bound
     * @param count interval count in range
     */
    public record HistogramBin(double lowerMillis, double upperMillis, int count) {
        /** Validates bin values. */
        public HistogramBin {
            if (!Double.isFinite(lowerMillis) || !Double.isFinite(upperMillis)
                    || lowerMillis < 0.0d || upperMillis <= lowerMillis || count < 0) {
                throw new IllegalArgumentException("invalid timing histogram bin");
            }
        }
    }
}
