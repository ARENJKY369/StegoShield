package analysis;

import java.util.Objects;

/**
 * Result of one channel's pair-of-values chi-square prefix sweep, the classic
 * Westfeld-Pfitzmann style analysis for LSB replacement: the largest sample
 * prefix whose adjacent-value histogram pairs are statistically consistent
 * with equalization. A large equalized prefix is consistent with sequential
 * LSB replacement of random-looking data; it is heuristic evidence, not proof,
 * because dithered or noisy legitimate imagery can also equalize pairs.
 *
 * @param channelIndex zero-based channel index (0=red, 1=green, 2=blue)
 * @param channelName human-readable channel name
 * @param channelSamples total per-channel sample count analyzed
 * @param equalizedSamples largest prefix sample count whose pairs were equalized
 * @param equalizedFraction equalizedSamples divided by channelSamples
 * @param zScore chi-square z-score measured at the equalized prefix, or at the
 *        whole channel when no prefix qualified
 */
public record ChiSquareSweep(int channelIndex, String channelName, int channelSamples,
        int equalizedSamples, double equalizedFraction, double zScore) {
    /**
     * Validates sweep fields.
     */
    public ChiSquareSweep {
        if (channelIndex < 0 || channelIndex > 2) {
            throw new IllegalArgumentException("channel index must be 0, 1, or 2");
        }
        Objects.requireNonNull(channelName, "channel name must not be null");
        if (channelName.isBlank()) {
            throw new IllegalArgumentException("channel name must not be blank");
        }
        if (channelSamples <= 0 || equalizedSamples < 0 || equalizedSamples > channelSamples) {
            throw new IllegalArgumentException("invalid sweep sample counts");
        }
        if (!Double.isFinite(equalizedFraction) || equalizedFraction < 0.0d
                || equalizedFraction > 1.0d) {
            throw new IllegalArgumentException("equalized fraction must be between zero and one");
        }
        if (!Double.isFinite(zScore)) {
            throw new IllegalArgumentException("z-score must be finite");
        }
    }
}
