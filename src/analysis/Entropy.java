package analysis;

import java.util.Objects;

/**
 * Computes Shannon entropy in bits per byte for byte arrays. High entropy can
 * indicate encrypted or compressed data, but is not proof of maliciousness or
 * steganography.
 */
public final class Entropy {
    private Entropy() {
        // Utility class.
    }

    /**
     * Calculates Shannon entropy for a complete byte array.
     *
     * @param bytes bytes to analyze
     * @return entropy from zero through eight bits per byte
     */
    public static double shannonBitsPerByte(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes must not be null");
        if (bytes.length == 0) {
            return 0.0d;
        }
        long[] counts = new long[256];
        for (byte value : bytes) {
            counts[Byte.toUnsignedInt(value)]++;
        }
        double entropy = 0.0d;
        for (long count : counts) {
            if (count == 0L) {
                continue;
            }
            double probability = (double) count / bytes.length;
            entropy -= probability * (Math.log(probability) / Math.log(2.0d));
        }
        return entropy;
    }
}
