package core;

import java.util.Objects;

/**
 * Bit-level helpers using most-significant-bit-first ordering within each byte.
 * The methods validate indexes so malformed carrier data cannot cause silent
 * truncation or accidental array access outside a declared payload.
 */
public final class BitUtil {
    /** Number of bits in one byte. */
    public static final int BITS_PER_BYTE = Byte.SIZE;

    private BitUtil() {
        // Utility class.
    }

    /**
     * Gets one bit from a byte array using most-significant-bit-first ordering.
     *
     * @param data source bytes
     * @param bitIndex zero-based bit index
     * @return zero or one
     */
    public static int getBit(byte[] data, long bitIndex) {
        Objects.requireNonNull(data, "data must not be null");
        checkBitIndex(data.length, bitIndex);
        int byteIndex = Math.toIntExact(bitIndex / BITS_PER_BYTE);
        int bitOffset = (int) (bitIndex % BITS_PER_BYTE);
        return (data[byteIndex] >>> (BITS_PER_BYTE - 1 - bitOffset)) & 1;
    }

    /**
     * Sets one bit in a byte array using most-significant-bit-first ordering.
     *
     * @param data target bytes
     * @param bitIndex zero-based bit index
     * @param bit bit value, zero or one
     */
    public static void setBit(byte[] data, long bitIndex, int bit) {
        Objects.requireNonNull(data, "data must not be null");
        checkBitIndex(data.length, bitIndex);
        if (bit != 0 && bit != 1) {
            throw new IllegalArgumentException("bit must be 0 or 1");
        }
        int byteIndex = Math.toIntExact(bitIndex / BITS_PER_BYTE);
        int bitOffset = (int) (bitIndex % BITS_PER_BYTE);
        int mask = 1 << (BITS_PER_BYTE - 1 - bitOffset);
        int value = data[byteIndex] & 0xFF;
        data[byteIndex] = (byte) (bit == 1 ? value | mask : value & ~mask);
    }

    /**
     * Reads an unsigned 32-bit integer from four big-endian bytes.
     *
     * @param data source bytes
     * @param offset offset of the first byte
     * @return value in the range 0 through 4,294,967,295
     */
    public static long readUnsignedIntBigEndian(byte[] data, int offset) {
        Objects.requireNonNull(data, "data must not be null");
        checkRange(data.length, offset, Integer.BYTES);
        return ((long) (data[offset] & 0xFF) << 24)
                | ((long) (data[offset + 1] & 0xFF) << 16)
                | ((long) (data[offset + 2] & 0xFF) << 8)
                | (long) (data[offset + 3] & 0xFF);
    }

    /**
     * Writes a non-negative unsigned 32-bit value as four big-endian bytes.
     *
     * @param value value in the range 0 through 4,294,967,295
     * @return four encoded bytes
     */
    public static byte[] unsignedIntToBigEndian(long value) {
        if (value < 0L || value > 0xFFFF_FFFFL) {
            throw new IllegalArgumentException("value is outside the unsigned 32-bit range");
        }
        return new byte[] {
            (byte) (value >>> 24),
            (byte) (value >>> 16),
            (byte) (value >>> 8),
            (byte) value
        };
    }

    /**
     * Returns the number of whole bytes that can hold the supplied bit count.
     *
     * @param bitCount count of bits
     * @return floor(bitCount / 8)
     */
    public static long wholeBytesForBits(long bitCount) {
        if (bitCount < 0L) {
            throw new IllegalArgumentException("bitCount must not be negative");
        }
        return bitCount / BITS_PER_BYTE;
    }

    /**
     * Returns the exact number of bits required to represent the supplied byte count.
     *
     * @param byteCount count of bytes
     * @return byteCount multiplied by eight
     */
    public static long bitsForBytes(long byteCount) {
        if (byteCount < 0L || byteCount > Long.MAX_VALUE / BITS_PER_BYTE) {
            throw new IllegalArgumentException("byteCount is outside the supported range");
        }
        return byteCount * BITS_PER_BYTE;
    }

    /**
     * Converts an integer whose low {@code bitCount} bits are significant to a
     * most-significant-bit-first bit array.
     *
     * @param value value to encode
     * @param bitCount number of bits, from zero through 32
     * @return bits in display and embedding order
     */
    public static int[] intToBits(int value, int bitCount) {
        if (bitCount < 0 || bitCount > Integer.SIZE) {
            throw new IllegalArgumentException("bitCount must be between 0 and 32");
        }
        int[] result = new int[bitCount];
        for (int index = 0; index < bitCount; index++) {
            result[index] = (value >>> (bitCount - 1 - index)) & 1;
        }
        return result;
    }

    private static void checkBitIndex(int byteLength, long bitIndex) {
        if (bitIndex < 0L || bitIndex >= (long) byteLength * BITS_PER_BYTE) {
            throw new IndexOutOfBoundsException("bit index is outside the byte array");
        }
    }

    private static void checkRange(int length, int offset, int required) {
        if (offset < 0 || required < 0 || offset > length - required) {
            throw new IndexOutOfBoundsException("requested byte range is outside the array");
        }
    }
}
