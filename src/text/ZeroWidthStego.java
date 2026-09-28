package text;

import core.Stego;
import java.util.Objects;

/**
 * Hides a length-delimited byte stream after visible Unicode code points using
 * U+200B for zero and U+200C for one. A 32-bit unsigned big-endian byte-length
 * header precedes payload bits. The class also detects and removes the common
 * invisible characters relevant to text steganography.
 *
 * <p>Zero-width text steganography is fragile: editors, messaging platforms,
 * copy/paste operations, normalization, and fonts may remove or alter these
 * characters. It is appropriate only for text paths that preserve Unicode
 * exactly.</p>
 */
public final class ZeroWidthStego implements Stego<String> {
    /** U+200B represents a zero bit. */
    public static final int ZERO_BIT_CHARACTER = 0x200B;
    /** U+200C represents a one bit. */
    public static final int ONE_BIT_CHARACTER = 0x200C;
    /** U+200D is detected because it is a related zero-width character. */
    public static final int ZERO_WIDTH_JOINER = 0x200D;
    /** U+2060 is detected as an invisible Unicode character. */
    public static final int WORD_JOINER = 0x2060;
    /** U+FEFF is detected as an invisible Unicode character. */
    public static final int ZERO_WIDTH_NO_BREAK_SPACE = 0xFEFF;
    /** Bits reserved for the unsigned payload-length header. */
    public static final int LENGTH_HEADER_BITS = Integer.SIZE;

    /**
     * Returns capacity after accounting for the 32 bits used to store length.
     * One hidden bit can be added after every original Unicode code point.
     *
     * @param carrier visible text carrier
     * @return maximum payload capacity in bytes
     */
    @Override
    public long capacityBytes(String carrier) {
        validateCarrier(carrier);
        int codePoints = carrier.codePointCount(0, carrier.length());
        if (codePoints <= LENGTH_HEADER_BITS) {
            return 0L;
        }
        return (codePoints - (long) LENGTH_HEADER_BITS) / Byte.SIZE;
    }

    /**
     * Adds one invisible bit after each of the carrier's initial code points.
     * The carrier must not already contain the invisible characters monitored
     * by this toolkit, since existing bit characters would make extraction
     * ambiguous.
     *
     * @param carrier visible carrier text
     * @param payload non-empty bytes to hide
     * @return text visually equivalent to the carrier but containing hidden bits
     */
    @Override
    public String embed(String carrier, byte[] payload) {
        validateCarrier(carrier);
        Objects.requireNonNull(payload, "payload must not be null");
        if (payload.length == 0) {
            throw new IllegalArgumentException("payload must not be empty");
        }
        InvisibleCharacterReport existing = detectInvisibleCharacters(carrier);
        if (existing.totalCount() != 0) {
            throw new IllegalArgumentException("carrier already contains invisible Unicode characters; "
                    + "clean it before embedding to avoid ambiguous extraction");
        }
        long capacity = capacityBytes(carrier);
        if ((long) payload.length > capacity) {
            throw new IllegalArgumentException("payload is " + payload.length
                    + " bytes but text capacity is only " + capacity + " bytes");
        }
        long requiredBits = LENGTH_HEADER_BITS + (long) payload.length * Byte.SIZE;
        if (requiredBits > Integer.MAX_VALUE - (long) carrier.length()) {
            throw new IllegalArgumentException("carrier and hidden payload exceed Java String size limits");
        }
        StringBuilder result = new StringBuilder(carrier.length());
        long logicalBitIndex = 0L;
        for (int offset = 0; offset < carrier.length();) {
            int codePoint = carrier.codePointAt(offset);
            result.appendCodePoint(codePoint);
            if (logicalBitIndex < requiredBits) {
                result.appendCodePoint(bitAt(payload, logicalBitIndex));
                logicalBitIndex++;
            }
            offset += Character.charCount(codePoint);
        }
        return result.toString();
    }

    /**
     * Extracts bytes from U+200B and U+200C characters after validating their
     * 32-bit declared length against available hidden bits.
     *
     * @param carrier text to inspect
     * @return extracted payload bytes
     */
    @Override
    public byte[] extract(String carrier) {
        validateCarrier(carrier);
        long availableBits = countPayloadBitCharacters(carrier);
        if (availableBits < LENGTH_HEADER_BITS) {
            throw new IllegalArgumentException("text does not contain a complete zero-width length header");
        }
        long declaredLength = 0L;
        long bitPosition = 0L;
        for (int offset = 0; offset < carrier.length() && bitPosition < LENGTH_HEADER_BITS;) {
            int codePoint = carrier.codePointAt(offset);
            int bit = bitValue(codePoint);
            if (bit >= 0) {
                declaredLength = (declaredLength << 1) | bit;
                bitPosition++;
            }
            offset += Character.charCount(codePoint);
        }
        if (declaredLength == 0L) {
            throw new IllegalArgumentException("zero-width length header declares an empty payload");
        }
        if (declaredLength > (Long.MAX_VALUE - LENGTH_HEADER_BITS) / Byte.SIZE) {
            throw new IllegalArgumentException("zero-width length header exceeds supported size");
        }
        long requiredBits = LENGTH_HEADER_BITS + declaredLength * Byte.SIZE;
        if (requiredBits > availableBits) {
            throw new IllegalArgumentException("zero-width length header exceeds available hidden bits");
        }
        final int payloadLength;
        try {
            payloadLength = Math.toIntExact(declaredLength);
        } catch (ArithmeticException exception) {
            throw new IllegalArgumentException("declared text payload is too large to allocate", exception);
        }
        byte[] payload = new byte[payloadLength];
        long payloadBit = 0L;
        bitPosition = 0L;
        for (int offset = 0; offset < carrier.length() && payloadBit < (long) payloadLength * Byte.SIZE;) {
            int codePoint = carrier.codePointAt(offset);
            int bit = bitValue(codePoint);
            if (bit >= 0) {
                if (bitPosition >= LENGTH_HEADER_BITS) {
                    int byteIndex = (int) (payloadBit / Byte.SIZE);
                    payload[byteIndex] = (byte) ((payload[byteIndex] << 1) | bit);
                    payloadBit++;
                }
                bitPosition++;
            }
            offset += Character.charCount(codePoint);
        }
        return payload;
    }

    /**
     * Counts relevant invisible Unicode code points in text.
     *
     * @param text text to inspect
     * @return immutable count report
     */
    public static InvisibleCharacterReport detectInvisibleCharacters(String text) {
        Objects.requireNonNull(text, "text must not be null");
        int zero = 0;
        int one = 0;
        int joiner = 0;
        int wordJoiner = 0;
        int noBreakSpace = 0;
        for (int offset = 0; offset < text.length();) {
            int codePoint = text.codePointAt(offset);
            switch (codePoint) {
                case ZERO_BIT_CHARACTER -> zero++;
                case ONE_BIT_CHARACTER -> one++;
                case ZERO_WIDTH_JOINER -> joiner++;
                case WORD_JOINER -> wordJoiner++;
                case ZERO_WIDTH_NO_BREAK_SPACE -> noBreakSpace++;
                default -> {
                    // Visible or unrelated code point.
                }
            }
            offset += Character.charCount(codePoint);
        }
        return new InvisibleCharacterReport(zero, one, joiner, wordJoiner, noBreakSpace);
    }

    /**
     * Removes U+200B through U+200D, U+2060, and U+FEFF without changing other
     * Unicode code points. This supports non-destructive text sanitization when
     * callers write the returned text to a new file.
     *
     * @param text source text
     * @return text with monitored invisible characters removed
     */
    public static String stripInvisibleCharacters(String text) {
        Objects.requireNonNull(text, "text must not be null");
        StringBuilder cleaned = new StringBuilder(text.length());
        for (int offset = 0; offset < text.length();) {
            int codePoint = text.codePointAt(offset);
            if (!isMonitoredInvisible(codePoint)) {
                cleaned.appendCodePoint(codePoint);
            }
            offset += Character.charCount(codePoint);
        }
        return cleaned.toString();
    }

    /**
     * Returns whether a code point is one of the monitored invisible characters.
     *
     * @param codePoint Unicode code point
     * @return true for U+200B through U+200D, U+2060, or U+FEFF
     */
    public static boolean isMonitoredInvisible(int codePoint) {
        return (codePoint >= ZERO_BIT_CHARACTER && codePoint <= ZERO_WIDTH_JOINER)
                || codePoint == WORD_JOINER || codePoint == ZERO_WIDTH_NO_BREAK_SPACE;
    }

    private static int bitAt(byte[] payload, long logicalBitIndex) {
        if (logicalBitIndex < LENGTH_HEADER_BITS) {
            int shift = LENGTH_HEADER_BITS - 1 - (int) logicalBitIndex;
            return ((payload.length >>> shift) & 1) == 0 ? ZERO_BIT_CHARACTER : ONE_BIT_CHARACTER;
        }
        long payloadBitIndex = logicalBitIndex - LENGTH_HEADER_BITS;
        int byteIndex = Math.toIntExact(payloadBitIndex / Byte.SIZE);
        int bitInByte = (int) (payloadBitIndex % Byte.SIZE);
        int bit = (Byte.toUnsignedInt(payload[byteIndex]) >>> (Byte.SIZE - 1 - bitInByte)) & 1;
        return bit == 0 ? ZERO_BIT_CHARACTER : ONE_BIT_CHARACTER;
    }

    private static long countPayloadBitCharacters(String text) {
        long count = 0L;
        for (int offset = 0; offset < text.length();) {
            int codePoint = text.codePointAt(offset);
            if (bitValue(codePoint) >= 0) {
                count++;
            }
            offset += Character.charCount(codePoint);
        }
        return count;
    }

    private static int bitValue(int codePoint) {
        if (codePoint == ZERO_BIT_CHARACTER) {
            return 0;
        }
        if (codePoint == ONE_BIT_CHARACTER) {
            return 1;
        }
        return -1;
    }

    private static void validateCarrier(String carrier) {
        Objects.requireNonNull(carrier, "text carrier must not be null");
        if (carrier.isEmpty()) {
            throw new IllegalArgumentException("text carrier must not be empty");
        }
    }

    /**
     * Immutable counts for characters commonly used to conceal text payloads.
     *
     * @param zeroBitCount U+200B count
     * @param oneBitCount U+200C count
     * @param zeroWidthJoinerCount U+200D count
     * @param wordJoinerCount U+2060 count
     * @param zeroWidthNoBreakSpaceCount U+FEFF count
     */
    public record InvisibleCharacterReport(int zeroBitCount, int oneBitCount,
            int zeroWidthJoinerCount, int wordJoinerCount, int zeroWidthNoBreakSpaceCount) {
        /**
         * Validates that counts cannot be negative.
         */
        public InvisibleCharacterReport {
            if (zeroBitCount < 0 || oneBitCount < 0 || zeroWidthJoinerCount < 0
                    || wordJoinerCount < 0 || zeroWidthNoBreakSpaceCount < 0) {
                throw new IllegalArgumentException("invisible-character counts must not be negative");
            }
        }

        /**
         * Returns the total count of monitored invisible characters.
         *
         * @return sum of all count fields
         */
        public long totalCount() {
            return (long) zeroBitCount + oneBitCount + zeroWidthJoinerCount
                    + wordJoinerCount + zeroWidthNoBreakSpaceCount;
        }

        /**
         * Returns the count of U+200B/U+200C characters that encode bits.
         *
         * @return zero-plus-one bit-character count
         */
        public long bitCharacterCount() {
            return (long) zeroBitCount + oneBitCount;
        }
    }
}
