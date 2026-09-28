package core;

import java.util.Arrays;
import java.util.Objects;
import java.util.zip.CRC32;

/**
 * Serializes payload bytes with a compact, self-describing integrity header.
 *
 * <p>The wire layout is {@code SSHD | version | length | CRC32 | data}, where
 * the magic is four ASCII bytes, version is one byte, and the two numeric
 * fields are unsigned 32-bit, big-endian values. The CRC32 detects accidental
 * corruption and is not a cryptographic integrity mechanism; encrypted payloads
 * must additionally use authenticated encryption.</p>
 */
public final class Payload {
    /** Four-byte ASCII marker for StegoShield payloads. */
    public static final byte[] MAGIC = {0x53, 0x53, 0x48, 0x44};
    /** Current on-carrier payload format version. */
    public static final int VERSION = 1;
    /** Byte offset of the version field. */
    public static final int VERSION_OFFSET = MAGIC.length;
    /** Byte offset of the big-endian payload-length field. */
    public static final int LENGTH_OFFSET = VERSION_OFFSET + 1;
    /** Byte offset of the big-endian CRC32 field. */
    public static final int CRC_OFFSET = LENGTH_OFFSET + Integer.BYTES;
    /** Number of bytes preceding the actual payload. */
    public static final int HEADER_LENGTH = CRC_OFFSET + Integer.BYTES;

    private Payload() {
        // Utility class.
    }

    /**
     * Adds the StegoShield header to application bytes.
     *
     * @param data application bytes to protect with a header
     * @return a new serialized payload
     */
    public static byte[] wrap(byte[] data) {
        Objects.requireNonNull(data, "payload data must not be null");
        if ((long) data.length > 0xFFFF_FFFFL
                || data.length > Integer.MAX_VALUE - HEADER_LENGTH) {
            throw new IllegalArgumentException("payload is too large for the format");
        }
        byte[] serialized = new byte[HEADER_LENGTH + data.length];
        System.arraycopy(MAGIC, 0, serialized, 0, MAGIC.length);
        serialized[VERSION_OFFSET] = (byte) VERSION;
        writeUnsignedInt(serialized, LENGTH_OFFSET, data.length);
        writeUnsignedInt(serialized, CRC_OFFSET, crc32(data));
        System.arraycopy(data, 0, serialized, HEADER_LENGTH, data.length);
        return serialized;
    }

    /**
     * Validates and removes the StegoShield header.
     *
     * @param serialized header followed by application bytes
     * @return a new copy of the embedded application bytes
     */
    public static byte[] unwrap(byte[] serialized) {
        Header header = inspect(serialized);
        int dataLength = Math.toIntExact(header.payloadLength());
        byte[] data = Arrays.copyOfRange(serialized, HEADER_LENGTH, HEADER_LENGTH + dataLength);
        long actualCrc = crc32(data);
        if (actualCrc != header.crc32()) {
            throw new IllegalArgumentException("payload CRC32 verification failed; data is corrupted");
        }
        return data;
    }

    /**
     * Parses and validates the fixed header and declared total length, without
     * copying or interpreting the application bytes.
     *
     * @param serialized bytes beginning with a payload header
     * @return immutable parsed header
     */
    public static Header inspect(byte[] serialized) {
        Objects.requireNonNull(serialized, "serialized payload must not be null");
        if (serialized.length < HEADER_LENGTH) {
            throw new IllegalArgumentException("payload is shorter than the StegoShield header");
        }
        for (int index = 0; index < MAGIC.length; index++) {
            if (serialized[index] != MAGIC[index]) {
                throw new IllegalArgumentException("StegoShield payload magic is missing");
            }
        }
        int version = Byte.toUnsignedInt(serialized[VERSION_OFFSET]);
        if (version != VERSION) {
            throw new IllegalArgumentException("unsupported StegoShield payload version: " + version);
        }
        long length = BitUtil.readUnsignedIntBigEndian(serialized, LENGTH_OFFSET);
        long expectedTotal = (long) HEADER_LENGTH + length;
        if (expectedTotal != serialized.length) {
            throw new IllegalArgumentException(
                    "payload length header does not match the available data");
        }
        long crc = BitUtil.readUnsignedIntBigEndian(serialized, CRC_OFFSET);
        return new Header(version, length, crc);
    }

    /**
     * Returns whether bytes start with the StegoShield payload magic. This is a
     * quick signature check only; callers should use {@link #inspect(byte[])}
     * before trusting any length or data.
     *
     * @param bytes candidate bytes
     * @return true when the first four bytes match the magic
     */
    public static boolean hasMagic(byte[] bytes) {
        if (bytes == null || bytes.length < MAGIC.length) {
            return false;
        }
        for (int index = 0; index < MAGIC.length; index++) {
            if (bytes[index] != MAGIC[index]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Calculates the CRC32 value represented as an unsigned 32-bit long.
     *
     * @param data data to checksum
     * @return CRC32 in the range 0 through 4,294,967,295
     */
    public static long crc32(byte[] data) {
        Objects.requireNonNull(data, "data must not be null");
        CRC32 crc = new CRC32();
        crc.update(data, 0, data.length);
        return crc.getValue();
    }

    private static void writeUnsignedInt(byte[] target, int offset, long value) {
        byte[] encoded = BitUtil.unsignedIntToBigEndian(value);
        System.arraycopy(encoded, 0, target, offset, encoded.length);
    }

    /**
     * Immutable description of a validated StegoShield payload header.
     *
     * @param version format version
     * @param payloadLength declared application-data byte length
     * @param crc32 expected CRC32 value as an unsigned long
     */
    public record Header(int version, long payloadLength, long crc32) {
        /**
         * Validates header field ranges for direct record construction.
         */
        public Header {
            if (version < 0 || version > 0xFF) {
                throw new IllegalArgumentException("version is outside the unsigned byte range");
            }
            if (payloadLength < 0L || payloadLength > 0xFFFF_FFFFL) {
                throw new IllegalArgumentException("payload length is outside the unsigned 32-bit range");
            }
            if (crc32 < 0L || crc32 > 0xFFFF_FFFFL) {
                throw new IllegalArgumentException("CRC32 is outside the unsigned 32-bit range");
            }
        }
    }
}
