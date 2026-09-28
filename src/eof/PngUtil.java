package eof;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Minimal, bounds-checked PNG chunk parser for locating the IEND boundary and
 * describing chunks. It validates structure and lengths but intentionally does
 * not attempt full PNG decoding or CRC verification.
 */
public final class PngUtil {
    /** Eight-byte PNG file signature. */
    public static final byte[] SIGNATURE = {
        (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
    };
    /** PNG chunk type marking the end of the image data stream. */
    public static final String IEND = "IEND";

    private PngUtil() {
        // Utility class.
    }

    /**
     * Reads a regular file and validates the PNG signature and chunk structure.
     *
     * @param file PNG file to read
     * @return complete file bytes
     * @throws IOException if the file is absent, unreadable, or not structurally PNG
     */
    public static byte[] readPng(File file) throws IOException {
        if (file == null) {
            throw new IllegalArgumentException("PNG file must not be null");
        }
        if (!file.isFile()) {
            throw new IOException("PNG path is not a readable regular file: " + file);
        }
        byte[] bytes = Files.readAllBytes(file.toPath());
        parseChunks(bytes);
        return bytes;
    }

    /**
     * Returns true when bytes begin with the eight-byte PNG signature.
     *
     * @param bytes candidate file bytes
     * @return whether the signature matches
     */
    public static boolean hasSignature(byte[] bytes) {
        if (bytes == null || bytes.length < SIGNATURE.length) {
            return false;
        }
        for (int index = 0; index < SIGNATURE.length; index++) {
            if (bytes[index] != SIGNATURE[index]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Parses chunks from the PNG signature through IEND. Bytes after IEND are
     * deliberately not parsed and can be inspected with {@link #iendEnd(byte[])}.
     *
     * @param png complete PNG bytes
     * @return unmodifiable chunk descriptions in file order through IEND
     */
    public static List<Chunk> parseChunks(byte[] png) {
        Objects.requireNonNull(png, "PNG bytes must not be null");
        if (!hasSignature(png)) {
            throw new IllegalArgumentException("PNG signature is missing or truncated");
        }
        List<Chunk> chunks = new ArrayList<>();
        int offset = SIGNATURE.length;
        boolean foundIend = false;
        while (offset < png.length) {
            if (png.length - offset < 12) {
                throw new IllegalArgumentException("truncated PNG chunk header or CRC at byte " + offset);
            }
            long dataLength = unsignedInt(png, offset);
            long totalLength = 12L + dataLength;
            if (totalLength > png.length - (long) offset) {
                throw new IllegalArgumentException("PNG chunk exceeds available file data at byte " + offset);
            }
            int dataOffset = offset + 8;
            int endOffset = Math.toIntExact(offset + totalLength);
            String type = chunkType(png, offset + 4);
            if (chunks.isEmpty() && (!"IHDR".equals(type) || dataLength != 13L)) {
                throw new IllegalArgumentException("PNG must begin with a 13-byte IHDR chunk");
            }
            Chunk chunk = new Chunk(type, dataLength, dataOffset, endOffset);
            chunks.add(chunk);
            offset = endOffset;
            if (IEND.equals(type)) {
                if (dataLength != 0L) {
                    throw new IllegalArgumentException("PNG IEND chunk must have zero data bytes");
                }
                foundIend = true;
                break;
            }
        }
        if (!foundIend) {
            throw new IllegalArgumentException("PNG IEND chunk is missing");
        }
        return List.copyOf(chunks);
    }

    /**
     * Returns the zero-based offset immediately after the validated IEND chunk.
     *
     * @param png complete PNG bytes
     * @return first possible trailing-byte offset
     */
    public static int iendEnd(byte[] png) {
        List<Chunk> chunks = parseChunks(png);
        return chunks.get(chunks.size() - 1).endOffset();
    }

    /**
     * Returns a copy of all bytes after IEND; an empty array means no trailing data.
     *
     * @param png complete PNG bytes
     * @return trailing byte copy
     */
    public static byte[] trailingBytes(byte[] png) {
        int end = iendEnd(png);
        return Arrays.copyOfRange(png, end, png.length);
    }

    private static long unsignedInt(byte[] bytes, int offset) {
        return ((long) (bytes[offset] & 0xFF) << 24)
                | ((long) (bytes[offset + 1] & 0xFF) << 16)
                | ((long) (bytes[offset + 2] & 0xFF) << 8)
                | (long) (bytes[offset + 3] & 0xFF);
    }

    private static String chunkType(byte[] bytes, int offset) {
        char first = (char) (bytes[offset] & 0xFF);
        char second = (char) (bytes[offset + 1] & 0xFF);
        char third = (char) (bytes[offset + 2] & 0xFF);
        char fourth = (char) (bytes[offset + 3] & 0xFF);
        return new String(new char[] {first, second, third, fourth});
    }

    /**
     * Describes a validated PNG chunk. Offsets are indexes into the original
     * byte array; {@code endOffset} points immediately after the chunk CRC.
     *
     * @param type four-character PNG chunk type
     * @param dataLength unsigned data length in bytes
     * @param dataOffset first data-byte offset
     * @param endOffset first offset after this complete chunk
     */
    public record Chunk(String type, long dataLength, int dataOffset, int endOffset) {
        /**
         * Validates structural record fields.
         */
        public Chunk {
            Objects.requireNonNull(type, "PNG chunk type must not be null");
            if (type.length() != 4 || dataLength < 0L || dataOffset < 0 || endOffset < dataOffset) {
                throw new IllegalArgumentException("invalid PNG chunk description");
            }
        }
    }
}
