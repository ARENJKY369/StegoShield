package eof;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;

/**
 * Creates and reads simple PNG end-of-file payload fixtures. Bytes after the
 * PNG IEND chunk are ignored by many image viewers but are detectable by a
 * structural scanner. This technique offers no confidentiality or integrity;
 * callers should encrypt and frame payloads before appending them.
 */
public final class PngEofStego {
    private PngEofStego() {
        // Utility class.
    }

    /**
     * Appends non-empty bytes immediately after IEND, writing a distinct output
     * file. A source PNG with pre-existing trailing bytes is rejected so callers
     * do not accidentally combine unrelated data with a new hidden payload.
     *
     * @param source clean PNG source file
     * @param payload bytes to append
     * @param output distinct output PNG file
     * @return output file
     * @throws IOException if validation or writing fails
     */
    public static File appendAfterIend(File source, byte[] payload, File output) throws IOException {
        Objects.requireNonNull(payload, "trailing payload must not be null");
        if (payload.length == 0) {
            throw new IllegalArgumentException("trailing payload must not be empty");
        }
        byte[] sourceBytes = PngUtil.readPng(source);
        int iendEnd = PngUtil.iendEnd(sourceBytes);
        if (iendEnd != sourceBytes.length) {
            throw new IllegalArgumentException("source PNG already contains trailing bytes after IEND");
        }
        validateDistinctOutput(source, output);
        if (sourceBytes.length > Integer.MAX_VALUE - payload.length) {
            throw new IllegalArgumentException("PNG and trailing payload are too large to combine");
        }
        byte[] result = Arrays.copyOf(sourceBytes, sourceBytes.length + payload.length);
        System.arraycopy(payload, 0, result, sourceBytes.length, payload.length);
        Files.write(output.toPath(), result);
        return output;
    }

    /**
     * Returns all bytes after IEND. An empty array means the PNG has no trailing data.
     *
     * @param source PNG file to inspect
     * @return copy of bytes after IEND
     * @throws IOException if the source is not a structurally valid PNG file
     */
    public static byte[] extractAfterIend(File source) throws IOException {
        return PngUtil.trailingBytes(PngUtil.readPng(source));
    }

    /**
     * Returns the count of bytes after IEND without exposing their contents.
     *
     * @param source PNG file to inspect
     * @return trailing byte count
     * @throws IOException if the source is not a structurally valid PNG file
     */
    public static long trailingByteCount(File source) throws IOException {
        byte[] png = PngUtil.readPng(source);
        return png.length - (long) PngUtil.iendEnd(png);
    }

    private static void validateDistinctOutput(File source, File output) throws IOException {
        if (output == null) {
            throw new IllegalArgumentException("output PNG file must not be null");
        }
        if (output.isDirectory()) {
            throw new IOException("output PNG path is a directory: " + output);
        }
        if (!output.getName().toLowerCase(Locale.ROOT).endsWith(".png")) {
            throw new IllegalArgumentException("EOF stego output must use a .png filename");
        }
        File parent = output.getAbsoluteFile().getParentFile();
        if (parent != null && !parent.isDirectory()) {
            throw new IOException("output PNG directory does not exist: " + parent);
        }
        if (source.getCanonicalFile().equals(output.getCanonicalFile())) {
            throw new IllegalArgumentException("output PNG must differ from the source; original files are not modified");
        }
    }
}
