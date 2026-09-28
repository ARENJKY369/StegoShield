package analysis;

import java.util.Locale;

/**
 * Recognizes common carrier and embedded-file magic-byte signatures without
 * relying on a filename extension.
 */
public enum FileSignature {
    /** PNG image signature. */
    PNG("PNG", new String[] {"png"}),
    /** JPEG start-of-image signature. */
    JPEG("JPEG", new String[] {"jpg", "jpeg"}),
    /** BMP bitmap signature. */
    BMP("BMP", new String[] {"bmp"}),
    /** RIFF/WAVE audio signature. */
    WAV("WAV/RIFF", new String[] {"wav", "wave"}),
    /** ZIP local-header or empty-archive signature. */
    ZIP("ZIP", new String[] {"zip", "jar", "apk", "docx", "xlsx", "pptx", "odt", "ods", "odp"}),
    /** DOS/Windows executable signature. */
    WINDOWS_EXECUTABLE("Windows executable", new String[] {"exe", "dll", "sys"}),
    /** PDF document signature. */
    PDF("PDF", new String[] {"pdf"}),
    /** ELF executable/shared-library signature. */
    ELF("ELF", new String[] {"elf", "so", "bin", "out"}),
    /** No signature implemented or detected. */
    UNKNOWN("unknown", new String[0]);

    private final String displayName;
    private final String[] expectedExtensions;

    FileSignature(String displayName, String[] expectedExtensions) {
        this.displayName = displayName;
        this.expectedExtensions = expectedExtensions.clone();
    }

    /**
     * Identifies a signature at the beginning of supplied bytes.
     *
     * @param bytes bytes to inspect
     * @return detected signature or {@link #UNKNOWN}
     */
    public static FileSignature detect(byte[] bytes) {
        FileSignature signature = detectAt(bytes, 0);
        return signature == null ? UNKNOWN : signature;
    }

    /**
     * Identifies a signature at an offset, returning null when none matches.
     *
     * @param bytes bytes to inspect
     * @param offset candidate signature offset
     * @return matching signature, or null
     */
    public static FileSignature detectAt(byte[] bytes, int offset) {
        if (bytes == null || offset < 0 || offset >= bytes.length) {
            return null;
        }
        if (matches(bytes, offset, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)) {
            return PNG;
        }
        if (matches(bytes, offset, 0xFF, 0xD8, 0xFF)) {
            return JPEG;
        }
        if (matches(bytes, offset, 0x42, 0x4D)) {
            return BMP;
        }
        if (matches(bytes, offset, 0x52, 0x49, 0x46, 0x46)
                && matches(bytes, offset + 8, 0x57, 0x41, 0x56, 0x45)) {
            return WAV;
        }
        if (matches(bytes, offset, 0x50, 0x4B, 0x03, 0x04)
                || matches(bytes, offset, 0x50, 0x4B, 0x05, 0x06)
                || matches(bytes, offset, 0x50, 0x4B, 0x07, 0x08)) {
            return ZIP;
        }
        if (matches(bytes, offset, 0x4D, 0x5A)) {
            return WINDOWS_EXECUTABLE;
        }
        if (matches(bytes, offset, 0x25, 0x50, 0x44, 0x46, 0x2D)) {
            return PDF;
        }
        if (matches(bytes, offset, 0x7F, 0x45, 0x4C, 0x46)) {
            return ELF;
        }
        return null;
    }

    /**
     * Returns the display name used in reports.
     *
     * @return signature display name
     */
    public String displayName() {
        return displayName;
    }

    /**
     * Returns whether a filename extension is normal for this signature.
     * Unknown signatures do not match any extension.
     *
     * @param extension extension without a leading dot
     * @return whether the extension is expected
     */
    public boolean matchesExtension(String extension) {
        if (extension == null || extension.isBlank()) {
            return false;
        }
        String normalized = extension.toLowerCase(Locale.ROOT);
        for (String expected : expectedExtensions) {
            if (expected.equals(normalized)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matches(byte[] bytes, int offset, int... expected) {
        if (offset < 0 || expected.length > bytes.length - offset) {
            return false;
        }
        for (int index = 0; index < expected.length; index++) {
            if ((bytes[offset + index] & 0xFF) != expected[index]) {
                return false;
            }
        }
        return true;
    }
}
