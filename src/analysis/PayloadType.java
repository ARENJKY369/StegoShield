package analysis;

import core.Payload;

/**
 * Labels common embedded payload signatures for extraction results. Recognition
 * is structural only and does not assert that a payload is safe or malicious.
 */
public enum PayloadType {
    /** A StegoShield framed payload beginning with SSHD. */
    STEGOSHIELD_FRAMED("StegoShield framed payload"),
    /** ZIP-family archive or container. */
    ZIP("ZIP archive"),
    /** DOS/Windows executable. */
    WINDOWS_EXECUTABLE("Windows executable"),
    /** PDF document. */
    PDF("PDF document"),
    /** ELF executable or shared library. */
    ELF("ELF executable or shared library"),
    /** No recognized payload signature. */
    UNKNOWN("unknown binary data");

    private final String displayName;

    PayloadType(String displayName) {
        this.displayName = displayName;
    }

    /**
     * Identifies a payload by its leading magic bytes.
     *
     * @param bytes candidate payload bytes
     * @return recognized payload label or {@link #UNKNOWN}
     */
    public static PayloadType identify(byte[] bytes) {
        if (Payload.hasMagic(bytes)) {
            return STEGOSHIELD_FRAMED;
        }
        FileSignature signature = FileSignature.detect(bytes);
        return switch (signature) {
            case ZIP -> ZIP;
            case WINDOWS_EXECUTABLE -> WINDOWS_EXECUTABLE;
            case PDF -> PDF;
            case ELF -> ELF;
            default -> UNKNOWN;
        };
    }

    /**
     * Returns a user-facing payload description.
     *
     * @return display name
     */
    public String displayName() {
        return displayName;
    }
}
