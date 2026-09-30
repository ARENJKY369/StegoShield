package image;

/**
 * Selects how image LSB payload bits are assigned to color-channel positions.
 * The self-describing public header is always sequential; this mode controls
 * only the encrypted payload positions after that header.
 */
public enum EmbeddingMode {
    /** Stores payload bits in channel order after the public header. */
    SEQUENTIAL("sequential"),
    /** Stores payload bits in a password-derived Fisher-Yates order. */
    PASSWORD_SCATTERED("password-scattered");

    private final String displayName;

    EmbeddingMode(String displayName) {
        this.displayName = displayName;
    }

    /** @return concise user-facing placement name */
    public String displayName() {
        return displayName;
    }
}
