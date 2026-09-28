package image;

/**
 * Selects how image LSB payload bits are assigned to color-channel positions.
 * Sequential mode is simple but readily discoverable; password-scattered mode
 * deterministically shuffles the positions from a password-derived seed.
 */
public enum EmbeddingMode {
    /** Stores the 32-bit length header and payload bits in channel order. */
    SEQUENTIAL,
    /** Stores the header and payload in a password-derived Fisher-Yates order. */
    PASSWORD_SCATTERED
}
