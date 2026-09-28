package core;

/**
 * Defines the in-memory operations shared by steganography carriers.
 *
 * <p>Implementations must reject invalid carriers and payloads with a clear
 * {@link IllegalArgumentException}. The capacity is expressed in payload bytes
 * and must be calculated without narrowing arithmetic.</p>
 *
 * @param <C> carrier type handled by the implementation
 */
public interface Stego<C> {
    /**
     * Returns the maximum number of bytes that can be embedded in {@code carrier}.
     *
     * @param carrier carrier to inspect
     * @return usable payload capacity in bytes
     * @throws IllegalArgumentException if the carrier is invalid
     */
    long capacityBytes(C carrier);

    /**
     * Embeds a payload in a copy or transformed form of {@code carrier}.
     * Implementations must not silently truncate data.
     *
     * @param carrier carrier to modify
     * @param payload bytes to embed
     * @return carrier containing the payload
     * @throws IllegalArgumentException if an argument is invalid or capacity is exceeded
     */
    C embed(C carrier, byte[] payload);

    /**
     * Extracts and validates a payload from {@code carrier}.
     *
     * @param carrier carrier to inspect
     * @return extracted payload bytes
     * @throws IllegalArgumentException if no valid payload is present
     */
    byte[] extract(C carrier);
}
