package analysis;

import java.util.Arrays;
import java.util.Objects;

/**
 * Outcome of a best-effort carrier extraction attempt. Success only means bytes
 * were recovered through the named technique; callers must still validate a
 * StegoShield frame, decrypt authenticated ciphertext, and handle unknown data
 * safely.
 */
public final class ExtractionAttempt {
    private final boolean successful;
    private final String technique;
    private final PayloadType payloadType;
    private final byte[] payload;
    private final String message;

    private ExtractionAttempt(boolean successful, String technique, PayloadType payloadType,
            byte[] payload, String message) {
        this.successful = successful;
        this.technique = Objects.requireNonNull(technique, "technique must not be null");
        this.payloadType = Objects.requireNonNull(payloadType, "payload type must not be null");
        this.payload = payload == null ? null : Arrays.copyOf(payload, payload.length);
        this.message = Objects.requireNonNull(message, "message must not be null");
    }

    /**
     * Creates a successful attempt and identifies the leading payload magic.
     *
     * @param technique extraction path used
     * @param payload recovered bytes
     * @return successful result
     */
    public static ExtractionAttempt success(String technique, byte[] payload) {
        Objects.requireNonNull(payload, "recovered payload must not be null");
        return new ExtractionAttempt(true, technique, PayloadType.identify(payload), payload,
                "Recovered " + payload.length + " byte(s) as " + PayloadType.identify(payload).displayName() + ".");
    }

    /**
     * Creates a non-successful, user-safe attempt result.
     *
     * @param technique extraction path attempted
     * @param message result explanation
     * @return failure result
     */
    public static ExtractionAttempt failure(String technique, String message) {
        return new ExtractionAttempt(false, technique, PayloadType.UNKNOWN, null, message);
    }

    /**
     * Returns whether payload bytes were recovered.
     *
     * @return true on recovery
     */
    public boolean successful() {
        return successful;
    }

    /**
     * Returns the extraction method that succeeded or was attempted.
     *
     * @return technique name
     */
    public String technique() {
        return technique;
    }

    /**
     * Returns leading-byte payload identification.
     *
     * @return payload type
     */
    public PayloadType payloadType() {
        return payloadType;
    }

    /**
     * Returns a copy of recovered bytes, or null when extraction failed.
     *
     * @return payload copy or null
     */
    public byte[] payload() {
        return payload == null ? null : Arrays.copyOf(payload, payload.length);
    }

    /**
     * Returns a user-safe status message.
     *
     * @return outcome message
     */
    public String message() {
        return message;
    }
}
