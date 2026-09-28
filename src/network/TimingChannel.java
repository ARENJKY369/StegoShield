package network;

/**
 * Protocol constants for the localhost-only timing-channel simulation. The
 * deliberately slow timings make this suitable for demonstration and analysis,
 * not for real communications.
 */
public final class TimingChannel {
    /** One marker byte is sent for every timing event. */
    public static final int TOKEN = 0x7E;
    /** Delay before a zero-bit token. */
    public static final long ZERO_GAP_MILLIS = 50L;
    /** Delay before a one-bit token. */
    public static final long ONE_GAP_MILLIS = 150L;
    /** Midpoint decoder threshold between expected zero and one gaps. */
    public static final long DECISION_THRESHOLD_MILLIS = (ZERO_GAP_MILLIS + ONE_GAP_MILLIS) / 2L;
    /** TCP connection and accepted-socket read timeout. */
    public static final int SOCKET_TIMEOUT_MILLIS = 10_000;
    /** Default receive limit to prevent unexpectedly long simulations. */
    public static final int DEFAULT_MAX_PAYLOAD_BYTES = 8_192;

    private TimingChannel() {
        // Constants class.
    }
}
