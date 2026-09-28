package network;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Objects;

/**
 * Localhost-only timing-channel sender. It sends a marker token after a roughly
 * 50 ms delay for zero and 150 ms delay for one, preceded by one synchronization
 * token. This is a controlled demonstration, not a production covert channel.
 */
public final class CovertSender {
    private final int port;

    /**
     * Creates a sender targeting a receiver bound to the local loopback address.
     *
     * @param port receiver TCP port
     */
    public CovertSender(int port) {
        if (port < 1 || port > 65_535) {
            throw new IllegalArgumentException("receiver port must be between 1 and 65535");
        }
        this.port = port;
    }

    /**
     * Sends a non-empty payload using the simulation timing protocol. The call
     * blocks for the intentional timing delays and should therefore be invoked
     * from a worker thread by UI code.
     *
     * @param payload bytes to transmit
     * @return transmission summary
     * @throws IOException if localhost connection or writing fails
     * @throws InterruptedException if the caller interrupts the timing delays
     */
    public Transmission send(byte[] payload) throws IOException, InterruptedException {
        Objects.requireNonNull(payload, "timing payload must not be null");
        if (payload.length == 0) {
            throw new IllegalArgumentException("timing payload must not be empty");
        }
        long bitCount = Integer.SIZE + (long) payload.length * Byte.SIZE;
        try (Socket socket = new Socket()) {
            socket.setTcpNoDelay(true);
            socket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port),
                    TimingChannel.SOCKET_TIMEOUT_MILLIS);
            socket.setSoTimeout(TimingChannel.SOCKET_TIMEOUT_MILLIS);
            try (OutputStream output = socket.getOutputStream()) {
                sendToken(output);
                for (int shift = Integer.SIZE - 1; shift >= 0; shift--) {
                    sendBit(output, (payload.length >>> shift) & 1);
                }
                for (byte value : payload) {
                    int unsigned = Byte.toUnsignedInt(value);
                    for (int shift = Byte.SIZE - 1; shift >= 0; shift--) {
                        sendBit(output, (unsigned >>> shift) & 1);
                    }
                }
            }
        }
        return new Transmission(payload.length, bitCount, TimingChannel.ZERO_GAP_MILLIS,
                TimingChannel.ONE_GAP_MILLIS);
    }

    private static void sendBit(OutputStream output, int bit) throws IOException, InterruptedException {
        Thread.sleep(bit == 0 ? TimingChannel.ZERO_GAP_MILLIS : TimingChannel.ONE_GAP_MILLIS);
        sendToken(output);
    }

    private static void sendToken(OutputStream output) throws IOException {
        output.write(TimingChannel.TOKEN);
        output.flush();
    }

    /**
     * Transmission details based on the intended protocol rather than fabricated
     * delivery measurements.
     *
     * @param payloadBytes payload length
     * @param encodedBits number of timed bits, including the 32-bit length
     * @param zeroGapMillis configured zero delay
     * @param oneGapMillis configured one delay
     */
    public record Transmission(int payloadBytes, long encodedBits, long zeroGapMillis, long oneGapMillis) {
        /** Validates summary ranges. */
        public Transmission {
            if (payloadBytes <= 0 || encodedBits < Integer.SIZE || zeroGapMillis <= 0L
                    || oneGapMillis <= zeroGapMillis) {
                throw new IllegalArgumentException("invalid timing transmission summary");
            }
        }
    }
}
