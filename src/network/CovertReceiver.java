package network;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Localhost-only receiver for the controlled timing-channel simulation. It
 * binds only to loopback, uses accept/read timeouts, limits payload length, and
 * can run one receive operation on a daemon worker thread.
 */
public final class CovertReceiver implements AutoCloseable {
    private final ServerSocket serverSocket;
    private final int maximumPayloadBytes;
    private volatile boolean closed;

    /**
     * Binds a loopback receiver with the default payload limit. Use port zero
     * to request an available ephemeral loopback port.
     *
     * @param port requested TCP port from zero through 65535
     * @throws IOException if loopback binding fails
     */
    public CovertReceiver(int port) throws IOException {
        this(port, TimingChannel.DEFAULT_MAX_PAYLOAD_BYTES);
    }

    /**
     * Binds a loopback receiver with an explicit payload limit.
     *
     * @param port requested TCP port from zero through 65535
     * @param maximumPayloadBytes positive maximum decoded payload length
     * @throws IOException if loopback binding fails
     */
    public CovertReceiver(int port, int maximumPayloadBytes) throws IOException {
        if (port < 0 || port > 65_535) {
            throw new IllegalArgumentException("receiver port must be between 0 and 65535");
        }
        if (maximumPayloadBytes <= 0) {
            throw new IllegalArgumentException("maximum payload bytes must be positive");
        }
        this.maximumPayloadBytes = maximumPayloadBytes;
        serverSocket = new ServerSocket();
        try {
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
            serverSocket.setSoTimeout(TimingChannel.SOCKET_TIMEOUT_MILLIS);
            closed = false;
        } catch (IOException | RuntimeException exception) {
            try {
                serverSocket.close();
            } catch (IOException closeException) {
                exception.addSuppressed(closeException);
            }
            throw exception;
        }
    }

    /**
     * Returns the loopback port selected for this receiver.
     *
     * @return active local TCP port
     */
    public int port() {
        return serverSocket.getLocalPort();
    }

    /**
     * Accepts one sender and blocks until a complete timing payload, timeout,
     * disconnect, or close. It is safe to call from a worker thread.
     *
     * @return decoded message, raw intervals, and analysis
     * @throws IOException if timeout, malformed protocol, or socket I/O occurs
     */
    public Reception receiveOnce() throws IOException {
        ensureOpen();
        try (Socket socket = serverSocket.accept()) {
            socket.setTcpNoDelay(true);
            socket.setSoTimeout(TimingChannel.SOCKET_TIMEOUT_MILLIS);
            try (InputStream input = socket.getInputStream()) {
                return receiveTokens(input);
            }
        }
    }

    /**
     * Starts one daemon receive worker. Listener callbacks execute on that
     * worker and AWT callers must use EventQueue.invokeLater before UI updates.
     *
     * @param listener receive result callback
     * @return started daemon worker
     */
    public Thread receiveAsync(Listener listener) {
        Objects.requireNonNull(listener, "receiver listener must not be null");
        ensureOpen();
        Thread worker = new Thread(() -> {
            try {
                listener.onReceived(receiveOnce());
            } catch (IOException exception) {
                if (!closed) {
                    listener.onFailure(exception);
                }
            }
        }, "StegoShield-TimingReceiver");
        worker.setDaemon(true);
        worker.start();
        return worker;
    }

    private Reception receiveTokens(InputStream input) throws IOException {
        int synchronization = input.read();
        if (synchronization != TimingChannel.TOKEN) {
            throw new IOException("timing channel synchronization token is missing");
        }
        List<Long> intervals = new ArrayList<>();
        long previousArrival = System.nanoTime();
        int header = 0;
        int headerBits = 0;
        byte[] payload = null;
        long payloadBits = 0L;
        while (true) {
            int token = input.read();
            if (token < 0) {
                throw new IOException("timing sender disconnected before a complete payload arrived");
            }
            if (token != TimingChannel.TOKEN) {
                throw new IOException("timing channel received an unexpected token byte");
            }
            long arrival = System.nanoTime();
            long interval = Math.max(0L, arrival - previousArrival);
            intervals.add(interval);
            previousArrival = arrival;
            int bit = interval >= TimingChannel.DECISION_THRESHOLD_MILLIS * 1_000_000L ? 1 : 0;
            if (headerBits < Integer.SIZE) {
                header = (header << 1) | bit;
                headerBits++;
                if (headerBits == Integer.SIZE) {
                    long length = Integer.toUnsignedLong(header);
                    if (length == 0L || length > maximumPayloadBytes) {
                        throw new IOException("timing payload length " + length + " exceeds receiver limit of "
                                + maximumPayloadBytes + " bytes");
                    }
                    payload = new byte[(int) length];
                }
                continue;
            }
            int byteIndex = (int) (payloadBits / Byte.SIZE);
            payload[byteIndex] = (byte) ((payload[byteIndex] << 1) | bit);
            payloadBits++;
            if (payloadBits == (long) payload.length * Byte.SIZE) {
                return new Reception(payload, intervals, TimingAnalyzer.analyze(intervals));
            }
        }
    }

    private void ensureOpen() {
        if (closed || serverSocket.isClosed()) {
            throw new IllegalStateException("timing receiver is closed");
        }
    }

    /**
     * Closes the loopback server socket, unblocking an in-progress accept.
     */
    @Override
    public void close() throws IOException {
        closed = true;
        serverSocket.close();
    }

    /**
     * Immutable receive result. Payload and intervals are copied defensively.
     */
    public static final class Reception {
        private final byte[] payload;
        private final List<Long> intervalsNanos;
        private final TimingAnalysis analysis;

        private Reception(byte[] payload, List<Long> intervalsNanos, TimingAnalysis analysis) {
            this.payload = Arrays.copyOf(Objects.requireNonNull(payload, "payload must not be null"), payload.length);
            this.intervalsNanos = List.copyOf(Objects.requireNonNull(intervalsNanos,
                    "interval list must not be null"));
            this.analysis = Objects.requireNonNull(analysis, "timing analysis must not be null");
        }

        /** @return recovered payload copy */
        public byte[] payload() {
            return Arrays.copyOf(payload, payload.length);
        }

        /** @return immutable inter-arrival measurements in nanoseconds */
        public List<Long> intervalsNanos() {
            return intervalsNanos;
        }

        /** @return histogram and bimodality/regularity analysis */
        public TimingAnalysis analysis() {
            return analysis;
        }
    }

    /**
     * Callback for asynchronous receive operations.
     */
    public interface Listener {
        /** @param reception completed receive result */
        void onReceived(Reception reception);

        /** @param exception timeout, I/O, or malformed-protocol failure */
        void onFailure(Exception exception);
    }
}
