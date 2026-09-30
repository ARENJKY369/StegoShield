package image;

import core.Stego;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import javax.imageio.ImageIO;
import javax.imageio.stream.ImageOutputStream;

/**
 * Embeds arbitrary bytes in PNG or BMP image color-channel least-significant
 * bits. The in-memory carrier is always copied to {@link BufferedImage#TYPE_INT_RGB}.
 *
 * <p>Every payload starts with a fixed, sequential header containing a magic
 * marker, format version, placement flags, and a 32-bit unsigned payload
 * length. Keeping this small header sequential lets extraction detect the
 * placement mode before it reads the encrypted payload. Password-scattered
 * mode permutes only the RGB positions after that header; it provides placement
 * obfuscation, not a replacement for authenticated encryption.</p>
 *
 * <p>This class is not thread-safe. A password-scattered instance retains only
 * a SHA-256-derived seed and should be {@link #close() closed} when its caller
 * has finished using it.</p>
 */
public final class LSBImageStego implements Stego<BufferedImage>, AutoCloseable {
    /** Four-byte marker in the public image-LSB framing header. */
    public static final byte[] HEADER_MAGIC = {0x53, 0x53, 0x4C, 0x49}; // SSLI
    /** Current public image-LSB framing version. */
    public static final int HEADER_VERSION = 1;
    /** Flag indicating that payload positions after the header are password-scattered. */
    public static final int FLAG_PASSWORD_SCATTERED = 0x01;
    /** Header bytes: magic, version, flags, and unsigned 32-bit payload length. */
    public static final int HEADER_BYTES = HEADER_MAGIC.length + 1 + 1 + Integer.BYTES;
    /** RGB LSB positions reserved for the public framing header. */
    public static final int HEADER_BITS = HEADER_BYTES * Byte.SIZE;
    /** Number of RGB channel positions consumed by each payload byte. */
    public static final int BITS_PER_PAYLOAD_BYTE = Byte.SIZE;

    private static final int VERSION_OFFSET = HEADER_MAGIC.length;
    private static final int FLAGS_OFFSET = VERSION_OFFSET + 1;
    private static final int LENGTH_OFFSET = FLAGS_OFFSET + 1;

    private static final byte[] PNG_SIGNATURE = {
        (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
    };

    private final EmbeddingMode mode;
    private byte[] shuffleSeed;

    /**
     * Creates a sequential LSB encoder.
     */
    public LSBImageStego() {
        this(EmbeddingMode.SEQUENTIAL, null);
    }

    /**
     * Creates an LSB encoder in the selected placement mode.
     *
     * <p>For {@link EmbeddingMode#PASSWORD_SCATTERED}, {@code password} must
     * be non-empty and is cleared before this constructor returns. The encoder
     * retains a SHA-256-derived seed instead of the password itself. A supplied
     * password for sequential mode is likewise cleared and otherwise ignored.</p>
     *
     * @param mode embedding-position mode
     * @param password password for scattered mode, or null in sequential mode
     */
    public LSBImageStego(EmbeddingMode mode, char[] password) {
        this.mode = Objects.requireNonNull(mode, "embedding mode must not be null");
        if (mode == EmbeddingMode.PASSWORD_SCATTERED) {
            shuffleSeed = seedFromPassword(password);
        } else {
            shuffleSeed = null;
            clear(password);
        }
    }

    /**
     * Creates a sequential LSB encoder.
     *
     * @return a new sequential encoder
     */
    public static LSBImageStego sequential() {
        return new LSBImageStego();
    }

    /**
     * Creates a password-scattered LSB encoder.
     *
     * @param password non-empty mutable password, cleared before this method returns
     * @return a new password-scattered encoder
     */
    public static LSBImageStego passwordScattered(char[] password) {
        return new LSBImageStego(EmbeddingMode.PASSWORD_SCATTERED, password);
    }

    /**
     * Returns the placement mode selected for this encoder.
     *
     * @return embedding mode
     */
    public EmbeddingMode mode() {
        return mode;
    }

    /**
     * Calculates payload capacity after accounting for the public framing header.
     *
     * @param carrier image carrier
     * @return payload byte capacity
     */
    @Override
    public long capacityBytes(BufferedImage carrier) {
        long channelCount = channelCount(carrier);
        if (channelCount <= HEADER_BITS) {
            return 0L;
        }
        return (channelCount - HEADER_BITS) / BITS_PER_PAYLOAD_BYTE;
    }

    /**
     * Embeds a non-empty byte array and returns a new TYPE_INT_RGB image.
     * The supplied image is never modified.
     *
     * @param carrier PNG or BMP-compatible in-memory carrier image
     * @param payload non-empty bytes to embed
     * @return new RGB image containing the self-describing header and payload bits
     */
    @Override
    public BufferedImage embed(BufferedImage carrier, byte[] payload) {
        Objects.requireNonNull(payload, "payload must not be null");
        ensureOpen();
        if (payload.length == 0) {
            throw new IllegalArgumentException("payload must not be empty");
        }
        long capacity = capacityBytes(carrier);
        if ((long) payload.length > capacity) {
            throw new IllegalArgumentException("payload is " + payload.length
                    + " bytes but image capacity is only " + capacity + " bytes");
        }
        BufferedImage embedded = copyToRgb(carrier);
        writeHeader(embedded, mode, Integer.toUnsignedLong(payload.length));
        int[] positions = positionsFor(embedded);
        long payloadBitIndex = 0L;
        for (byte payloadByte : payload) {
            int value = Byte.toUnsignedInt(payloadByte);
            for (int shift = BITS_PER_PAYLOAD_BYTE - 1; shift >= 0; shift--) {
                writeCarrierBit(embedded, payloadBitIndex++, (value >>> shift) & 1, positions);
            }
        }
        return embedded;
    }

    /**
     * Extracts bytes after reading and validating the self-describing header.
     * The selected encoder mode must match the mode recorded in that header.
     *
     * @param carrier carrier to inspect
     * @return extracted bytes
     */
    @Override
    public byte[] extract(BufferedImage carrier) {
        ensureOpen();
        BufferedImage source = copyToRgb(carrier);
        Header header = inspectHeader(source);
        if (header.mode() != mode) {
            throw new IllegalArgumentException("image payload uses " + header.mode().displayName()
                    + " placement; extraction must use the mode recorded in its header");
        }
        long capacity = capacityBytes(source);
        if (header.payloadLength() == 0L) {
            throw new IllegalArgumentException("LSB header declares an empty payload");
        }
        if (header.payloadLength() > capacity) {
            throw new IllegalArgumentException("LSB header declares " + header.payloadLength()
                    + " bytes, exceeding image capacity of " + capacity + " bytes");
        }
        int payloadLength = Math.toIntExact(header.payloadLength());
        int[] positions = positionsFor(source);
        byte[] payload = new byte[payloadLength];
        long payloadBitIndex = 0L;
        for (int byteIndex = 0; byteIndex < payload.length; byteIndex++) {
            int value = 0;
            for (int bit = 0; bit < BITS_PER_PAYLOAD_BYTE; bit++) {
                value = (value << 1) | readCarrierBit(source, payloadBitIndex++, positions);
            }
            payload[byteIndex] = (byte) value;
        }
        return payload;
    }

    /**
     * Reads the public header and returns its recorded placement and payload length.
     * No password is needed because the header itself is always sequential.
     *
     * @param carrier image to inspect
     * @return validated image-LSB header
     */
    public static Header inspectHeader(BufferedImage carrier) {
        long channels = channelCount(carrier);
        if (channels < HEADER_BITS) {
            throw new IllegalArgumentException("image is too small to contain a StegoShield LSB header");
        }
        byte[] bytes = new byte[HEADER_BYTES];
        long physicalBit = 0L;
        for (int byteIndex = 0; byteIndex < bytes.length; byteIndex++) {
            int value = 0;
            for (int bit = 0; bit < Byte.SIZE; bit++) {
                value = (value << 1) | readPhysicalBit(carrier, physicalBit++);
            }
            bytes[byteIndex] = (byte) value;
        }
        for (int index = 0; index < HEADER_MAGIC.length; index++) {
            if (bytes[index] != HEADER_MAGIC[index]) {
                throw new IllegalArgumentException("StegoShield image LSB header was not found");
            }
        }
        int version = Byte.toUnsignedInt(bytes[VERSION_OFFSET]);
        if (version != HEADER_VERSION) {
            throw new IllegalArgumentException("unsupported StegoShield image LSB header version: " + version);
        }
        int flags = Byte.toUnsignedInt(bytes[FLAGS_OFFSET]);
        if ((flags & ~FLAG_PASSWORD_SCATTERED) != 0) {
            throw new IllegalArgumentException("unsupported StegoShield image LSB header flags: " + flags);
        }
        long length = ((long) Byte.toUnsignedInt(bytes[LENGTH_OFFSET]) << 24)
                | ((long) Byte.toUnsignedInt(bytes[LENGTH_OFFSET + 1]) << 16)
                | ((long) Byte.toUnsignedInt(bytes[LENGTH_OFFSET + 2]) << 8)
                | Byte.toUnsignedInt(bytes[LENGTH_OFFSET + 3]);
        EmbeddingMode placement = (flags & FLAG_PASSWORD_SCATTERED) != 0
                ? EmbeddingMode.PASSWORD_SCATTERED : EmbeddingMode.SEQUENTIAL;
        return new Header(placement, length);
    }

    /**
     * Detects placement from the header, then extracts with the supplied password
     * only when scattered placement requires it. The password array is cleared.
     *
     * @param carrier image carrier
     * @param password password for a scattered payload, otherwise optional
     * @return extracted opaque payload bytes
     */
    public static byte[] extractAutomatically(BufferedImage carrier, char[] password) {
        EmbeddingMode detected = inspectHeader(carrier).mode();
        try (LSBImageStego stego = new LSBImageStego(detected, password)) {
            return stego.extract(carrier);
        }
    }

    /**
     * Loads an image only when its on-disk signature is PNG or BMP and decoding
     * succeeds. This rejects a JPEG or arbitrary file merely renamed to .png.
     *
     * @param source candidate PNG or BMP file
     * @return decoded image
     * @throws IOException if the file cannot be safely decoded as PNG or BMP
     */
    public static BufferedImage readCarrier(File source) throws IOException {
        requireReadableFile(source, "image source");
        try (BufferedInputStream input = new BufferedInputStream(new FileInputStream(source))) {
            input.mark(PNG_SIGNATURE.length);
            byte[] magic = input.readNBytes(PNG_SIGNATURE.length);
            if (!hasPngSignature(magic) && !hasBmpSignature(magic)) {
                throw new IOException("image carrier must be a PNG or BMP file; JPEG and other formats are unsupported");
            }
            input.reset();
            final BufferedImage decoded;
            try {
                decoded = ImageIO.read(input);
            } catch (IOException exception) {
                throw new IOException("cannot decode PNG/BMP image carrier: " + source, exception);
            }
            if (decoded == null) {
                throw new IOException("file has a PNG/BMP signature but is not a decodable image");
            }
            return decoded;
        }
    }

    /**
     * Writes a TYPE_INT_RGB-normalized PNG and returns the actual output path.
     * JPEG filenames are explicitly rejected. A BMP or extensionless requested
     * name is converted to a .png filename so the extension matches the bytes.
     *
     * @param image image to write
     * @param requestedOutput target file selected by the user
     * @return actual PNG file written
     * @throws IOException if the image cannot be written as PNG
     */
    public static File writePng(BufferedImage image, File requestedOutput) throws IOException {
        validateImage(image);
        File output = pngOutputFile(requestedOutput);
        File parent = output.getAbsoluteFile().getParentFile();
        if (parent != null && !parent.isDirectory()) {
            throw new IOException("output directory does not exist: " + parent);
        }
        if (output.isDirectory()) {
            throw new IOException("output path is a directory: " + output);
        }
        try (ImageOutputStream stream = ImageIO.createImageOutputStream(output)) {
            if (stream == null) {
                throw new IOException("cannot open output image file: " + output);
            }
            boolean written = ImageIO.write(copyToRgb(image), "png", stream);
            if (!written) {
                throw new IOException("no PNG ImageIO writer is available in this JDK");
            }
        }
        return output;
    }

    /**
     * Normalizes a selected output name to a PNG filename without writing it.
     *
     * @param requestedOutput user-selected destination
     * @return requested destination when it ends in .png, otherwise a .png variant
     */
    public static File pngOutputFile(File requestedOutput) {
        Objects.requireNonNull(requestedOutput, "requested output file must not be null");
        String name = requestedOutput.getName();
        if (name.isEmpty()) {
            throw new IllegalArgumentException("output file name must not be empty");
        }
        String extension = extensionOf(name);
        if ("jpg".equals(extension) || "jpeg".equals(extension)) {
            throw new IllegalArgumentException("JPEG output is not supported because JPEG is lossy; choose PNG output");
        }
        if ("png".equals(extension)) {
            return requestedOutput;
        }
        int lastDot = name.lastIndexOf('.');
        String pngName = lastDot > 0 ? name.substring(0, lastDot) + ".png" : name + ".png";
        File parent = requestedOutput.getParentFile();
        return parent == null ? new File(pngName) : new File(parent, pngName);
    }

    /**
     * Returns a new RGB copy suitable for deterministic LSB operations.
     *
     * @param image image to normalize
     * @return TYPE_INT_RGB copy
     */
    public static BufferedImage copyToRgb(BufferedImage image) {
        validateImage(image);
        BufferedImage copy = new BufferedImage(image.getWidth(), image.getHeight(), BufferedImage.TYPE_INT_RGB);
        Graphics2D graphics = copy.createGraphics();
        try {
            graphics.drawImage(image, 0, 0, null);
        } finally {
            graphics.dispose();
        }
        return copy;
    }

    /**
     * Clears the retained password-derived seed. A closed password-scattered
     * encoder cannot be used again; closing a sequential encoder is harmless.
     */
    @Override
    public void close() {
        clear(shuffleSeed);
        shuffleSeed = null;
    }

    private void ensureOpen() {
        if (mode == EmbeddingMode.PASSWORD_SCATTERED && shuffleSeed == null) {
            throw new IllegalStateException("password-scattered encoder has been closed");
        }
    }

    private static long channelCount(BufferedImage image) {
        validateImage(image);
        try {
            long pixelCount = Math.multiplyExact((long) image.getWidth(), (long) image.getHeight());
            return Math.multiplyExact(pixelCount, 3L);
        } catch (ArithmeticException exception) {
            throw new IllegalArgumentException("image dimensions are too large to calculate safely", exception);
        }
    }

    private int[] positionsFor(BufferedImage image) {
        if (mode == EmbeddingMode.SEQUENTIAL) {
            return null;
        }
        long channels = channelCount(image);
        if (channels > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("image has too many channels for password-scattered embedding");
        }
        long usableChannels = channels - HEADER_BITS;
        int[] positions = new int[(int) usableChannels];
        for (int index = 0; index < positions.length; index++) {
            positions[index] = HEADER_BITS + index;
        }
        DeterministicRandom random = new DeterministicRandom(shuffleSeed);
        for (int index = positions.length - 1; index > 0; index--) {
            int swapIndex = random.nextInt(index + 1);
            int position = positions[index];
            positions[index] = positions[swapIndex];
            positions[swapIndex] = position;
        }
        return positions;
    }

    private static void writeHeader(BufferedImage image, EmbeddingMode placement, long byteLength) {
        byte[] header = new byte[HEADER_BYTES];
        System.arraycopy(HEADER_MAGIC, 0, header, 0, HEADER_MAGIC.length);
        header[VERSION_OFFSET] = (byte) HEADER_VERSION;
        header[FLAGS_OFFSET] = placement == EmbeddingMode.PASSWORD_SCATTERED
                ? (byte) FLAG_PASSWORD_SCATTERED : 0;
        header[LENGTH_OFFSET] = (byte) (byteLength >>> 24);
        header[LENGTH_OFFSET + 1] = (byte) (byteLength >>> 16);
        header[LENGTH_OFFSET + 2] = (byte) (byteLength >>> 8);
        header[LENGTH_OFFSET + 3] = (byte) byteLength;
        long physicalBit = 0L;
        for (byte value : header) {
            int unsigned = Byte.toUnsignedInt(value);
            for (int shift = Byte.SIZE - 1; shift >= 0; shift--) {
                writePhysicalBit(image, physicalBit++, (unsigned >>> shift) & 1);
            }
        }
    }

    private static void writeCarrierBit(BufferedImage image, long logicalBitIndex, int bit,
            int[] positions) {
        if (bit != 0 && bit != 1) {
            throw new IllegalArgumentException("carrier bit must be zero or one");
        }
        writePhysicalBit(image, channelPosition(logicalBitIndex, positions), bit);
    }

    private static int readCarrierBit(BufferedImage image, long logicalBitIndex, int[] positions) {
        return readPhysicalBit(image, channelPosition(logicalBitIndex, positions));
    }

    private static long channelPosition(long logicalBitIndex, int[] positions) {
        if (logicalBitIndex < 0L) {
            throw new IllegalArgumentException("logical bit index must not be negative");
        }
        if (positions == null) {
            return HEADER_BITS + logicalBitIndex;
        }
        if (logicalBitIndex >= positions.length) {
            throw new IllegalArgumentException("logical bit index exceeds scattered carrier positions");
        }
        return positions[Math.toIntExact(logicalBitIndex)];
    }


    private static void writePhysicalBit(BufferedImage image, long channelPosition, int bit) {
        long pixelIndex = channelPosition / 3L;
        int channel = (int) (channelPosition % 3L);
        int x = (int) (pixelIndex % image.getWidth());
        int y = Math.toIntExact(pixelIndex / image.getWidth());
        int shift = channel == 0 ? 16 : channel == 1 ? 8 : 0;
        int rgb = image.getRGB(x, y);
        image.setRGB(x, y, (rgb & ~(1 << shift)) | (bit << shift));
    }

    private static int readPhysicalBit(BufferedImage image, long channelPosition) {
        long pixelIndex = channelPosition / 3L;
        int channel = (int) (channelPosition % 3L);
        int x = (int) (pixelIndex % image.getWidth());
        int y = Math.toIntExact(pixelIndex / image.getWidth());
        int shift = channel == 0 ? 16 : channel == 1 ? 8 : 0;
        return (image.getRGB(x, y) >>> shift) & 1;
    }

    private static byte[] seedFromPassword(char[] password) {
        if (password == null) {
            throw new IllegalArgumentException("password is required for password-scattered embedding");
        }
        byte[] passwordBytes = null;
        try {
            if (password.length == 0) {
                throw new IllegalArgumentException("password must not be empty for password-scattered embedding");
            }
            ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
            passwordBytes = new byte[encoded.remaining()];
            encoded.get(passwordBytes);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(passwordBytes);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("this JDK does not provide required SHA-256", exception);
        } finally {
            clear(passwordBytes);
            clear(password);
        }
    }

    private static boolean hasPngSignature(byte[] bytes) {
        if (bytes.length < PNG_SIGNATURE.length) {
            return false;
        }
        for (int index = 0; index < PNG_SIGNATURE.length; index++) {
            if (bytes[index] != PNG_SIGNATURE[index]) {
                return false;
            }
        }
        return true;
    }

    private static boolean hasBmpSignature(byte[] bytes) {
        return bytes.length >= 2 && bytes[0] == 0x42 && bytes[1] == 0x4D;
    }

    private static void requireReadableFile(File file, String description) throws IOException {
        if (file == null) {
            throw new IllegalArgumentException(description + " must not be null");
        }
        if (!file.isFile()) {
            throw new IOException(description + " is not a readable regular file: " + file);
        }
    }

    private static void validateImage(BufferedImage image) {
        Objects.requireNonNull(image, "image must not be null");
        if (image.getWidth() <= 0 || image.getHeight() <= 0) {
            throw new IllegalArgumentException("image dimensions must be positive");
        }
    }

    private static String extensionOf(String name) {
        int dot = name.lastIndexOf('.');
        if (dot < 0 || dot == name.length() - 1) {
            return "";
        }
        return name.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    private static void clear(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static void clear(char[] characters) {
        if (characters != null) {
            Arrays.fill(characters, '\0');
        }
    }

    /** Parsed public image-LSB framing header. */
    public record Header(EmbeddingMode mode, long payloadLength) {
        /** Validates directly constructed headers. */
        public Header {
            Objects.requireNonNull(mode, "header placement mode must not be null");
            if (payloadLength < 0L || payloadLength > 0xFFFF_FFFFL) {
                throw new IllegalArgumentException("payload length is outside the unsigned 32-bit range");
            }
        }
    }

    /**
     * Deterministic SHA-256 counter-mode byte generator used solely to drive a
     * reproducible Fisher-Yates permutation. It is not exposed as a general
     * random-number generator or encryption primitive.
     */
    private static final class DeterministicRandom {
        private final byte[] seed;
        private byte[] block;
        private int blockOffset;
        private long counter;

        private DeterministicRandom(byte[] seed) {
            this.seed = Objects.requireNonNull(seed, "shuffle seed must not be null");
            block = new byte[0];
            blockOffset = 0;
            counter = 0L;
        }

        private int nextInt(int bound) {
            if (bound <= 0) {
                throw new IllegalArgumentException("random bound must be positive");
            }
            long range = 1L << Integer.SIZE;
            long acceptanceLimit = range - range % bound;
            long candidate;
            do {
                candidate = nextUnsignedInt();
            } while (candidate >= acceptanceLimit);
            return (int) (candidate % bound);
        }

        private long nextUnsignedInt() {
            return ((long) nextByte() << 24)
                    | ((long) nextByte() << 16)
                    | ((long) nextByte() << 8)
                    | (long) nextByte();
        }

        private int nextByte() {
            if (blockOffset >= block.length) {
                refill();
            }
            return Byte.toUnsignedInt(block[blockOffset++]);
        }

        private void refill() {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(seed);
                for (int shift = Long.SIZE - Byte.SIZE; shift >= 0; shift -= Byte.SIZE) {
                    digest.update((byte) (counter >>> shift));
                }
                if (counter == Long.MAX_VALUE) {
                    throw new IllegalStateException("password-scatter counter exhausted");
                }
                counter++;
                block = digest.digest();
                blockOffset = 0;
            } catch (NoSuchAlgorithmException exception) {
                throw new IllegalStateException("this JDK does not provide required SHA-256", exception);
            }
        }
    }
}
