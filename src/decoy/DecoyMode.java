package decoy;

import core.BitUtil;
import core.Payload;
import crypto.CryptoUtil;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Builds a fixed-size plausible-deniability container with two independently
 * AES-GCM-encrypted messages. The decoy ciphertext is stored conventionally;
 * the real ciphertext length and bytes are scattered into the least-significant
 * bits of otherwise random padding using a SHA-256 password-derived permutation.
 *
 * <p>A decoy-password holder can decrypt the decoy and sees only random padding,
 * which is indistinguishable from normal fixed-size padding at the byte level.
 * This is not a guarantee against coercion, traffic analysis, source-code
 * knowledge, implementation compromise, or an adversary who already knows a
 * real message is expected. Use it only as an optional privacy feature and
 * explain its limits to users.</p>
 */
public final class DecoyMode {
    /** Four-byte ASCII marker for a decoy-mode container. */
    public static final byte[] MAGIC = {0x53, 0x53, 0x44, 0x4E};
    /** Current decoy container format version. */
    public static final int VERSION = 1;
    /** Bytes before conventional decoy ciphertext: magic, version, and length. */
    public static final int HEADER_LENGTH = MAGIC.length + 1 + Integer.BYTES;
    /** Maximum container size to avoid unbounded permutation allocation. */
    public static final int MAX_CONTAINER_BYTES = 64 * 1024 * 1024;

    private static final SecureRandom RANDOM = new SecureRandom();

    private DecoyMode() {
        // Utility class.
    }

    /**
     * Creates a fixed-size container holding independent decoy and real
     * messages. All supplied password arrays are cleared before this method
     * returns or throws.
     *
     * @param decoyMessage harmless message shown with the decoy password
     * @param decoyPassword non-empty decoy password
     * @param realMessage sensitive message shown with the real password
     * @param realPassword non-empty real password distinct from decoy password
     * @param totalBytes fixed output size, including header and random padding
     * @return opaque fixed-size container
     * @throws GeneralSecurityException if JDK encryption fails
     */
    public static byte[] create(byte[] decoyMessage, char[] decoyPassword, byte[] realMessage,
            char[] realPassword, int totalBytes) throws GeneralSecurityException {
        Objects.requireNonNull(decoyMessage, "decoy message must not be null");
        Objects.requireNonNull(realMessage, "real message must not be null");
        try {
            requirePassword(decoyPassword, "decoy password");
            requirePassword(realPassword, "real password");
            if (decoyMessage.length == 0 || realMessage.length == 0) {
                throw new IllegalArgumentException("decoy and real messages must not be empty");
            }
            if (samePassword(decoyPassword, realPassword)) {
                throw new IllegalArgumentException("decoy and real passwords must be different");
            }
            if (totalBytes <= HEADER_LENGTH || totalBytes > MAX_CONTAINER_BYTES) {
                throw new IllegalArgumentException("container size must be between " + (HEADER_LENGTH + 1)
                        + " and " + MAX_CONTAINER_BYTES + " bytes");
            }
            byte[] realSeed = seedFromPassword(realPassword);
            char[] realPasswordForEncryption = Arrays.copyOf(realPassword, realPassword.length);
            byte[] framedDecoy = null;
            byte[] framedReal = null;
            byte[] decoyCiphertext = null;
            byte[] realCiphertext = null;
            try {
                framedDecoy = Payload.wrap(decoyMessage);
                framedReal = Payload.wrap(realMessage);
                decoyCiphertext = CryptoUtil.encrypt(framedDecoy, decoyPassword);
                realCiphertext = CryptoUtil.encrypt(framedReal, realPasswordForEncryption);
                long realBitCount = BitUtil.bitsForBytes(Integer.BYTES + realCiphertext.length);
                long requiredTotal = HEADER_LENGTH + (long) decoyCiphertext.length + realBitCount;
                if (requiredTotal > totalBytes) {
                    throw new IllegalArgumentException("container is too small: requires at least "
                            + requiredTotal + " bytes for these messages");
                }
                byte[] container = new byte[totalBytes];
                System.arraycopy(MAGIC, 0, container, 0, MAGIC.length);
                container[MAGIC.length] = (byte) VERSION;
                byte[] lengthBytes = BitUtil.unsignedIntToBigEndian(decoyCiphertext.length);
                System.arraycopy(lengthBytes, 0, container, MAGIC.length + 1, lengthBytes.length);
                int paddingOffset = HEADER_LENGTH + decoyCiphertext.length;
                System.arraycopy(decoyCiphertext, 0, container, HEADER_LENGTH, decoyCiphertext.length);
                byte[] padding = new byte[container.length - paddingOffset];
                RANDOM.nextBytes(padding);
                byte[] realStream = new byte[Integer.BYTES + realCiphertext.length];
                System.arraycopy(BitUtil.unsignedIntToBigEndian(realCiphertext.length), 0, realStream, 0,
                        Integer.BYTES);
                System.arraycopy(realCiphertext, 0, realStream, Integer.BYTES, realCiphertext.length);
                embedScatteredBits(padding, realStream, realSeed);
                System.arraycopy(padding, 0, container, paddingOffset, padding.length);
                clear(padding);
                clear(realStream);
                return container;
            } finally {
                clear(realSeed);
                clear(framedDecoy);
                clear(framedReal);
                clear(decoyCiphertext);
                clear(realCiphertext);
                clear(realPasswordForEncryption);
            }
        } finally {
            clear(decoyPassword);
            clear(realPassword);
        }
    }

    /**
     * Decrypts and CRC-validates the conventionally stored decoy message.
     * Password material is cleared after use. Wrong passwords or tampering
     * propagate the standard {@link javax.crypto.AEADBadTagException} path.
     *
     * @param container decoy-mode bytes
     * @param decoyPassword non-empty mutable decoy password
     * @return decoy message
     * @throws GeneralSecurityException if authenticated decryption fails
     */
    public static byte[] revealDecoy(byte[] container, char[] decoyPassword)
            throws GeneralSecurityException {
        requirePassword(decoyPassword, "decoy password");
        byte[] decrypted = null;
        try {
            ParsedContainer parsed = parse(container);
            byte[] ciphertext = Arrays.copyOfRange(container, HEADER_LENGTH, parsed.paddingOffset());
            try {
                decrypted = CryptoUtil.decrypt(ciphertext, decoyPassword);
                return Payload.unwrap(decrypted);
            } finally {
                clear(ciphertext);
            }
        } finally {
            clear(decrypted);
            clear(decoyPassword);
        }
    }

    /**
     * Reconstructs the password-scattered real ciphertext from random-looking
     * padding, decrypts it, and CRC-validates its inner StegoShield frame.
     * Password material is cleared after use.
     *
     * @param container decoy-mode bytes
     * @param realPassword non-empty mutable real password
     * @return real message
     * @throws GeneralSecurityException if authentication fails
     */
    public static byte[] revealReal(byte[] container, char[] realPassword)
            throws GeneralSecurityException {
        requirePassword(realPassword, "real password");
        byte[] seed = null;
        byte[] stream = null;
        byte[] decrypted = null;
        try {
            ParsedContainer parsed = parse(container);
            byte[] padding = Arrays.copyOfRange(container, parsed.paddingOffset(), container.length);
            seed = seedFromPassword(realPassword);
            stream = extractScatteredBytes(padding, Integer.BYTES, seed);
            long encryptedLength = BitUtil.readUnsignedIntBigEndian(stream, 0);
            long maximum = (padding.length - (long) Integer.SIZE) / Byte.SIZE;
            if (encryptedLength < CryptoUtil.minimumEncryptedLength() || encryptedLength > maximum) {
                throw new IllegalArgumentException("real-message length is invalid for this container or password");
            }
            byte[] ciphertext = extractScatteredBytes(padding,
                    Math.toIntExact(Integer.BYTES + encryptedLength), seed);
            try {
                decrypted = CryptoUtil.decrypt(Arrays.copyOfRange(ciphertext, Integer.BYTES, ciphertext.length),
                        realPassword);
                return Payload.unwrap(decrypted);
            } finally {
                clear(ciphertext);
                clear(padding);
            }
        } finally {
            clear(seed);
            clear(stream);
            clear(decrypted);
            clear(realPassword);
        }
    }

    /**
     * Returns the minimum fixed container size for supplied message lengths.
     * It includes framing, AES-GCM overhead, the real scattered stream, and no
     * optional extra random padding.
     *
     * @param decoyMessageBytes decoy plaintext length
     * @param realMessageBytes real plaintext length
     * @return minimum container byte count
     */
    public static long minimumContainerBytes(long decoyMessageBytes, long realMessageBytes) {
        if (decoyMessageBytes <= 0L || realMessageBytes <= 0L
                || decoyMessageBytes > Integer.MAX_VALUE - Payload.HEADER_LENGTH
                || realMessageBytes > Integer.MAX_VALUE - Payload.HEADER_LENGTH) {
            throw new IllegalArgumentException("message lengths must be positive and supported");
        }
        long decoyEncrypted = Payload.HEADER_LENGTH + decoyMessageBytes + CryptoUtil.minimumEncryptedLength();
        long realEncrypted = Payload.HEADER_LENGTH + realMessageBytes + CryptoUtil.minimumEncryptedLength();
        return HEADER_LENGTH + decoyEncrypted + BitUtil.bitsForBytes(Integer.BYTES + realEncrypted);
    }

    private static ParsedContainer parse(byte[] container) {
        Objects.requireNonNull(container, "decoy container must not be null");
        if (container.length < HEADER_LENGTH + CryptoUtil.minimumEncryptedLength()) {
            throw new IllegalArgumentException("decoy container is too short");
        }
        for (int index = 0; index < MAGIC.length; index++) {
            if (container[index] != MAGIC[index]) {
                throw new IllegalArgumentException("decoy container magic is missing");
            }
        }
        int version = Byte.toUnsignedInt(container[MAGIC.length]);
        if (version != VERSION) {
            throw new IllegalArgumentException("unsupported decoy container version: " + version);
        }
        long decoyLength = BitUtil.readUnsignedIntBigEndian(container, MAGIC.length + 1);
        if (decoyLength < CryptoUtil.minimumEncryptedLength()
                || decoyLength > container.length - (long) HEADER_LENGTH) {
            throw new IllegalArgumentException("decoy ciphertext length is invalid");
        }
        int paddingOffset = Math.toIntExact(HEADER_LENGTH + decoyLength);
        long paddingLength = container.length - (long) paddingOffset;
        if (paddingLength < Integer.SIZE + CryptoUtil.minimumEncryptedLength() * Byte.SIZE) {
            throw new IllegalArgumentException("decoy container lacks enough random padding for a real message");
        }
        return new ParsedContainer(paddingOffset);
    }

    private static void embedScatteredBits(byte[] padding, byte[] stream, byte[] seed) {
        long requiredBits = BitUtil.bitsForBytes(stream.length);
        if (requiredBits > padding.length) {
            throw new IllegalArgumentException("random padding is too short for real-message bits");
        }
        int[] positions = shuffledPositions(padding.length, seed);
        long bitIndex = 0L;
        for (byte value : stream) {
            int unsigned = Byte.toUnsignedInt(value);
            for (int shift = Byte.SIZE - 1; shift >= 0; shift--) {
                int position = positions[Math.toIntExact(bitIndex++)];
                padding[position] = (byte) ((padding[position] & 0xFE) | ((unsigned >>> shift) & 1));
            }
        }
        clear(positions);
    }

    private static byte[] extractScatteredBytes(byte[] padding, int byteCount, byte[] seed) {
        if (byteCount <= 0 || BitUtil.bitsForBytes(byteCount) > padding.length) {
            throw new IllegalArgumentException("requested scattered data exceeds padding capacity");
        }
        int[] positions = shuffledPositions(padding.length, seed);
        byte[] result = new byte[byteCount];
        long bitIndex = 0L;
        for (int byteIndex = 0; byteIndex < result.length; byteIndex++) {
            int value = 0;
            for (int bit = 0; bit < Byte.SIZE; bit++) {
                int position = positions[Math.toIntExact(bitIndex++)];
                value = (value << 1) | (padding[position] & 1);
            }
            result[byteIndex] = (byte) value;
        }
        clear(positions);
        return result;
    }

    private static int[] shuffledPositions(int length, byte[] seed) {
        if (length <= 0 || length > MAX_CONTAINER_BYTES) {
            throw new IllegalArgumentException("random padding length is unsupported");
        }
        int[] positions = new int[length];
        for (int index = 0; index < positions.length; index++) {
            positions[index] = index;
        }
        DeterministicRandom random = new DeterministicRandom(seed);
        for (int index = positions.length - 1; index > 0; index--) {
            int swapIndex = random.nextInt(index + 1);
            int position = positions[index];
            positions[index] = positions[swapIndex];
            positions[swapIndex] = position;
        }
        return positions;
    }

    private static byte[] seedFromPassword(char[] password) {
        byte[] passwordBytes = null;
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
            passwordBytes = new byte[encoded.remaining()];
            encoded.get(passwordBytes);
            return MessageDigest.getInstance("SHA-256").digest(passwordBytes);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("this JDK does not provide required SHA-256", exception);
        } finally {
            clear(passwordBytes);
        }
    }

    private static boolean samePassword(char[] first, char[] second) {
        if (first.length != second.length) {
            return false;
        }
        int difference = 0;
        for (int index = 0; index < first.length; index++) {
            difference |= first[index] ^ second[index];
        }
        return difference == 0;
    }

    private static void requirePassword(char[] password, String description) {
        Objects.requireNonNull(password, description + " must not be null");
        if (password.length == 0) {
            clear(password);
            throw new IllegalArgumentException(description + " must not be empty");
        }
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

    private static void clear(int[] values) {
        if (values != null) {
            Arrays.fill(values, 0);
        }
    }

    private record ParsedContainer(int paddingOffset) {
    }

    /**
     * SHA-256 counter-mode byte source for deterministic Fisher-Yates shuffling.
     */
    private static final class DeterministicRandom {
        private final byte[] seed;
        private byte[] block = new byte[0];
        private int blockOffset;
        private long counter;

        private DeterministicRandom(byte[] seed) {
            this.seed = Objects.requireNonNull(seed, "password seed must not be null");
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
            return ((long) nextByte() << 24) | ((long) nextByte() << 16)
                    | ((long) nextByte() << 8) | nextByte();
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
                    throw new IllegalStateException("decoy scatter counter exhausted");
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
