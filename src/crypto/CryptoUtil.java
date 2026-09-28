package crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Offline authenticated encryption for StegoShield payloads.
 *
 * <p>Encryption uses AES-256-GCM with a PBKDF2WithHmacSHA256 password-derived
 * key. Ciphertext layout is {@code salt | IV | ciphertext-and-GCM-tag}; the
 * salt is 16 random bytes and the IV is 12 random bytes. Callers supply a
 * mutable password array because this class clears it after every operation.
 * On decrypt, an {@link AEADBadTagException} indicates a wrong password or
 * tampering and must be handled as one deliberately indistinguishable error.</p>
 */
public final class CryptoUtil {
    /** Number of PBKDF2 rounds, intentionally at least the project minimum. */
    public static final int PBKDF2_ITERATIONS = 65_536;
    /** AES key size used by this application. */
    public static final int AES_KEY_BITS = 256;
    /** Random salt size in bytes. */
    public static final int SALT_LENGTH = 16;
    /** GCM IV size in bytes, recommended for GCM. */
    public static final int IV_LENGTH = 12;
    /** GCM authentication tag size in bits. */
    public static final int GCM_TAG_BITS = 128;
    /** Authentication tag size in bytes. */
    public static final int GCM_TAG_LENGTH = GCM_TAG_BITS / Byte.SIZE;
    /** Number of bytes before ciphertext in the serialized output. */
    public static final int ENCRYPTED_PREFIX_LENGTH = SALT_LENGTH + IV_LENGTH;

    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";
    private static final SecureRandom RANDOM = new SecureRandom();

    private CryptoUtil() {
        // Utility class.
    }

    /**
     * Encrypts bytes with a password-derived AES-256-GCM key.
     *
     * <p>This method clears {@code password} before returning or throwing. It
     * never writes plaintext or password material to logs.</p>
     *
     * @param plaintext bytes to encrypt, including zero-length data when needed
     * @param password mutable, non-empty password characters
     * @return {@code salt | IV | ciphertext-and-tag}
     * @throws GeneralSecurityException if the JDK crypto provider fails
     */
    public static byte[] encrypt(byte[] plaintext, char[] password) throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "plaintext must not be null");
        requirePassword(password);
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        byte[] keyBytes = null;
        try {
            RANDOM.nextBytes(salt);
            RANDOM.nextBytes(iv);
            keyBytes = deriveKey(password, salt);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, KEY_ALGORITHM),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ciphertextAndTag = cipher.doFinal(plaintext);
            byte[] result = new byte[ENCRYPTED_PREFIX_LENGTH + ciphertextAndTag.length];
            System.arraycopy(salt, 0, result, 0, SALT_LENGTH);
            System.arraycopy(iv, 0, result, SALT_LENGTH, IV_LENGTH);
            System.arraycopy(ciphertextAndTag, 0, result, ENCRYPTED_PREFIX_LENGTH,
                    ciphertextAndTag.length);
            return result;
        } finally {
            clear(keyBytes);
            clear(password);
        }
    }

    /**
     * Decrypts and authenticates bytes produced by {@link #encrypt(byte[], char[])}.
     *
     * <p>This method clears {@code password} before returning or throwing. A
     * wrong password or altered ciphertext causes {@link AEADBadTagException};
     * callers should present one generic, user-friendly failure message rather
     * than trying to distinguish those cases.</p>
     *
     * @param encrypted {@code salt | IV | ciphertext-and-tag}
     * @param password mutable, non-empty password characters
     * @return authenticated plaintext
     * @throws AEADBadTagException if authentication fails
     * @throws GeneralSecurityException if the JDK crypto provider fails
     */
    public static byte[] decrypt(byte[] encrypted, char[] password)
            throws GeneralSecurityException {
        Objects.requireNonNull(encrypted, "encrypted data must not be null");
        requirePassword(password);
        if (encrypted.length < ENCRYPTED_PREFIX_LENGTH + GCM_TAG_LENGTH) {
            clear(password);
            throw new IllegalArgumentException("encrypted data is too short to contain salt, IV, and GCM tag");
        }
        byte[] salt = Arrays.copyOfRange(encrypted, 0, SALT_LENGTH);
        byte[] iv = Arrays.copyOfRange(encrypted, SALT_LENGTH, ENCRYPTED_PREFIX_LENGTH);
        byte[] keyBytes = null;
        try {
            keyBytes = deriveKey(password, salt);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, KEY_ALGORITHM),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            return cipher.doFinal(encrypted, ENCRYPTED_PREFIX_LENGTH,
                    encrypted.length - ENCRYPTED_PREFIX_LENGTH);
        } finally {
            clear(keyBytes);
            clear(password);
        }
    }

    /**
     * Returns the smallest valid encrypted message size for quick validation.
     *
     * @return bytes required for salt, IV, and an empty-message GCM tag
     */
    public static int minimumEncryptedLength() {
        return ENCRYPTED_PREFIX_LENGTH + GCM_TAG_LENGTH;
    }

    private static byte[] deriveKey(char[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec specification = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, AES_KEY_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
            return factory.generateSecret(specification).getEncoded();
        } finally {
            specification.clearPassword();
        }
    }

    private static void requirePassword(char[] password) {
        Objects.requireNonNull(password, "password must not be null");
        if (password.length == 0) {
            clear(password);
            throw new IllegalArgumentException("password must not be empty");
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
}
