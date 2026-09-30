package demo;

import core.Payload;
import crypto.CryptoUtil;
import eof.PngEofStego;
import image.LSBImageStego;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.FileTime;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/** Creates a fixed, deterministic set of safe demonstration carriers. */
public final class SampleFileGenerator {
    /** Password shared by both encrypted image-LSB demonstration payloads. */
    public static final String DEMO_PASSWORD = "demo1234";
    /** Names generated on every successful invocation. */
    public static final List<String> SAMPLE_NAMES = List.of(
            "sample_clean.png",
            "sample_text_hidden.png",
            "sample_script_hidden.png",
            "sample_appended_zip.png",
            "sample_wrong_extension.png");

    private static final int WIDTH = 128;
    private static final int HEIGHT = 64;
    private static final byte[] TEXT_SALT = fixedBytes(0x11, CryptoUtil.SALT_LENGTH);
    private static final byte[] TEXT_IV = fixedBytes(0x31, CryptoUtil.IV_LENGTH);
    private static final byte[] SCRIPT_SALT = fixedBytes(0x51, CryptoUtil.SALT_LENGTH);
    private static final byte[] SCRIPT_IV = fixedBytes(0x71, CryptoUtil.IV_LENGTH);

    private SampleFileGenerator() {
        // Utility class.
    }

    /**
     * Chooses {@code samples/} beside the development output directory or jar.
     *
     * @param anchor class loaded from the application output or jar
     * @return default sample directory
     */
    public static File defaultDirectory(Class<?> anchor) {
        Objects.requireNonNull(anchor, "anchor class must not be null");
        try {
            File location = new File(anchor.getProtectionDomain().getCodeSource().getLocation().toURI());
            File base = location.isFile() ? location.getParentFile() : location.getAbsoluteFile().getParentFile();
            if (base != null) {
                return new File(base, "samples");
            }
        } catch (Exception ignored) {
            // Fall back to the process working directory below.
        }
        return new File(System.getProperty("user.dir", "."), "samples");
    }

    /**
     * Regenerates all five samples, replacing only the known sample filenames.
     * Fixed pixels, salts, IVs, timestamps, and content make output repeatable.
     *
     * @param directory destination sample folder
     * @return generated files in documented order
     */
    public static List<File> generate(File directory) throws IOException, GeneralSecurityException {
        Objects.requireNonNull(directory, "sample directory must not be null");
        Files.createDirectories(directory.toPath());
        if (!directory.isDirectory()) {
            throw new IOException("sample output is not a directory: " + directory);
        }

        BufferedImage clean = baseImage();
        File cleanFile = new File(directory, SAMPLE_NAMES.get(0));
        LSBImageStego.writePng(clean, cleanFile);

        File textFile = new File(directory, SAMPLE_NAMES.get(1));
        writeHidden(clean,
                "StegoShield deterministic hidden-text sample. This harmless demo text is padded to make "
                        + "the sequential LSB prefix large enough for the scanner's statistical lesson.",
                TEXT_SALT, TEXT_IV, textFile);

        File scriptFile = new File(directory, SAMPLE_NAMES.get(2));
        writeHidden(clean,
                "powershell.exe -NoProfile -EncodedCommand ZABlAG0AbwAxADIAMwA= # deterministic safe demo; "
                        + "the remaining printable padding exists only to exercise sequential LSB detection.",
                SCRIPT_SALT, SCRIPT_IV, scriptFile);

        byte[] zip = deterministicZip();
        try {
            PngEofStego.appendAfterIend(cleanFile, zip, new File(directory, SAMPLE_NAMES.get(3)));
            Files.write(new File(directory, SAMPLE_NAMES.get(4)).toPath(), zip);
        } finally {
            Arrays.fill(zip, (byte) 0);
        }
        return SAMPLE_NAMES.stream().map(name -> new File(directory, name)).toList();
    }

    private static BufferedImage baseImage() {
        BufferedImage image = new BufferedImage(WIDTH, HEIGHT, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < HEIGHT; y++) {
            for (int x = 0; x < WIDTH; x++) {
                // Even samples give clean, deliberately imbalanced LSBs while
                // retaining a colorful deterministic gradient.
                int red = (x * 2) & 0xFE;
                int green = (y * 2) & 0xFE;
                int blue = ((x + y) * 2) & 0xFE;
                image.setRGB(x, y, (red << 16) | (green << 8) | blue);
            }
        }
        return image;
    }

    private static void writeHidden(BufferedImage clean, String message, byte[] salt, byte[] iv, File output)
            throws GeneralSecurityException, IOException {
        byte[] framed = Payload.wrap(message.getBytes(StandardCharsets.UTF_8));
        byte[] encrypted = deterministicEncrypt(framed, salt, iv);
        try (LSBImageStego stego = LSBImageStego.sequential()) {
            LSBImageStego.writePng(stego.embed(clean, encrypted), output);
        } finally {
            Arrays.fill(framed, (byte) 0);
            Arrays.fill(encrypted, (byte) 0);
        }
    }

    /** Demo-only deterministic encryption compatible with CryptoUtil.decrypt. */
    private static byte[] deterministicEncrypt(byte[] plaintext, byte[] salt, byte[] iv)
            throws GeneralSecurityException {
        PBEKeySpec specification = new PBEKeySpec(DEMO_PASSWORD.toCharArray(), salt,
                CryptoUtil.PBKDF2_ITERATIONS, CryptoUtil.AES_KEY_BITS);
        byte[] key = null;
        try {
            key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(specification).getEncoded();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(CryptoUtil.GCM_TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] result = new byte[CryptoUtil.ENCRYPTED_PREFIX_LENGTH + ciphertext.length];
            System.arraycopy(salt, 0, result, 0, salt.length);
            System.arraycopy(iv, 0, result, CryptoUtil.SALT_LENGTH, iv.length);
            System.arraycopy(ciphertext, 0, result, CryptoUtil.ENCRYPTED_PREFIX_LENGTH, ciphertext.length);
            Arrays.fill(ciphertext, (byte) 0);
            return result;
        } finally {
            specification.clearPassword();
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }
        }
    }

    private static byte[] deterministicZip() throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes, StandardCharsets.UTF_8)) {
            ZipEntry entry = new ZipEntry("demo.txt");
            FileTime epoch = FileTime.fromMillis(0L);
            entry.setTime(0L);
            entry.setCreationTime(epoch);
            entry.setLastAccessTime(epoch);
            entry.setLastModifiedTime(epoch);
            zip.putNextEntry(entry);
            zip.write("StegoShield deterministic ZIP sample.\n".getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return bytes.toByteArray();
    }

    private static byte[] fixedBytes(int start, int length) {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.length; index++) {
            bytes[index] = (byte) (start + index);
        }
        return bytes;
    }
}
