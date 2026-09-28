package sanitize;

import analysis.AnalysisConstants;
import analysis.FileSignature;
import analysis.ScanReport;
import analysis.StegoScanner;
import audio.LSBAudioStego;
import audio.WavData;
import image.LSBImageStego;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Objects;
import javax.imageio.ImageIO;
import text.ZeroWidthStego;

/**
 * Non-destructive carrier sanitizer. It always creates a distinct output file:
 * images are decoded and re-encoded as PNG with randomized RGB LSBs, text has
 * monitored invisible Unicode removed, and supported WAV sample LSBs are
 * randomized. It then re-scans the newly written copy for transparent feedback.
 */
public final class StegoCleaner {
    private static final SecureRandom RANDOM = new SecureRandom();

    private final StegoScanner scanner;

    /**
     * Creates a cleaner with a default scanner for before/after reports.
     */
    public StegoCleaner() {
        this(new StegoScanner());
    }

    /**
     * Creates a cleaner with a supplied scanner.
     *
     * @param scanner scanner used before and after cleaning
     */
    public StegoCleaner(StegoScanner scanner) {
        this.scanner = Objects.requireNonNull(scanner, "scanner must not be null");
    }

    /**
     * Cleans a supported file type and scans the newly written output. JPEG,
     * BMP, and PNG images are re-encoded as lossless PNG; only PNG output names
     * are accepted for image cleaning.
     *
     * @param source original file, never modified
     * @param requestedOutput distinct target file
     * @return cleaning details and before/after reports
     * @throws IOException if reading, writing, validation, or re-scanning fails
     */
    public SanitizationResult clean(File source, File requestedOutput) throws IOException {
        validateSource(source);
        ScanReport before = scanner.scan(source);
        FileSignature signature = detectSignature(source);
        return switch (signature) {
            case PNG, JPEG, BMP -> cleanImage(source, requestedOutput, before);
            case WAV -> cleanWav(source, requestedOutput, before);
            default -> cleanText(source, requestedOutput, before);
        };
    }

    private SanitizationResult cleanImage(File source, File requestedOutput, ScanReport before)
            throws IOException {
        File output = LSBImageStego.pngOutputFile(requestedOutput);
        validateDistinct(source, output);
        BufferedImage image = readImage(source);
        BufferedImage cleaned = randomizeImageLsbs(image);
        File written = LSBImageStego.writePng(cleaned, output);
        ScanReport after = scanner.scan(written);
        return new SanitizationResult(source, written,
                "Decoded and re-encoded image as PNG; metadata/trailing bytes were dropped and RGB LSBs randomized.",
                before, after);
    }

    private SanitizationResult cleanWav(File source, File output, ScanReport before) throws IOException {
        validateDistinct(source, output);
        WavData wav = LSBAudioStego.readWav(source);
        byte[] pcm = wav.pcmBytes();
        for (int index = 0; index < pcm.length; index += Short.BYTES) {
            pcm[index] = (byte) ((pcm[index] & 0xFE) | (RANDOM.nextBoolean() ? 1 : 0));
        }
        File written = LSBAudioStego.writeWav(new WavData(wav.format(), pcm), output);
        ScanReport after = scanner.scan(written);
        return new SanitizationResult(source, written,
                "Randomized every supported 16-bit PCM sample LSB while preserving the WAV AudioFormat.", before,
                after);
    }

    private SanitizationResult cleanText(File source, File output, ScanReport before) throws IOException {
        validateDistinct(source, output);
        long size = Files.size(source.toPath());
        if (size > AnalysisConstants.MAX_TEXT_ANALYSIS_BYTES) {
            throw new IOException("UTF-8 text cleaning is limited to "
                    + AnalysisConstants.MAX_TEXT_ANALYSIS_BYTES + " bytes for memory safety");
        }
        byte[] bytes = Files.readAllBytes(source.toPath());
        String text = strictUtf8(bytes);
        if (text == null) {
            throw new IOException("unsupported file type: only PNG, JPEG, BMP, 16-bit PCM WAV, or valid UTF-8 text can be cleaned");
        }
        String cleaned = ZeroWidthStego.stripInvisibleCharacters(text);
        Files.writeString(output.toPath(), cleaned, StandardCharsets.UTF_8);
        ScanReport after = scanner.scan(output);
        return new SanitizationResult(source, output,
                "Removed U+200B through U+200D, U+2060, and U+FEFF from UTF-8 text.", before, after);
    }

    /**
     * Makes a TYPE_INT_RGB copy and independently randomizes each red, green,
     * and blue least-significant bit using {@link SecureRandom}. LSBs are never
     * zeroed, because all-zero replacement itself creates an obvious pattern.
     *
     * @param source decoded image
     * @return sanitized RGB image
     */
    public static BufferedImage randomizeImageLsbs(BufferedImage source) {
        Objects.requireNonNull(source, "image source must not be null");
        if (source.getWidth() <= 0 || source.getHeight() <= 0) {
            throw new IllegalArgumentException("image dimensions must be positive");
        }
        BufferedImage cleaned = new BufferedImage(source.getWidth(), source.getHeight(), BufferedImage.TYPE_INT_RGB);
        Graphics2D graphics = cleaned.createGraphics();
        try {
            graphics.drawImage(source, 0, 0, null);
        } finally {
            graphics.dispose();
        }
        for (int y = 0; y < cleaned.getHeight(); y++) {
            for (int x = 0; x < cleaned.getWidth(); x++) {
                int rgb = cleaned.getRGB(x, y);
                rgb = replaceBit(rgb, 16, RANDOM.nextBoolean());
                rgb = replaceBit(rgb, 8, RANDOM.nextBoolean());
                rgb = replaceBit(rgb, 0, RANDOM.nextBoolean());
                cleaned.setRGB(x, y, rgb);
            }
        }
        return cleaned;
    }

    private static int replaceBit(int rgb, int shift, boolean one) {
        return (rgb & ~(1 << shift)) | ((one ? 1 : 0) << shift);
    }

    private static BufferedImage readImage(File source) throws IOException {
        try (BufferedInputStream input = new BufferedInputStream(new FileInputStream(source))) {
            BufferedImage image = ImageIO.read(input);
            if (image == null) {
                throw new IOException("image source cannot be decoded: " + source);
            }
            return image;
        }
    }

    private static FileSignature detectSignature(File source) throws IOException {
        try (java.io.InputStream input = Files.newInputStream(source.toPath())) {
            return FileSignature.detect(input.readNBytes(16));
        }
    }

    private static String strictUtf8(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException exception) {
            return null;
        }
    }

    private static void validateSource(File source) throws IOException {
        if (source == null) {
            throw new IllegalArgumentException("cleaning source must not be null");
        }
        if (!source.isFile()) {
            throw new IOException("cleaning source is not a readable regular file: " + source);
        }
    }

    private static void validateDistinct(File source, File output) throws IOException {
        if (output == null) {
            throw new IllegalArgumentException("cleaning output file must not be null");
        }
        if (output.isDirectory()) {
            throw new IOException("cleaning output path is a directory: " + output);
        }
        File parent = output.getAbsoluteFile().getParentFile();
        if (parent != null && !parent.isDirectory()) {
            throw new IOException("cleaning output directory does not exist: " + parent);
        }
        if (source.getCanonicalFile().equals(output.getCanonicalFile())) {
            throw new IllegalArgumentException("cleaning output must differ from source; original files are never modified");
        }
    }
}
