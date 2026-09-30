package test;

import analysis.ScanReport;
import analysis.StegoScanner;
import core.Payload;
import crypto.CryptoUtil;
import decoy.DecoyMode;
import eof.PngEofStego;
import image.EmbeddingMode;
import image.ImageMetrics;
import image.LSBImageStego;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Comparator;
import javax.crypto.AEADBadTagException;
import javax.imageio.ImageIO;
import sanitize.StegoCleaner;

/**
 * JDK-only self-test suite with a plain {@code main} method. It creates all
 * carriers in a temporary directory, uses no testing framework, prints each
 * completed case, and exits non-zero if any assertion fails.
 */
public final class StegoShieldSelfTest {
    private static final SecureRandom RANDOM = new SecureRandom();

    private StegoShieldSelfTest() {
        // Utility class.
    }

    /**
     * Runs core integration checks for embedding, encryption, cleaning, and scanning.
     *
     * @param arguments ignored
     */
    public static void main(String[] arguments) {
        Path temporaryDirectory = null;
        try {
            temporaryDirectory = Files.createTempDirectory("stegoshield-self-test-");
            testImageHideExtractRoundTrip();
            testImageFileRoundTrips(temporaryDirectory);
            testPlacementAutoDetectionAndDifference();
            testNoDecoyPayloadIdentification();
            testWrongPassword();
            testOversizePayload();
            testJpegOutputRejection(temporaryDirectory);
            testCleanThenExtractFailure(temporaryDirectory);
            testScannerCleanStegoAndAppendedData(temporaryDirectory);
            System.out.println("ALL STEGOSHIELD SELF-TESTS PASSED");
        } catch (Exception exception) {
            System.err.println("SELF-TEST FAILED: " + safeMessage(exception));
            exception.printStackTrace(System.err);
            System.exit(1);
        } finally {
            if (temporaryDirectory != null) {
                try {
                    deleteRecursively(temporaryDirectory);
                } catch (IOException exception) {
                    System.err.println("Could not remove self-test temporary directory: " + safeMessage(exception));
                }
            }
        }
    }

    private static void testImageHideExtractRoundTrip() throws GeneralSecurityException {
        BufferedImage carrier = patternedCarrier(96, 96);
        byte[] message = "Round-trip message: offline and authenticated.".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = null;
        byte[] extracted = null;
        byte[] decrypted = null;
        try {
            encrypted = CryptoUtil.encrypt(Payload.wrap(message), "correct horse battery staple".toCharArray());
            try (LSBImageStego stego = LSBImageStego.sequential()) {
                BufferedImage embedded = stego.embed(carrier, encrypted);
                extracted = stego.extract(embedded);
            }
            decrypted = CryptoUtil.decrypt(extracted, "correct horse battery staple".toCharArray());
            byte[] recovered = Payload.unwrap(decrypted);
            try {
                require(Arrays.equals(message, recovered), "image hide/extract round trip changed the message");
            } finally {
                clear(recovered);
            }
            System.out.println("PASS: image hide/extract round trip");
        } finally {
            clear(encrypted);
            clear(extracted);
            clear(decrypted);
            clear(message);
        }
    }

    private static void testImageFileRoundTrips(Path directory) throws Exception {
        BufferedImage carrier = patternedCarrier(128, 128);
        File carrierFile = directory.resolve("workflow-carrier.png").toFile();
        File sequentialFile = directory.resolve("workflow-sequential.png").toFile();
        File scatteredFile = directory.resolve("workflow-scattered.png").toFile();
        LSBImageStego.writePng(carrier, carrierFile);
        String message = "GUI workflow encrypted round-trip";
        for (boolean scattered : new boolean[] {false, true}) {
            byte[] encrypted = null;
            try {
                encrypted = CryptoUtil.encrypt(Payload.wrap(message.getBytes(StandardCharsets.UTF_8)),
                        "workflow-password".toCharArray());
                BufferedImage loaded = LSBImageStego.readCarrier(carrierFile);
                File output = scattered ? scatteredFile : sequentialFile;
                try (LSBImageStego stego = scattered
                        ? LSBImageStego.passwordScattered("workflow-password".toCharArray())
                        : LSBImageStego.sequential()) {
                    require(encrypted.length <= stego.capacityBytes(loaded), "encrypted workflow payload exceeds capacity");
                    BufferedImage embedded = stego.embed(loaded, encrypted);
                    File actual = LSBImageStego.writePng(embedded, output);
                    require(actual.isFile(), "generated workflow PNG was not saved");
                    BufferedImage reloaded = LSBImageStego.readCarrier(actual);
                    EmbeddingMode expectedMode = scattered
                            ? EmbeddingMode.PASSWORD_SCATTERED : EmbeddingMode.SEQUENTIAL;
                    require(LSBImageStego.inspectHeader(reloaded).mode() == expectedMode,
                            "image header did not preserve placement mode");
                    byte[] extracted = LSBImageStego.extractAutomatically(reloaded,
                            "workflow-password".toCharArray());
                    byte[] decrypted = CryptoUtil.decrypt(extracted, "workflow-password".toCharArray());
                    byte[] recovered = Payload.unwrap(decrypted);
                    require(message.equals(new String(recovered, StandardCharsets.UTF_8)),
                            "image file workflow round-trip changed the message");
                    clear(extracted);
                    clear(decrypted);
                    clear(recovered);
                }
            } finally {
                clear(encrypted);
            }
        }
        require(ImageIO.read(sequentialFile) != null && ImageIO.read(scatteredFile) != null,
                "saved workflow outputs could not be reloaded");
        System.out.println("PASS: sequential and password-scattered PNG workflow round trips");
    }

    private static void testPlacementAutoDetectionAndDifference() throws Exception {
        BufferedImage carrier = patternedCarrier(128, 128);
        byte[] encrypted = CryptoUtil.encrypt(
                Payload.wrap("auto-detected scattered placement".getBytes(StandardCharsets.UTF_8)),
                "placement-password".toCharArray());
        byte[] extracted = null;
        byte[] decrypted = null;
        try {
            BufferedImage embedded;
            try (LSBImageStego stego = LSBImageStego.passwordScattered(
                    "placement-password".toCharArray())) {
                embedded = stego.embed(carrier, encrypted);
            }
            require(LSBImageStego.inspectHeader(embedded).mode() == EmbeddingMode.PASSWORD_SCATTERED,
                    "scattered placement flag was not detected from the public header");
            extracted = LSBImageStego.extractAutomatically(embedded, "placement-password".toCharArray());
            decrypted = CryptoUtil.decrypt(extracted, "placement-password".toCharArray());
            byte[] recovered = Payload.unwrap(decrypted);
            String result = new String(recovered, StandardCharsets.UTF_8);
            clear(recovered);
            require("auto-detected scattered placement".equals(result),
                    "automatic scattered extraction changed the message");

            BufferedImage difference = ImageMetrics.amplifiedDifference(carrier, embedded, 20.0d);
            boolean visibleChange = false;
            for (int y = 0; y < difference.getHeight() && !visibleChange; y++) {
                for (int x = 0; x < difference.getWidth(); x++) {
                    if ((difference.getRGB(x, y) & 0x00FF_FFFF) != 0) {
                        visibleChange = true;
                        break;
                    }
                }
            }
            require(visibleChange, "amplified LSB difference image was solid black");
            System.out.println("PASS: placement auto-detected as password-scattered; extraction result: " + result);
            System.out.println("PASS: LSB amplified difference contains visible non-black pixel noise"
                    + " (MSE " + ImageMetrics.meanSquaredError(carrier, embedded) + ")");
        } finally {
            clear(encrypted);
            clear(extracted);
            clear(decrypted);
        }
    }

    private static void testNoDecoyPayloadIdentification() {
        byte[] standard = {0x01, 0x02, 0x03, 0x04};
        require(!DecoyMode.hasMagic(standard), "standard payload was misidentified as a decoy container");
        String error = DecoyMode.hasMagic(standard) ? "" : "no decoy payload found";
        require("no decoy payload found".equals(error), "missing-decoy error was not specific");
        System.out.println("PASS: standard payload in decoy reveal mode reports: no decoy payload found");
    }

    private static void testWrongPassword() throws GeneralSecurityException {
        byte[] encrypted = null;
        try {
            encrypted = CryptoUtil.encrypt(Payload.wrap("secret".getBytes(StandardCharsets.UTF_8)),
                    "correct-password".toCharArray());
            boolean rejected = false;
            try {
                CryptoUtil.decrypt(encrypted, "wrong-password".toCharArray());
            } catch (AEADBadTagException exception) {
                rejected = true;
            }
            require(rejected, "wrong password did not raise AEADBadTagException");
            System.out.println("PASS: wrong password authentication failure");
        } finally {
            clear(encrypted);
        }
    }

    private static void testOversizePayload() {
        BufferedImage tinyCarrier = patternedCarrier(8, 8);
        try (LSBImageStego stego = LSBImageStego.sequential()) {
            long capacity = stego.capacityBytes(tinyCarrier);
            require(capacity > 0L, "tiny test carrier unexpectedly has zero capacity");
            boolean rejected = false;
            try {
                stego.embed(tinyCarrier, new byte[Math.toIntExact(capacity + 1L)]);
            } catch (IllegalArgumentException exception) {
                rejected = true;
            }
            require(rejected, "oversize image payload was accepted");
        }
        System.out.println("PASS: oversize payload rejection");
    }

    private static void testJpegOutputRejection(Path directory) throws IOException {
        File forbiddenOutput = directory.resolve("lossy-output.jpg").toFile();
        boolean rejected = false;
        try {
            LSBImageStego.writePng(patternedCarrier(32, 32), forbiddenOutput);
        } catch (IllegalArgumentException exception) {
            rejected = true;
        }
        require(rejected, "JPEG output filename was not rejected");
        require(!forbiddenOutput.exists(), "JPEG rejection created an output file");
        System.out.println("PASS: JPEG output rejection");
    }

    private static void testCleanThenExtractFailure(Path directory) throws Exception {
        BufferedImage carrier = patternedCarrier(96, 96);
        byte[] encrypted = null;
        File stegoFile = directory.resolve("clean-source.png").toFile();
        File cleanedFile = directory.resolve("cleaned.png").toFile();
        try {
            encrypted = CryptoUtil.encrypt(Payload.wrap("remove me".getBytes(StandardCharsets.UTF_8)),
                    "clean-test-password".toCharArray());
            try (LSBImageStego stego = LSBImageStego.sequential()) {
                BufferedImage embedded = stego.embed(carrier, encrypted);
                LSBImageStego.writePng(embedded, stegoFile);
            }
            new StegoCleaner(new StegoScanner()).clean(stegoFile, cleanedFile);
            boolean originalRecovered = false;
            try {
                BufferedImage cleaned = LSBImageStego.readCarrier(cleanedFile);
                byte[] randomized = null;
                byte[] decrypted = null;
                try (LSBImageStego stego = LSBImageStego.sequential()) {
                    randomized = stego.extract(cleaned);
                    decrypted = CryptoUtil.decrypt(randomized, "clean-test-password".toCharArray());
                    byte[] recovered = Payload.unwrap(decrypted);
                    originalRecovered = Arrays.equals("remove me".getBytes(StandardCharsets.UTF_8), recovered);
                    clear(recovered);
                } finally {
                    clear(randomized);
                    clear(decrypted);
                }
            } catch (AEADBadTagException | IllegalArgumentException exception) {
                originalRecovered = false;
            }
            require(!originalRecovered, "sanitized image still yielded the original authenticated message");
            System.out.println("PASS: clean-then-extract failure");
        } finally {
            clear(encrypted);
        }
    }

    private static void testScannerCleanStegoAndAppendedData(Path directory) throws Exception {
        BufferedImage carrier = patternedCarrier(96, 96);
        File cleanFile = directory.resolve("clean.png").toFile();
        File stegoFile = directory.resolve("stego.png").toFile();
        File appendedFile = directory.resolve("appended.png").toFile();
        LSBImageStego.writePng(carrier, cleanFile);
        try (LSBImageStego stego = LSBImageStego.sequential()) {
            byte[] fullPayload = new byte[Math.toIntExact(stego.capacityBytes(carrier))];
            Arrays.fill(fullPayload, (byte) 0xAA);
            BufferedImage embedded = stego.embed(carrier, fullPayload);
            LSBImageStego.writePng(embedded, stegoFile);
            clear(fullPayload);
        }
        byte[] appended = new byte[4_096];
        RANDOM.nextBytes(appended);
        appended[0] = 0x50;
        appended[1] = 0x4B;
        appended[2] = 0x03;
        appended[3] = 0x04;
        try {
            PngEofStego.appendAfterIend(cleanFile, appended, appendedFile);
        } finally {
            clear(appended);
        }
        StegoScanner scanner = new StegoScanner();
        ScanReport clean = scanner.scan(cleanFile);
        ScanReport stego = scanner.scan(stegoFile);
        ScanReport appendedReport = scanner.scan(appendedFile);
        require(clean.riskScore() <= 24, "clean control image was unexpectedly flagged: " + clean.riskScore());
        require(stego.riskScore() > clean.riskScore(), "stego image did not score above clean control");
        require(appendedReport.riskScore() >= 60,
                "appended-data PNG was not strongly flagged: " + appendedReport.riskScore());
        System.out.println("PASS: scanner clean vs stego vs appended-data comparison");
        System.out.println("VERIFY risk scores: clean=" + clean.riskScore() + "/100, LSB="
                + stego.riskScore() + "/100, appended=" + appendedReport.riskScore() + "/100");
    }

    private static BufferedImage patternedCarrier(int width, int height) {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int red = (x * 2) & 0xFE;
                int green = (y * 2) & 0xFE;
                int blue = ((x + y) * 2) & 0xFE;
                image.setRGB(x, y, (red << 16) | (green << 8) | blue);
            }
        }
        return image;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void deleteRecursively(Path root) throws IOException {
        try (java.util.stream.Stream<Path> paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException exception) {
                    throw new DeleteFailure(exception);
                }
            });
        } catch (DeleteFailure failure) {
            throw failure.getCause();
        }
    }

    private static String safeMessage(Exception exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank() ? exception.getClass().getSimpleName() : message;
    }

    private static void clear(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static final class DeleteFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;

        private DeleteFailure(IOException cause) {
            super(cause);
        }

        @Override
        public IOException getCause() {
            return (IOException) super.getCause();
        }
    }
}
