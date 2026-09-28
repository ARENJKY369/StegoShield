package analysis;

import audio.LSBAudioStego;
import audio.WavData;
import eof.PngEofStego;
import eof.PngMetadataStego;
import image.LSBImageStego;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Objects;
import text.ZeroWidthStego;

/**
 * Performs controlled extraction attempts for formats that StegoShield knows.
 * It does not execute recovered content and it intentionally avoids guessing a
 * password for password-scattered or encrypted payloads.
 */
public final class ExtractionService {
    /**
     * Attempts known extraction paths in a safe order for one file.
     *
     * @param file carrier candidate
     * @return first successful recovery or an explanation of failed attempts
     */
    public ExtractionAttempt attempt(File file) {
        if (file == null || !file.isFile()) {
            return ExtractionAttempt.failure("Input validation", "Select a readable regular file first.");
        }
        try {
            byte[] header = readHeader(file, 16);
            FileSignature signature = FileSignature.detect(header);
            return switch (signature) {
                case PNG -> attemptPng(file);
                case BMP -> attemptSequentialImage(file);
                case WAV -> attemptWav(file);
                default -> attemptText(file);
            };
        } catch (IOException exception) {
            return ExtractionAttempt.failure("File access", safeMessage(exception));
        }
    }

    private ExtractionAttempt attemptPng(File file) {
        try {
            byte[] trailing = PngEofStego.extractAfterIend(file);
            if (trailing.length > 0) {
                return ExtractionAttempt.success("PNG trailing bytes after IEND", trailing);
            }
        } catch (IOException | IllegalArgumentException exception) {
            return ExtractionAttempt.failure("PNG trailing bytes", safeMessage(exception));
        }
        String metadataMessage;
        try {
            byte[] metadata = PngMetadataStego.extractFromTextChunk(file);
            return ExtractionAttempt.success("PNG tEXt metadata", metadata);
        } catch (IOException | IllegalArgumentException exception) {
            metadataMessage = safeMessage(exception);
        }
        ExtractionAttempt imageAttempt = attemptSequentialImage(file);
        if (imageAttempt.successful()) {
            return imageAttempt;
        }
        return ExtractionAttempt.failure("PNG extraction", "No PNG trailing payload was found. Metadata attempt: "
                + metadataMessage + ". Sequential LSB attempt: " + imageAttempt.message());
    }

    private ExtractionAttempt attemptSequentialImage(File file) {
        try {
            BufferedImage image = LSBImageStego.readCarrier(file);
            try (LSBImageStego stego = LSBImageStego.sequential()) {
                return ExtractionAttempt.success("Sequential RGB LSB", stego.extract(image));
            }
        } catch (IOException | IllegalArgumentException exception) {
            return ExtractionAttempt.failure("Sequential RGB LSB", safeMessage(exception));
        }
    }

    private ExtractionAttempt attemptWav(File file) {
        try {
            WavData wav = LSBAudioStego.readWav(file);
            return ExtractionAttempt.success("16-bit PCM WAV LSB", new LSBAudioStego().extract(wav));
        } catch (IOException | IllegalArgumentException exception) {
            return ExtractionAttempt.failure("16-bit PCM WAV LSB", safeMessage(exception));
        }
    }

    private ExtractionAttempt attemptText(File file) {
        try {
            long size = Files.size(file.toPath());
            if (size > AnalysisConstants.MAX_TEXT_ANALYSIS_BYTES) {
                return ExtractionAttempt.failure("Zero-width text", "Text extraction is limited to "
                        + AnalysisConstants.MAX_TEXT_ANALYSIS_BYTES + " bytes for memory safety.");
            }
            String text = strictUtf8(Files.readAllBytes(file.toPath()));
            if (text == null) {
                return ExtractionAttempt.failure("Zero-width text", "File is not valid UTF-8 text.");
            }
            return ExtractionAttempt.success("Zero-width Unicode", new ZeroWidthStego().extract(text));
        } catch (IOException | IllegalArgumentException exception) {
            return ExtractionAttempt.failure("Zero-width text", safeMessage(exception));
        }
    }

    private static byte[] readHeader(File file, int maximum) throws IOException {
        try (java.io.InputStream input = Files.newInputStream(file.toPath())) {
            return input.readNBytes(maximum);
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

    private static String safeMessage(Exception exception) {
        Objects.requireNonNull(exception, "exception must not be null");
        String message = exception.getMessage();
        return message == null || message.isBlank() ? exception.getClass().getSimpleName() : message;
    }
}
