package analysis;

import audio.LSBAudioStego;
import audio.WavData;
import image.LSBImageStego;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import text.ZeroWidthStego;

/**
 * Offline, explainable heuristic steganalysis scanner. It reports evidence and
 * risk rather than claiming malware detection or certainty. Low embedding
 * rates, adaptive/scattered techniques, unusual legitimate files, and formats
 * outside the implemented checks can evade or confuse these heuristics.
 */
public final class StegoScanner {
    /**
     * Scans one regular file and returns a bounded, explainable risk report.
     * Files larger than the configured deep-analysis limit still receive magic
     * and extension checks, but deep byte/image/text analysis is skipped safely.
     *
     * @param file file to scan
     * @return immutable report
     * @throws IOException if file access fails
     */
    public ScanReport scan(File file) throws IOException {
        validateFile(file);
        long size = Files.size(file.toPath());
        byte[] header = readHeader(file, 16);
        FileSignature signature = FileSignature.detect(header);
        ScanReport.Builder report = new ScanReport.Builder(file, size, signature);
        checkMagicExtensionMismatch(file, signature, report);
        if (size > AnalysisConstants.MAX_IN_MEMORY_ANALYSIS_BYTES) {
            report.add("Analysis scope", 0, "File is " + size + " bytes; deep byte analysis is limited to "
                    + AnalysisConstants.MAX_IN_MEMORY_ANALYSIS_BYTES + " bytes for memory safety.");
            return report.build();
        }
        byte[] bytes = Files.readAllBytes(file.toPath());
        if (signature == FileSignature.PNG) {
            inspectPng(bytes, report);
        } else if (signature == FileSignature.JPEG) {
            inspectJpegTrailing(bytes, report);
        }
        if (signature == FileSignature.PNG || signature == FileSignature.BMP) {
            inspectImageLsb(file, report);
        }
        if (signature == FileSignature.WAV) {
            inspectWavLsb(file, report);
        }
        inspectInvisibleUnicode(bytes, report);
        return report.build();
    }

    private static void inspectPng(byte[] bytes, ScanReport.Builder report) {
        try {
            List<eof.PngUtil.Chunk> chunks = eof.PngUtil.parseChunks(bytes);
            int iendEnd = eof.PngUtil.iendEnd(bytes);
            inspectTrailing(bytes, iendEnd, "PNG IEND", report);
            long textBytes = 0L;
            boolean oversizedChunk = false;
            for (eof.PngUtil.Chunk chunk : chunks) {
                if ("tEXt".equals(chunk.type()) || "zTXt".equals(chunk.type()) || "iTXt".equals(chunk.type())) {
                    textBytes += chunk.dataLength();
                    if (chunk.dataLength() > AnalysisConstants.OVERSIZED_PNG_TEXT_CHUNK_BYTES) {
                        oversizedChunk = true;
                    }
                }
            }
            if (oversizedChunk || textBytes > AnalysisConstants.OVERSIZED_PNG_TEXT_TOTAL_BYTES) {
                report.add("PNG metadata size", AnalysisConstants.SCORE_OVERSIZED_METADATA,
                        "PNG textual metadata totals " + textBytes + " bytes"
                                + (oversizedChunk ? " and contains a chunk above "
                                + AnalysisConstants.OVERSIZED_PNG_TEXT_CHUNK_BYTES + " bytes." : "."));
            }
        } catch (IllegalArgumentException exception) {
            report.add("PNG structure", 0, "PNG chunk parsing could not complete: " + exception.getMessage());
        }
    }

    private static void inspectJpegTrailing(byte[] bytes, ScanReport.Builder report) {
        int end = findJpegEnd(bytes);
        if (end < 0) {
            report.add("JPEG structure", 0, "JPEG start marker was found but no FFD9 end marker was located.");
            return;
        }
        inspectTrailing(bytes, end, "JPEG FFD9", report);
    }

    private static void inspectTrailing(byte[] bytes, int carrierEnd, String carrierName,
            ScanReport.Builder report) {
        if (carrierEnd >= bytes.length) {
            return;
        }
        int trailingLength = bytes.length - carrierEnd;
        report.add("Trailing carrier data", AnalysisConstants.SCORE_TRAILING_DATA,
                trailingLength + " byte(s) occur after " + carrierName + ".");
        byte[] trailing = java.util.Arrays.copyOfRange(bytes, carrierEnd, bytes.length);
        double entropy = Entropy.shannonBitsPerByte(trailing);
        if (entropy >= AnalysisConstants.HIGH_ENTROPY_BITS_PER_BYTE) {
            report.add("Trailing data entropy", AnalysisConstants.SCORE_HIGH_ENTROPY_TRAILING_DATA,
                    String.format(Locale.ROOT, "Trailing bytes have Shannon entropy %.3f bits/byte, above %.1f.",
                            entropy, AnalysisConstants.HIGH_ENTROPY_BITS_PER_BYTE));
        }
        EnumSet<FileSignature> found = EnumSet.noneOf(FileSignature.class);
        for (int offset = carrierEnd; offset < bytes.length; offset++) {
            FileSignature embedded = FileSignature.detectAt(bytes, offset);
            if (embedded != null && isEmbeddedPayloadSignature(embedded) && found.add(embedded)) {
                report.add("Embedded file signature", AnalysisConstants.SCORE_EMBEDDED_SIGNATURE,
                        embedded.displayName() + " signature found " + (offset - carrierEnd)
                                + " byte(s) after the carrier boundary.");
            }
        }
    }

    private static boolean isEmbeddedPayloadSignature(FileSignature signature) {
        return signature == FileSignature.ZIP || signature == FileSignature.WINDOWS_EXECUTABLE
                || signature == FileSignature.PDF || signature == FileSignature.ELF;
    }

    private static void inspectImageLsb(File file, ScanReport.Builder report) {
        try {
            BufferedImage image = LSBImageStego.readCarrier(file);
            long pixels = (long) image.getWidth() * image.getHeight();
            if (pixels < AnalysisConstants.MIN_IMAGE_PIXELS_FOR_STATISTICS) {
                report.add("Image statistical scope", 0, "Image has only " + pixels
                        + " pixels; chi-square and LSB randomness checks were skipped.");
                return;
            }
            ChiSquareResult chiSquare = ImageStatistics.pairOfValuesChiSquare(image);
            if (chiSquare.degreesOfFreedom() >= AnalysisConstants.MIN_CHI_SQUARE_DEGREES_OF_FREEDOM) {
                ChiSquareSweep sweep = ImageStatistics.pairOfValuesPrefixSweep(image,
                        AnalysisConstants.CHI_SQUARE_SWEEP_STEP_SAMPLES,
                        AnalysisConstants.CHI_SQUARE_EQUALIZED_Z);
                boolean sweepTriggered = sweep.equalizedSamples()
                        >= AnalysisConstants.CHI_SQUARE_SWEEP_MIN_PREFIX_SAMPLES
                        && sweep.equalizedFraction() >= AnalysisConstants.CHI_SQUARE_SWEEP_MIN_FRACTION;
                if (sweepTriggered) {
                    report.add("Chi-square pair-of-values", AnalysisConstants.SCORE_CHI_SQUARE_SWEEP,
                            String.format(Locale.ROOT, "Chi-square prefix sweep: the first %.1f%% of "
                                    + "%s-channel samples (%d of %d) have adjacent value pairs consistent "
                                    + "with equalization (z=%.3f at or below +%.1f), matching sequential "
                                    + "LSB replacement of random-looking data; the global combined "
                                    + "z-score is %.3f (df=%d).",
                                    sweep.equalizedFraction() * 100.0d, sweep.channelName(),
                                    sweep.equalizedSamples(), sweep.channelSamples(), sweep.zScore(),
                                    AnalysisConstants.CHI_SQUARE_EQUALIZED_Z, chiSquare.zScore(),
                                    chiSquare.degreesOfFreedom()));
                } else if (chiSquare.zScore() <= AnalysisConstants.CHI_SQUARE_SUSPICIOUS_Z) {
                    report.add("Chi-square pair-of-values", AnalysisConstants.SCORE_CHI_SQUARE,
                            String.format(Locale.ROOT, "Chi-square z-score %.3f (df=%d) is at or below %.1f; "
                                    + "adjacent RGB value pairs are unusually equalized.", chiSquare.zScore(),
                                    chiSquare.degreesOfFreedom(), AnalysisConstants.CHI_SQUARE_SUSPICIOUS_Z));
                } else {
                    report.add("Chi-square pair-of-values", 0,
                            String.format(Locale.ROOT, "Chi-square z-score %.3f (df=%d) is above %.1f and no "
                                    + "channel has an equalized sample prefix; adjacent RGB value pairs "
                                    + "are not unusually equalized.", chiSquare.zScore(),
                                    chiSquare.degreesOfFreedom(), AnalysisConstants.CHI_SQUARE_SUSPICIOUS_Z));
                }
            }
            LsbStatistics lsb = ImageStatistics.lsbStatistics(image, AnalysisConstants.IMAGE_LSB_BLOCK_SIZE);
            if (Math.abs(lsb.balanceZ()) <= AnalysisConstants.LSB_BALANCE_Z_LIMIT
                    && lsb.blockCount() >= AnalysisConstants.MIN_IMAGE_BLOCKS
                    && lsb.balancedBlockFraction() >= AnalysisConstants.BALANCED_BLOCK_FRACTION) {
                report.add("Image LSB randomness", AnalysisConstants.SCORE_IMAGE_LSB_RANDOMNESS,
                        String.format(Locale.ROOT, "RGB LSB balance z-score %.3f; %.1f%% of %d blocks are "
                                + "near-even (threshold %.1f%%).", lsb.balanceZ(),
                                lsb.balancedBlockFraction() * 100.0d, lsb.blockCount(),
                                AnalysisConstants.BALANCED_BLOCK_FRACTION * 100.0d));
            }
        } catch (IOException | IllegalArgumentException exception) {
            report.add("Image LSB analysis", 0, "Image statistical checks were unavailable: "
                    + safeMessage(exception));
        }
    }

    private static void inspectWavLsb(File file, ScanReport.Builder report) {
        try {
            WavData wav = LSBAudioStego.readWav(file);
            long samples = wav.sampleCount();
            if (samples < AnalysisConstants.MIN_WAV_SAMPLES_FOR_STATISTICS) {
                report.add("WAV statistical scope", 0, "WAV has only " + samples
                        + " samples; LSB randomness check was skipped.");
                return;
            }
            byte[] pcm = wav.pcmBytes();
            long oneBits = 0L;
            for (int byteIndex = 0; byteIndex < pcm.length; byteIndex += Short.BYTES) {
                oneBits += pcm[byteIndex] & 1;
            }
            double zScore = ImageStatistics.balanceZ(oneBits, samples);
            if (Math.abs(zScore) <= AnalysisConstants.LSB_BALANCE_Z_LIMIT) {
                report.add("WAV LSB randomness", AnalysisConstants.SCORE_WAV_LSB_RANDOMNESS,
                        String.format(Locale.ROOT, "PCM sample LSB balance z-score %.3f across %d samples is "
                                + "close to one-half.", zScore, samples));
            }
        } catch (IOException | IllegalArgumentException exception) {
            report.add("WAV LSB analysis", 0, "WAV statistical checks were unavailable: "
                    + safeMessage(exception));
        }
    }

    private static void inspectInvisibleUnicode(byte[] bytes, ScanReport.Builder report) {
        if (bytes.length > AnalysisConstants.MAX_TEXT_ANALYSIS_BYTES) {
            return;
        }
        String text = strictUtf8(bytes);
        if (text == null) {
            return;
        }
        ZeroWidthStego.InvisibleCharacterReport invisible = ZeroWidthStego.detectInvisibleCharacters(text);
        if (invisible.totalCount() > 0L) {
            report.add("Invisible Unicode", AnalysisConstants.SCORE_INVISIBLE_UNICODE,
                    "Found " + invisible.totalCount() + " monitored invisible character(s): U+200B="
                            + invisible.zeroBitCount() + ", U+200C=" + invisible.oneBitCount()
                            + ", U+200D=" + invisible.zeroWidthJoinerCount() + ", U+2060="
                            + invisible.wordJoinerCount() + ", U+FEFF="
                            + invisible.zeroWidthNoBreakSpaceCount() + ".");
        }
    }

    private static void checkMagicExtensionMismatch(File file, FileSignature signature,
            ScanReport.Builder report) {
        String extension = extensionOf(file.getName());
        if (signature != FileSignature.UNKNOWN && !extension.isEmpty()
                && !signature.matchesExtension(extension)) {
            report.add("Magic byte versus extension", AnalysisConstants.SCORE_MAGIC_EXTENSION_MISMATCH,
                    "Leading bytes identify " + signature.displayName() + " but filename extension is ."
                            + extension + ".");
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

    private static int findJpegEnd(byte[] bytes) {
        if (bytes.length < 4 || (bytes[0] & 0xFF) != 0xFF || (bytes[1] & 0xFF) != 0xD8) {
            return -1;
        }
        for (int index = 2; index < bytes.length - 1; index++) {
            if ((bytes[index] & 0xFF) == 0xFF && (bytes[index + 1] & 0xFF) == 0xD9) {
                return index + 2;
            }
        }
        return -1;
    }

    private static byte[] readHeader(File file, int maximumBytes) throws IOException {
        try (InputStream input = Files.newInputStream(file.toPath())) {
            return input.readNBytes(maximumBytes);
        }
    }

    private static void validateFile(File file) throws IOException {
        Objects.requireNonNull(file, "scan file must not be null");
        if (!file.isFile()) {
            throw new IOException("scan target is not a readable regular file: " + file);
        }
    }

    private static String extensionOf(String name) {
        int dot = name.lastIndexOf('.');
        if (dot <= 0 || dot == name.length() - 1) {
            return "";
        }
        return name.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    private static String safeMessage(Exception exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank() ? exception.getClass().getSimpleName() : message;
    }
}
