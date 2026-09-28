package analysis;

/**
 * Central, intentionally easy-to-tune thresholds and score contributions for
 * StegoShield's explainable heuristic scanner. These values are indicators,
 * not proof of hidden content or malware.
 */
public final class AnalysisConstants {
    /** Highest score labelled CLEAN. */
    public static final int CLEAN_MAX_SCORE = 24;
    /** Highest score labelled SUSPICIOUS. */
    public static final int SUSPICIOUS_MAX_SCORE = 59;
    /** Entropy at or above this value suggests compressed or encrypted bytes. */
    public static final double HIGH_ENTROPY_BITS_PER_BYTE = 7.5d;
    /** Minimum image pixel count before statistical image tests are meaningful. */
    public static final long MIN_IMAGE_PIXELS_FOR_STATISTICS = 4_096L;
    /** Minimum active histogram pairs needed for a chi-square z-score. */
    public static final int MIN_CHI_SQUARE_DEGREES_OF_FREEDOM = 8;
    /** Negative chi-square z-score at or below this implies unusually equal pairs. */
    public static final double CHI_SQUARE_SUSPICIOUS_Z = -3.0d;
    /** Absolute global LSB balance z-score considered unusually close to one-half. */
    public static final double LSB_BALANCE_Z_LIMIT = 2.0d;
    /** Side length in pixels for image LSB block statistics and heatmaps. */
    public static final int IMAGE_LSB_BLOCK_SIZE = 32;
    /** Minimum image blocks before block-wise results influence the score. */
    public static final int MIN_IMAGE_BLOCKS = 8;
    /** Fraction of balanced blocks suggesting a broadly randomized LSB plane. */
    public static final double BALANCED_BLOCK_FRACTION = 0.75d;
    /** Minimum WAV samples before a WAV LSB randomness result is considered. */
    public static final long MIN_WAV_SAMPLES_FOR_STATISTICS = 4_096L;
    /** PNG text/metadata chunk size that is unusually large for ordinary metadata. */
    public static final long OVERSIZED_PNG_TEXT_CHUNK_BYTES = 65_536L;
    /** Aggregate PNG textual metadata size that is unusually large. */
    public static final long OVERSIZED_PNG_TEXT_TOTAL_BYTES = 131_072L;
    /** Maximum regular file size fully loaded for deep byte analysis. */
    public static final long MAX_IN_MEMORY_ANALYSIS_BYTES = 64L * 1024L * 1024L;
    /** Maximum bytes considered text for Unicode invisible-character detection. */
    public static final long MAX_TEXT_ANALYSIS_BYTES = 8L * 1024L * 1024L;

    /** Score for a recognized magic-byte signature contradicting file extension. */
    public static final int SCORE_MAGIC_EXTENSION_MISMATCH = 25;
    /** Score for data after a PNG IEND or JPEG EOI carrier boundary. */
    public static final int SCORE_TRAILING_DATA = 30;
    /** Additional score for high-entropy trailing bytes. */
    public static final int SCORE_HIGH_ENTROPY_TRAILING_DATA = 15;
    /** Score for a ZIP, executable, PDF, or ELF signature in trailing data. */
    public static final int SCORE_EMBEDDED_SIGNATURE = 35;
    /** Score for a suspicious low chi-square pair-of-values z-score. */
    public static final int SCORE_CHI_SQUARE = 18;
    /** Score for global and block-wise image LSB randomness indicators together. */
    public static final int SCORE_IMAGE_LSB_RANDOMNESS = 18;
    /** Score for monitored invisible Unicode characters. */
    public static final int SCORE_INVISIBLE_UNICODE = 35;
    /** Score for oversized PNG text or metadata chunk content. */
    public static final int SCORE_OVERSIZED_METADATA = 18;
    /** Score for unusually balanced WAV LSB values. */
    public static final int SCORE_WAV_LSB_RANDOMNESS = 18;

    private AnalysisConstants() {
        // Constants class.
    }
}
