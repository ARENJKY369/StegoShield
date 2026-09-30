package analysis;

import java.io.File;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Immutable explainable outcome of one file scan. The score is capped at one
 * hundred, while every individual finding remains available for review.
 */
public final class ScanReport {
    private final File file;
    private final long fileSize;
    private final FileSignature detectedSignature;
    private final int riskScore;
    private final RiskLevel riskLevel;
    private final List<Finding> findings;
    private final Instant scannedAt;

    ScanReport(File file, long fileSize, FileSignature detectedSignature, int riskScore,
            List<Finding> findings, Instant scannedAt) {
        this.file = Objects.requireNonNull(file, "scan file must not be null");
        if (fileSize < 0L) {
            throw new IllegalArgumentException("file size must not be negative");
        }
        this.fileSize = fileSize;
        this.detectedSignature = Objects.requireNonNull(detectedSignature, "signature must not be null");
        if (riskScore < 0 || riskScore > 100) {
            throw new IllegalArgumentException("risk score must be between 0 and 100");
        }
        this.riskScore = riskScore;
        riskLevel = RiskLevel.fromScore(riskScore);
        this.findings = List.copyOf(Objects.requireNonNull(findings, "findings must not be null"));
        this.scannedAt = Objects.requireNonNull(scannedAt, "scan time must not be null");
    }

    /**
     * Returns the scanned file.
     *
     * @return scanned file
     */
    public File file() {
        return file;
    }

    /**
     * Returns size captured at scan time.
     *
     * @return file byte length
     */
    public long fileSize() {
        return fileSize;
    }

    /**
     * Returns the recognized leading signature, if any.
     *
     * @return detected signature
     */
    public FileSignature detectedSignature() {
        return detectedSignature;
    }

    /**
     * Returns capped zero-to-one-hundred risk score.
     *
     * @return risk score
     */
    public int riskScore() {
        return riskScore;
    }

    /**
     * Returns the label derived from {@link #riskScore()}.
     *
     * @return risk level
     */
    public RiskLevel riskLevel() {
        return riskLevel;
    }

    /**
     * Returns immutable triggered-test explanations.
     *
     * @return findings list
     */
    public List<Finding> findings() {
        return findings;
    }

    /**
     * Returns the scanner timestamp.
     *
     * @return scan timestamp
     */
    public Instant scannedAt() {
        return scannedAt;
    }

    /**
     * Renders this report in a stable, plain-text format for export.
     *
     * @return report text using line-feed separators
     */
    public String toText() {
        String lineSeparator = "\n";
        StringBuilder text = new StringBuilder();
        text.append("File: ").append(file.getAbsolutePath()).append(lineSeparator);
        text.append("Size: ").append(fileSize).append(" bytes").append(lineSeparator);
        text.append("Detected signature: ").append(detectedSignature.displayName()).append(lineSeparator);
        text.append("Risk score: ").append(riskScore).append("/100").append(lineSeparator);
        text.append("Risk label: ").append(riskLevel.displayName()).append(lineSeparator);
        text.append("Scanned at: ").append(scannedAt).append(lineSeparator);
        text.append("Findings:").append(lineSeparator);
        for (Finding finding : findings) {
            text.append("- [+").append(finding.points()).append("] ")
                    .append(finding.test()).append(": ")
                    .append(finding.reason()).append(lineSeparator);
        }
        return text.toString();
    }

    /**
     * Creates a report that records an individual-file analysis failure without
     * hiding the error from batch users.
     *
     * @param file file that could not be scanned
     * @param message user-safe failure reason
     * @return zero-score error report
     */
    public static ScanReport failure(File file, String message) {
        Objects.requireNonNull(file, "file must not be null");
        Objects.requireNonNull(message, "failure message must not be null");
        return new ScanReport(file, Math.max(0L, file.length()), FileSignature.UNKNOWN, 0,
                List.of(new Finding("Scan error", 0, message)), Instant.now());
    }

    /** Package-private mutable collector used by {@link StegoScanner}. */
    static final class Builder {
        private final File file;
        private final long size;
        private final FileSignature signature;
        private final List<Finding> findings = new ArrayList<>();
        private int rawScore;

        Builder(File file, long size, FileSignature signature) {
            this.file = Objects.requireNonNull(file, "file must not be null");
            this.size = size;
            this.signature = Objects.requireNonNull(signature, "signature must not be null");
            rawScore = 0;
        }

        void add(String test, int points, String reason) {
            findings.add(new Finding(test, points, reason));
            rawScore = Math.addExact(rawScore, points);
        }

        ScanReport build() {
            if (findings.isEmpty() || findings.stream().noneMatch(finding -> finding.points() > 0)) {
                findings.add(new Finding("Heuristic summary", 0,
                        "No implemented steganography indicators were triggered."));
            }
            return new ScanReport(file, size, signature, Math.min(100, rawScore), findings, Instant.now());
        }
    }
}
