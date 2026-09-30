package analysis;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.Collection;
import java.util.Comparator;
import java.util.Objects;
import core.AppInfo;

/**
 * Exports one or more explainable scan reports as UTF-8 plain text.
 */
public final class ReportExporter {
    private ReportExporter() {
        // Utility class.
    }

    /**
     * Writes one report to a new or existing text file in UTF-8.
     *
     * @param report report to export
     * @param output destination file
     * @return output file
     * @throws IOException if writing fails
     */
    public static File export(ScanReport report, File output) throws IOException {
        Objects.requireNonNull(report, "report must not be null");
        validateOutput(output);
        Files.writeString(output.toPath(), report.toText(), StandardCharsets.UTF_8);
        return output;
    }

    /**
     * Writes reports sorted from highest to lowest risk, then filename, to UTF-8 text.
     *
     * @param reports reports to export
     * @param output destination file
     * @return output file
     * @throws IOException if writing fails
     */
    public static File exportBatch(Collection<ScanReport> reports, File output) throws IOException {
        Objects.requireNonNull(reports, "reports must not be null");
        validateOutput(output);
        StringBuilder text = new StringBuilder("StegoShield batch scan report\n\n");
        reports.stream()
                .sorted(Comparator.comparingInt(ScanReport::riskScore).reversed()
                        .thenComparing(report -> report.file().getAbsolutePath()))
                .forEach(report -> text.append(report.toText()).append('\n'));
        Files.writeString(output.toPath(), text.toString(), StandardCharsets.UTF_8);
        return output;
    }

    /**
     * Writes a traceable session report beside the scanned file. The destination
     * is never overwritten; numeric suffixes are added when necessary.
     *
     * @param report scan whose findings are exported
     * @param classification most recent blind or authenticated classification, or null
     * @return newly created report file
     * @throws IOException if writing fails
     */
    public static File exportSession(ScanReport report, PayloadClassifier.Classification classification)
            throws IOException {
        Objects.requireNonNull(report, "report must not be null");
        File output = uniqueSessionOutput(report.file());
        StringBuilder text = new StringBuilder();
        text.append("StegoShield Session Report\n");
        text.append("==========================\n");
        text.append("App version: ").append(AppInfo.VERSION).append('\n');
        text.append("Git commit: ").append(AppInfo.commitHash()).append("\n\n");
        text.append("File name: ").append(report.file().getName()).append('\n');
        text.append("File path: ").append(report.file().getAbsolutePath()).append('\n');
        text.append("File size: ").append(report.fileSize()).append(" bytes\n");
        text.append("Detected signature/type: ").append(report.detectedSignature().displayName()).append('\n');
        text.append("Risk score: ").append(report.riskScore()).append("/100\n");
        text.append("Risk label: ").append(report.riskLevel().displayName()).append('\n');
        text.append("Scan timestamp: ").append(report.scannedAt()).append("\n\n");
        text.append("Findings:\n");
        for (Finding finding : report.findings()) {
            text.append("- [+").append(finding.points()).append("] ")
                    .append(finding.test()).append(": ").append(finding.reason()).append('\n');
        }
        text.append("\nPayload classification:\n");
        if (classification == null) {
            text.append("Not produced for this file.\n");
        } else {
            text.append(classification.toText());
        }
        Files.writeString(output.toPath(), text.toString(), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        return output;
    }

    private static File uniqueSessionOutput(File scannedFile) throws IOException {
        File absolute = scannedFile.getAbsoluteFile();
        File parent = absolute.getParentFile();
        if (parent == null || !parent.isDirectory()) {
            throw new IOException("scanned file has no writable parent folder: " + scannedFile);
        }
        String name = absolute.getName();
        int dot = name.lastIndexOf('.');
        String stem = dot > 0 ? name.substring(0, dot) : name;
        File candidate = new File(parent, stem + "-report.txt");
        int suffix = 2;
        while (candidate.exists()) {
            candidate = new File(parent, stem + "-report-" + suffix++ + ".txt");
        }
        return candidate;
    }

    private static void validateOutput(File output) throws IOException {
        if (output == null) {
            throw new IllegalArgumentException("report output file must not be null");
        }
        if (output.isDirectory()) {
            throw new IOException("report output path is a directory: " + output);
        }
        File parent = output.getAbsoluteFile().getParentFile();
        if (parent != null && !parent.isDirectory()) {
            throw new IOException("report output directory does not exist: " + parent);
        }
    }
}
