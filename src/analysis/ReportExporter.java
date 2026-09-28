package analysis;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collection;
import java.util.Comparator;
import java.util.Objects;

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
