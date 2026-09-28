package analysis;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * Folder scanner that walks regular files and returns reports sorted by
 * descending risk. {@link #scanAsync(File, Listener)} performs the walk in a
 * daemon background thread; UI callers must marshal callbacks onto AWT's event
 * thread themselves.
 */
public final class BatchScanner {
    private final StegoScanner scanner;

    /**
     * Creates a batch scanner using a fresh default file scanner.
     */
    public BatchScanner() {
        this(new StegoScanner());
    }

    /**
     * Creates a batch scanner using the supplied scanner.
     *
     * @param scanner scanner to invoke per file
     */
    public BatchScanner(StegoScanner scanner) {
        this.scanner = Objects.requireNonNull(scanner, "scanner must not be null");
    }

    /**
     * Recursively scans a folder synchronously and sorts reports from highest
     * to lowest risk. Individual-file failures become zero-score reports with
     * explicit error findings so they are not silently lost.
     *
     * @param folder existing directory
     * @return sorted scan reports
     * @throws IOException if walking the directory fails
     */
    public List<ScanReport> scanFolder(File folder) throws IOException {
        validateFolder(folder);
        List<ScanReport> reports = new ArrayList<>();
        try (Stream<Path> paths = Files.walk(folder.toPath())) {
            paths.filter(Files::isRegularFile).forEach(path -> reports.add(scanOne(path.toFile())));
        }
        reports.sort(reportOrder());
        return List.copyOf(reports);
    }

    /**
     * Starts a daemon background thread that scans a folder. Callback methods
     * are executed on that worker thread and are never invoked after an
     * unhandled folder-walk failure except {@link Listener#onFailure(Exception)}.
     *
     * @param folder existing directory
     * @param listener progress and completion callback
     * @return started worker thread
     */
    public Thread scanAsync(File folder, Listener listener) {
        validateFolderUnchecked(folder);
        Objects.requireNonNull(listener, "batch listener must not be null");
        Thread worker = new Thread(() -> {
            try {
                List<ScanReport> reports = scanFolderWithProgress(folder, listener);
                listener.onComplete(reports);
            } catch (Exception exception) {
                listener.onFailure(exception);
            }
        }, "StegoShield-BatchScan");
        worker.setDaemon(true);
        worker.start();
        return worker;
    }

    private List<ScanReport> scanFolderWithProgress(File folder, Listener listener) throws IOException {
        validateFolder(folder);
        List<ScanReport> reports = new ArrayList<>();
        try (Stream<Path> paths = Files.walk(folder.toPath())) {
            paths.filter(Files::isRegularFile).forEach(path -> {
                ScanReport report = scanOne(path.toFile());
                reports.add(report);
                listener.onFileScanned(report);
            });
        }
        reports.sort(reportOrder());
        return List.copyOf(reports);
    }

    private ScanReport scanOne(File file) {
        try {
            return scanner.scan(file);
        } catch (IOException | RuntimeException exception) {
            String message = exception.getMessage();
            if (message == null || message.isBlank()) {
                message = exception.getClass().getSimpleName();
            }
            return ScanReport.failure(file, message);
        }
    }

    private static Comparator<ScanReport> reportOrder() {
        return Comparator.comparingInt(ScanReport::riskScore).reversed()
                .thenComparing(report -> report.file().getAbsolutePath());
    }

    private static void validateFolder(File folder) throws IOException {
        if (folder == null) {
            throw new IllegalArgumentException("batch scan folder must not be null");
        }
        if (!folder.isDirectory()) {
            throw new IOException("batch scan target is not a directory: " + folder);
        }
    }

    private static void validateFolderUnchecked(File folder) {
        if (folder == null || !folder.isDirectory()) {
            throw new IllegalArgumentException("batch scan target must be an existing directory");
        }
    }

    /**
     * Receives asynchronous batch progress. Implementations must be thread-safe
     * and UI implementations should use EventQueue.invokeLater.
     */
    public interface Listener {
        /**
         * Called after each file scan, including individual failure reports.
         *
         * @param report per-file result
         */
        void onFileScanned(ScanReport report);

        /**
         * Called once after all reports have been sorted by descending risk.
         *
         * @param reports immutable sorted result list
         */
        void onComplete(List<ScanReport> reports);

        /**
         * Called when the folder itself cannot be walked.
         *
         * @param exception root failure
         */
        void onFailure(Exception exception);
    }
}
