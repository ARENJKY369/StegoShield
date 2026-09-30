package core;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/** Runtime build identity included in exported reports for traceability. */
public final class AppInfo {
    /** Human-readable application version. */
    public static final String VERSION = "1.0";
    private static final long GIT_TIMEOUT_SECONDS = 2L;

    private AppInfo() {
        // Constants and runtime metadata only.
    }

    /**
     * Returns a supplied build property or the current checkout commit hash.
     * Packaged builds can pass {@code -Dstegoshield.commit=<hash>}.
     *
     * @return commit hash, or {@code unknown} outside a Git checkout
     */
    public static String commitHash() {
        String supplied = System.getProperty("stegoshield.commit", "").strip();
        if (!supplied.isEmpty()) {
            return supplied;
        }
        Process process = null;
        try {
            process = new ProcessBuilder("git", "rev-parse", "HEAD")
                    .directory(new File(System.getProperty("user.dir", ".")))
                    .redirectErrorStream(true)
                    .start();
            if (!process.waitFor(GIT_TIMEOUT_SECONDS, TimeUnit.SECONDS) || process.exitValue() != 0) {
                return "unknown";
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    process.getInputStream(), StandardCharsets.UTF_8))) {
                String line = reader.readLine();
                return line == null || line.isBlank() ? "unknown" : line.strip();
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return "unknown";
        } catch (IOException | SecurityException exception) {
            return "unknown";
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }
}
