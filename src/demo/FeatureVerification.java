package demo;

import analysis.BatchScanner;
import analysis.PayloadClassifier;
import analysis.ReportExporter;
import analysis.ScanReport;
import core.Payload;
import crypto.CryptoUtil;
import image.LSBImageStego;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;

/** Command-line verification for deterministic samples and session export. */
public final class FeatureVerification {
    private FeatureVerification() {
        // Main-only utility.
    }

    /**
     * Generates samples, prints their sorted risks, extracts the script sample,
     * and prints the exact exported session report.
     *
     * @param arguments optional sample directory
     * @throws Exception when any generation, scan, extraction, or export step fails
     */
    public static void main(String[] arguments) throws Exception {
        File directory = arguments.length == 0
                ? SampleFileGenerator.defaultDirectory(FeatureVerification.class)
                : new File(arguments[0]);
        List<File> generated = SampleFileGenerator.generate(directory);
        if (generated.size() != SampleFileGenerator.SAMPLE_NAMES.size()
                || generated.stream().anyMatch(file -> !file.isFile())) {
            throw new IllegalStateException("not all five sample files were generated");
        }
        System.out.println("Generated samples: " + directory.getAbsolutePath());
        for (File file : generated) {
            System.out.println("- " + file.getName());
        }

        List<ScanReport> reports = new BatchScanner().scanFolder(directory);
        System.out.println("\nSorted sample risk table:");
        System.out.printf("%-34s %8s  %s%n", "File", "Risk", "Label");
        System.out.println("--------------------------------------------------------------------------");
        for (ScanReport report : reports) {
            System.out.printf("%-34s %7d/100  %s%n", report.file().getName(), report.riskScore(),
                    report.riskLevel().displayName());
        }

        File script = new File(directory, "sample_script_hidden.png");
        BufferedImage image = LSBImageStego.readCarrier(script);
        byte[] encrypted = null;
        byte[] framed = null;
        byte[] plaintext = null;
        PayloadClassifier.Classification classification;
        try {
            encrypted = LSBImageStego.extractAutomatically(image,
                    SampleFileGenerator.DEMO_PASSWORD.toCharArray());
            framed = CryptoUtil.decrypt(encrypted, SampleFileGenerator.DEMO_PASSWORD.toCharArray());
            plaintext = Payload.unwrap(framed);
            classification = PayloadClassifier.classifyAuthenticated(plaintext);
            System.out.println("\nExtraction result: " + new String(plaintext, StandardCharsets.UTF_8));
            System.out.println(classification.toText());
        } finally {
            clear(encrypted);
            clear(framed);
            clear(plaintext);
        }

        ScanReport scriptReport = reports.stream()
                .filter(report -> report.file().getName().equals(script.getName()))
                .findFirst().orElseThrow();
        File exported = ReportExporter.exportSession(scriptReport, classification);
        System.out.println("Exact session report: " + exported.getAbsolutePath());
        System.out.println("----- REPORT BEGIN -----");
        System.out.print(Files.readString(exported.toPath(), StandardCharsets.UTF_8));
        System.out.println("----- REPORT END -----");
    }

    private static void clear(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }
}
