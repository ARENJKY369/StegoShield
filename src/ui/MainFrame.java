package ui;

import analysis.AnalysisConstants;
import analysis.BatchScanner;
import analysis.ExtractionAttempt;
import analysis.ExtractionService;
import analysis.FileSignature;
import analysis.LsbHeatmap;
import analysis.LsbHeatmapCanvas;
import analysis.ReportExporter;
import analysis.ScanReport;
import analysis.StegoScanner;
import audio.LSBAudioStego;
import audio.WavData;
import core.Payload;
import crypto.CryptoUtil;
import decoy.DecoyMode;
import eof.PngEofStego;
import eof.PngMetadataStego;
import eof.PngUtil;
import eval.EvaluationResult;
import eval.EvaluationRunner;
import image.EmbeddingMode;
import image.ImageMetrics;
import image.LSBImageStego;
import network.CovertReceiver;
import network.CovertSender;
import network.TimingChannel;
import java.awt.BorderLayout;
import java.awt.Button;
import java.awt.CardLayout;
import java.awt.Checkbox;
import java.awt.Choice;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.FileDialog;
import java.awt.Frame;
import java.awt.GridLayout;
import java.awt.Label;
import java.awt.Panel;
import java.awt.TextArea;
import java.awt.TextField;
import java.awt.event.ItemEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.AEADBadTagException;
import text.ZeroWidthStego;
import sanitize.SanitizationResult;
import sanitize.StegoCleaner;

/**
 * Complete AWT front end for StegoShield's offline hide, extract, scan, clean,
 * batch, heatmap, report-export, and evaluation workflows. Every expensive
 * operation runs on a daemon worker and UI updates are marshalled through
 * {@link EventQueue#invokeLater(Runnable)}.
 */
public final class MainFrame extends Frame {
    private static final long serialVersionUID = 1L;
    private static final String HIDE_CARD = "hide";
    private static final String EXTRACT_CARD = "extract";
    private static final String SCAN_CARD = "scan";
    private static final String CLEAN_CARD = "clean";

    private final CardLayout cards;
    private final Panel cardPanel;
    private final TextArea statusArea;
    private final transient StegoScanner scanner;
    private final transient StegoCleaner cleaner;
    private final transient ExtractionService extractionService;

    private Choice hideKind;
    private Choice hidePlacement;
    private Checkbox decoyEnabled;
    private TextField hideSourceField;
    private TextArea hideMessage;
    private TextField hidePassword;
    private TextField decoyMessage;
    private TextField decoyPassword;
    private Label capacityLabel;
    private ImagePreviewCanvas previewCanvas;
    private File hideSource;

    private Choice extractPlacement;
    private Choice extractMode;
    private TextField extractSourceField;
    private TextField extractPassword;
    private TextArea extractResult;
    private File extractSource;

    private TextField scanSourceField;
    private TextArea scanReportArea;
    private Label riskLabel;
    private LsbHeatmapCanvas heatmapCanvas;
    private transient ScanReport latestReport;
    private transient List<ScanReport> latestBatch;

    private TextField cleanSourceField;
    private TextArea cleanResultArea;
    private File cleanSource;

    /**
     * Creates the main window and all four functional screens.
     */
    public MainFrame() {
        super("StegoShield — Offline Steganography and Steganalysis");
        scanner = new StegoScanner();
        cleaner = new StegoCleaner(scanner);
        extractionService = new ExtractionService();
        latestBatch = List.of();

        setLayout(new BorderLayout(6, 6));
        add(buildNavigation(), BorderLayout.NORTH);
        cards = new CardLayout();
        cardPanel = new Panel(cards);
        cardPanel.add(buildHideScreen(), HIDE_CARD);
        cardPanel.add(buildExtractScreen(), EXTRACT_CARD);
        cardPanel.add(buildScanScreen(), SCAN_CARD);
        cardPanel.add(buildCleanScreen(), CLEAN_CARD);
        add(cardPanel, BorderLayout.CENTER);
        statusArea = new TextArea("Ready. StegoShield operates only on files you own or are authorized to analyze.\n", 7,
                100, TextArea.SCROLLBARS_VERTICAL_ONLY);
        statusArea.setEditable(false);
        add(statusArea, BorderLayout.SOUTH);
        Theme.apply(this);
        statusArea.setBackground(Theme.TERMINAL);
        statusArea.setForeground(Theme.SUCCESS);
        statusArea.setRows(6);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent event) {
                dispose();
                System.exit(0);
            }
        });
        setMinimumSize(new Dimension(980, 760));
        setSize(1120, 860);
        cards.show(cardPanel, HIDE_CARD);
    }

    /**
     * Starts the AWT application on the event-dispatch thread.
     *
     * @param arguments ignored command-line arguments
     */
    public static void main(String[] arguments) {
        EventQueue.invokeLater(() -> {
            MainFrame frame = new MainFrame();
            frame.setVisible(true);
        });
    }

    private Panel buildNavigation() {
        Panel navigation = new Panel(new BorderLayout(16, 0));
        navigation.setBackground(Theme.BACKGROUND);
        navigation.add(Theme.brand("STEGOSHIELD"), BorderLayout.WEST);
        Panel tabs = new Panel();
        tabs.setBackground(Theme.BACKGROUND);
        tabs.add(navigationButton("HIDE", () -> cards.show(cardPanel, HIDE_CARD)));
        tabs.add(navigationButton("EXTRACT", () -> cards.show(cardPanel, EXTRACT_CARD)));
        tabs.add(navigationButton("SCAN", () -> cards.show(cardPanel, SCAN_CARD)));
        tabs.add(navigationButton("CLEAN", () -> cards.show(cardPanel, CLEAN_CARD)));
        tabs.add(navigationButton("EVALUATION", this::beginEvaluation));
        navigation.add(tabs, BorderLayout.CENTER);
        Label status = new Label("OFFLINE  |  AES-256-GCM  |  JDK ONLY");
        status.setForeground(Theme.MUTED);
        status.setBackground(Theme.BACKGROUND);
        navigation.add(status, BorderLayout.EAST);
        return navigation;
    }

    private Panel buildHideScreen() {
        Panel screen = new Panel(new BorderLayout(6, 6));
        Panel controls = new Panel(new GridLayout(0, 2, 6, 6));
        hideKind = new Choice();
        hideKind.add("Image LSB (PNG/BMP)");
        hideKind.add("Audio LSB (16-bit PCM WAV)");
        hideKind.add("Text zero-width Unicode (UTF-8)");
        hideKind.add("PNG bytes after IEND (fixture)");
        hideKind.add("PNG tEXt metadata (fixture)");
        hideKind.addItemListener(event -> {
            if (event.getStateChange() == ItemEvent.SELECTED) {
                hideSource = null;
                hideSourceField.setText("");
                capacityLabel.setText("Capacity: select a carrier");
                previewCanvas.clear();
            }
        });
        hidePlacement = new Choice();
        hidePlacement.add("Sequential positions");
        hidePlacement.add("Password-scattered image positions");
        hideSourceField = lockedField();
        hidePassword = passwordField();
        decoyEnabled = new Checkbox("Enable decoy / plausible-deniability mode");
        decoyMessage = new TextField();
        decoyPassword = passwordField();
        capacityLabel = new Label("Capacity: select a carrier");
        controls.add(new Label("Carrier type"));
        controls.add(hideKind);
        controls.add(new Label("Image placement"));
        controls.add(hidePlacement);
        controls.add(new Label("Carrier file"));
        controls.add(hideSourceField);
        controls.add(new Label("Encryption password"));
        controls.add(hidePassword);
        controls.add(new Label("Decoy mode"));
        controls.add(decoyEnabled);
        controls.add(new Label("Decoy message (when enabled)"));
        controls.add(decoyMessage);
        controls.add(new Label("Decoy password (when enabled)"));
        controls.add(decoyPassword);
        controls.add(new Label("Carrier capacity"));
        controls.add(capacityLabel);
        screen.add(controls, BorderLayout.NORTH);

        Panel center = new Panel(new GridLayout(1, 2, 6, 6));
        Panel messagePanel = new Panel(new BorderLayout());
        messagePanel.add(new Label("Secret message (UTF-8)"), BorderLayout.NORTH);
        hideMessage = new TextArea("", 10, 35, TextArea.SCROLLBARS_VERTICAL_ONLY);
        messagePanel.add(hideMessage, BorderLayout.CENTER);
        center.add(messagePanel);
        previewCanvas = new ImagePreviewCanvas();
        center.add(previewCanvas);
        screen.add(center, BorderLayout.CENTER);

        Panel actions = new Panel();
        actions.add(navigationButton("Open carrier", this::chooseHideCarrier));
        actions.add(navigationButton("Hide and save", this::beginHide));
        screen.add(actions, BorderLayout.SOUTH);
        return screen;
    }

    private Panel buildExtractScreen() {
        Panel screen = new Panel(new BorderLayout(6, 6));
        Panel controls = new Panel(new GridLayout(0, 2, 6, 6));
        extractSourceField = lockedField();
        extractPassword = passwordField();
        extractPlacement = new Choice();
        extractPlacement.add("Sequential / automatic carrier extraction");
        extractPlacement.add("Password-scattered image positions");
        extractMode = new Choice();
        extractMode.add("Standard encrypted message");
        extractMode.add("Decoy message");
        extractMode.add("Real decoy-mode message");
        controls.add(new Label("Carrier file"));
        controls.add(extractSourceField);
        controls.add(new Label("Password"));
        controls.add(extractPassword);
        controls.add(new Label("Image placement"));
        controls.add(extractPlacement);
        controls.add(new Label("Reveal mode"));
        controls.add(extractMode);
        screen.add(controls, BorderLayout.NORTH);
        extractResult = new TextArea("Extracted plaintext appears here after authentication succeeds.", 16, 90,
                TextArea.SCROLLBARS_BOTH);
        extractResult.setEditable(false);
        screen.add(extractResult, BorderLayout.CENTER);
        Panel actions = new Panel();
        actions.add(navigationButton("Open carrier", this::chooseExtractCarrier));
        actions.add(navigationButton("Extract", this::beginExtract));
        screen.add(actions, BorderLayout.SOUTH);
        return screen;
    }

    private Panel buildScanScreen() {
        Panel screen = new Panel(new BorderLayout(6, 6));
        Panel top = new Panel(new GridLayout(0, 2, 6, 6));
        scanSourceField = lockedField();
        riskLabel = new Label("Risk: no file scanned", Label.CENTER);
        riskLabel.setBackground(Color.LIGHT_GRAY);
        top.add(new Label("File to scan"));
        top.add(scanSourceField);
        top.add(new Label("Explainable risk"));
        top.add(riskLabel);
        screen.add(top, BorderLayout.NORTH);
        Panel center = new Panel(new GridLayout(1, 2, 6, 6));
        scanReportArea = new TextArea("Scanner findings appear here.", 18, 56, TextArea.SCROLLBARS_BOTH);
        scanReportArea.setEditable(false);
        center.add(scanReportArea);
        heatmapCanvas = new LsbHeatmapCanvas();
        center.add(heatmapCanvas);
        screen.add(center, BorderLayout.CENTER);
        Panel actions = new Panel();
        actions.add(navigationButton("Open file", this::chooseScanFile));
        actions.add(navigationButton("Scan file", this::beginScan));
        actions.add(navigationButton("Batch folder", this::beginBatchScan));
        actions.add(navigationButton("Timing demo", this::beginTimingDemo));
        actions.add(navigationButton("Export report", this::beginReportExport));
        screen.add(actions, BorderLayout.SOUTH);
        return screen;
    }

    private Panel buildCleanScreen() {
        Panel screen = new Panel(new BorderLayout(6, 6));
        Panel top = new Panel(new GridLayout(0, 2, 6, 6));
        cleanSourceField = lockedField();
        top.add(new Label("File to sanitize"));
        top.add(cleanSourceField);
        top.add(new Label("Guarantee"));
        top.add(new Label("A distinct output is required; originals are never modified."));
        screen.add(top, BorderLayout.NORTH);
        cleanResultArea = new TextArea("Cleaning will display source and output scores here.", 16, 90,
                TextArea.SCROLLBARS_BOTH);
        cleanResultArea.setEditable(false);
        screen.add(cleanResultArea, BorderLayout.CENTER);
        Panel actions = new Panel();
        actions.add(navigationButton("Open file", this::chooseCleanFile));
        actions.add(navigationButton("Clean and re-scan", this::beginClean));
        screen.add(actions, BorderLayout.SOUTH);
        return screen;
    }

    private void chooseHideCarrier() {
        File selected = chooseFile("Open carrier", FileDialog.LOAD, null);
        if (selected == null) {
            return;
        }
        hideSource = selected;
        hideSourceField.setText(selected.getAbsolutePath());
        refreshHideCapacity();
    }

    private void refreshHideCapacity() {
        File source = hideSource;
        CarrierKind kind = selectedHideKind();
        if (source == null) {
            return;
        }
        runAsync("carrier capacity", () -> {
            CapacityPreview preview = loadCapacityPreview(source, kind);
            onEdt(() -> {
                capacityLabel.setText("Capacity: " + preview.capacity + " bytes");
                if (preview.image != null) {
                    previewCanvas.setImages(preview.image, null);
                } else {
                    previewCanvas.clear();
                }
            });
            appendStatus("Carrier capacity: " + preview.capacity + " bytes for " + source.getName());
        });
    }

    private void beginHide() {
        File source = hideSource;
        if (source == null) {
            appendStatus("Choose a carrier before hiding data.");
            return;
        }
        String message = hideMessage.getText();
        if (message.isEmpty()) {
            appendStatus("[error] Secret message must not be empty.");
            return;
        }
        String passwordText = hidePassword.getText();
        if (passwordText.isEmpty()) {
            appendStatus("[error] Encryption password must not be empty.");
            return;
        }
        boolean useDecoy = decoyEnabled.getState();
        String decoyText = decoyMessage.getText();
        if (useDecoy && decoyText.isEmpty()) {
            appendStatus("[error] Decoy mode requires a non-empty decoy message.");
            return;
        }
        if (useDecoy && decoyPassword.getText().isEmpty()) {
            appendStatus("[error] Decoy mode requires a non-empty decoy password.");
            return;
        }
        if (hideSource == null || !hideSource.isFile() || !hideSource.canRead()) {
            appendStatus("[error] Carrier is missing or unreadable.");
            return;
        }
        File output = chooseFile("Save generated carrier", FileDialog.SAVE, defaultOutputName(selectedHideKind()));
        if (output == null) {
            return;
        }
        if (sameFile(source, output)) {
            appendStatus("Output must be different from the carrier; the original is never overwritten.");
            return;
        }
        CarrierKind kind = selectedHideKind();
        boolean scattered = hidePlacement.getSelectedIndex() == 1 && kind == CarrierKind.IMAGE;
        if (hidePlacement.getSelectedIndex() == 1 && kind != CarrierKind.IMAGE) {
            appendStatus("[warning] Password scattering applies only to image carriers; using sequential placement.");
        }
        char[] password = hidePassword.getText().toCharArray();
        char[] decoyPass = useDecoy ? decoyPassword.getText().toCharArray() : null;
        // CryptoUtil clears its input; use an independent copy for the placement seed.
        char[] scatteringPassword = scattered ? hidePassword.getText().toCharArray() : null;
        runAsync("hide", () -> {
            byte[] payload = null;
            try {
                long capacity = carrierCapacity(source, kind);
                if (useDecoy) {
                    int containerBytes = Math.toIntExact(Math.min(capacity, (long) DecoyMode.MAX_CONTAINER_BYTES));
                    payload = DecoyMode.create(decoyText.getBytes(StandardCharsets.UTF_8), decoyPass,
                            message.getBytes(StandardCharsets.UTF_8), password, containerBytes);
                } else {
                    payload = CryptoUtil.encrypt(Payload.wrap(message.getBytes(StandardCharsets.UTF_8)), password);
                }
                if ((long) payload.length > capacity) {
                    throw new IllegalArgumentException("encrypted payload is " + payload.length
                            + " bytes but carrier capacity is " + capacity + " bytes");
                }
                double used = capacity == 0L ? 100.0d : 100.0d * payload.length / capacity;
                HiddenOutput hidden = embedPayload(source, output, kind, payload, scattered, scatteringPassword);
                appendStatus(String.format(java.util.Locale.ROOT,
                        "[ok] Saved generated PNG: %s; encrypted payload %d bytes / capacity %d (%.2f%%)%s",
                        hidden.output.getAbsolutePath(), payload.length, capacity, used, hidden.metrics));
                onEdt(() -> {
                    if (hidden.original != null) {
                        previewCanvas.setImages(hidden.original, hidden.generated);
                    }
                });
            } finally {
                clear(payload);
                clear(password);
                clear(decoyPass);
                clear(scatteringPassword);
            }
        });
    }

    private void chooseExtractCarrier() {
        File selected = chooseFile("Open carrier to extract", FileDialog.LOAD, null);
        if (selected != null) {
            extractSource = selected;
            extractSourceField.setText(selected.getAbsolutePath());
        }
    }

    private void beginExtract() {
        File source = extractSource;
        if (source == null) {
            appendStatus("Choose a carrier before extraction.");
            return;
        }
        char[] password = extractPassword.getText().toCharArray();
        int mode = extractMode.getSelectedIndex();
        boolean scattered = extractPlacement.getSelectedIndex() == 1;
        runAsync("extract", () -> {
            try {
                byte[] raw = extractRawPayload(source, scattered, password);
                byte[] message;
                if (mode == 1) {
                    message = DecoyMode.revealDecoy(raw, password);
                } else if (mode == 2) {
                    message = DecoyMode.revealReal(raw, password);
                } else {
                    byte[] decrypted = CryptoUtil.decrypt(raw, password);
                    try {
                        message = Payload.unwrap(decrypted);
                    } finally {
                        clear(decrypted);
                    }
                }
                String plaintext = decodeUtf8(message);
                clear(message);
                onEdt(() -> extractResult.setText(plaintext));
                appendStatus("Extraction and authenticated validation succeeded for " + source.getName() + ".");
            } catch (AEADBadTagException exception) {
                appendStatus("Extraction failed: wrong password or tampered encrypted data.");
            } finally {
                clear(password);
            }
        });
    }

    private void chooseScanFile() {
        File selected = chooseFile("Open file to scan", FileDialog.LOAD, null);
        if (selected != null) {
            scanSourceField.setText(selected.getAbsolutePath());
        }
    }

    private void beginScan() {
        String selectedPath = scanSourceField.getText();
        if (selectedPath.isEmpty()) {
            appendStatus("Choose a file before scanning.");
            return;
        }
        File source = new File(selectedPath);
        runAsync("scan", () -> {
            ScanReport report = scanner.scan(source);
            LsbHeatmap.Heatmap heatmap = buildHeatmap(source);
            latestReport = report;
            latestBatch = List.of();
            onEdt(() -> {
                scanReportArea.setText(report.toText());
                setRiskLabel(report);
                heatmapCanvas.setHeatmap(heatmap);
            });
            appendStatus("Completed scan: " + source.getName() + " scored " + report.riskScore() + "/100.");
        });
    }

    private void beginBatchScan() {
        File selected = chooseFile("Select any file inside the folder to batch scan", FileDialog.LOAD, null);
        if (selected == null) {
            return;
        }
        File folder = selected.getParentFile();
        if (folder == null) {
            appendStatus("Could not determine batch folder.");
            return;
        }
        appendStatus("Starting background batch scan for: " + folder.getAbsolutePath());
        BatchScanner batch = new BatchScanner(scanner);
        batch.scanAsync(folder, new BatchScanner.Listener() {
            @Override
            public void onFileScanned(ScanReport report) {
                onEdt(() -> scanReportArea.append("\nBatch: " + report.file().getName() + " -> "
                        + report.riskLevel().displayName() + " (" + report.riskScore() + ")\n"));
            }

            @Override
            public void onComplete(List<ScanReport> reports) {
                latestBatch = reports;
                onEdt(() -> {
                    scanReportArea.append("\nBatch complete: " + reports.size()
                            + " file(s), sorted by descending risk.\n");
                    if (!reports.isEmpty()) {
                        setRiskLabel(reports.get(0));
                    }
                });
                appendStatus("Batch scan completed with " + reports.size() + " report(s).");
            }

            @Override
            public void onFailure(Exception exception) {
                appendStatus("Batch scan failed: " + safeMessage(exception));
            }
        });
    }

    private void beginTimingDemo() {
        byte[] demoPayload = "StegoShield timing demo".getBytes(StandardCharsets.UTF_8);
        runAsync("localhost timing demo", () -> {
            AtomicReference<CovertReceiver.Reception> reception = new AtomicReference<>();
            AtomicReference<Exception> failure = new AtomicReference<>();
            CountDownLatch completed = new CountDownLatch(1);
            try (CovertReceiver receiver = new CovertReceiver(0, 128)) {
                receiver.receiveAsync(new CovertReceiver.Listener() {
                    @Override
                    public void onReceived(CovertReceiver.Reception result) {
                        reception.set(result);
                        completed.countDown();
                    }

                    @Override
                    public void onFailure(Exception exception) {
                        failure.set(exception);
                        completed.countDown();
                    }
                });
                CovertSender.Transmission transmission = new CovertSender(receiver.port()).send(demoPayload);
                if (!completed.await(TimingChannel.SOCKET_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)) {
                    throw new IOException("timing receiver did not finish before its timeout");
                }
                if (failure.get() != null) {
                    throw new IOException("timing receiver failed", failure.get());
                }
                CovertReceiver.Reception result = reception.get();
                if (result == null) {
                    throw new IOException("timing receiver returned no result");
                }
                String recovered = decodeUtf8(result.payload());
                appendStatus("Timing demo recovered: \"" + recovered + "\"; " + transmission.encodedBits()
                        + " timed bits; suspicious=" + result.analysis().suspicious() + ".");
                for (String reason : result.analysis().reasons()) {
                    appendStatus("Timing analysis: " + reason);
                }
            }
        });
    }

    private void beginReportExport() {
        if (latestReport == null && latestBatch.isEmpty()) {
            appendStatus("Run a scan or batch scan before exporting a report.");
            return;
        }
        File output = chooseFile("Save text report", FileDialog.SAVE, "stegoshield-report.txt");
        if (output == null) {
            return;
        }
        List<ScanReport> batch = latestBatch;
        ScanReport single = latestReport;
        runAsync("report export", () -> {
            File written = !batch.isEmpty() ? ReportExporter.exportBatch(batch, output)
                    : ReportExporter.export(single, output);
            appendStatus("Saved report: " + written.getAbsolutePath());
        });
    }

    private void chooseCleanFile() {
        File selected = chooseFile("Open file to sanitize", FileDialog.LOAD, null);
        if (selected != null) {
            cleanSource = selected;
            cleanSourceField.setText(selected.getAbsolutePath());
        }
    }

    private void beginClean() {
        File source = cleanSource;
        if (source == null) {
            appendStatus("Choose a file before cleaning.");
            return;
        }
        File output = chooseFile("Save sanitized copy", FileDialog.SAVE, "cleaned-" + source.getName());
        if (output == null) {
            return;
        }
        if (sameFile(source, output)) {
            appendStatus("Sanitized output must be a distinct file.");
            return;
        }
        runAsync("clean", () -> {
            SanitizationResult result = cleaner.clean(source, output);
            onEdt(() -> {
                cleanResultArea.setText("Strategy: " + result.strategy() + "\n\nBefore:\n"
                        + result.before().toText() + "\nAfter:\n" + result.after().toText()
                        + "\nScore reduction: " + result.scoreReduction());
                setRiskLabel(result.after());
            });
            appendStatus("Sanitized copy saved to " + result.output().getAbsolutePath() + "; score change: "
                    + result.scoreReduction());
        });
    }

    private void beginEvaluation() {
        File selectedInput = chooseFile("Select any clean image inside the evaluation input folder", FileDialog.LOAD,
                null);
        if (selectedInput == null || selectedInput.getParentFile() == null) {
            return;
        }
        File selectedOutput = chooseFile("Choose a location inside the evaluation output root", FileDialog.SAVE,
                "evaluation-marker.txt");
        if (selectedOutput == null || selectedOutput.getParentFile() == null) {
            return;
        }
        File inputFolder = selectedInput.getParentFile();
        File outputRoot = selectedOutput.getParentFile();
        runAsync("evaluation", () -> {
            EvaluationResult result = new EvaluationRunner(scanner).run(inputFolder, outputRoot);
            onEdt(() -> scanReportArea.setText(result.toTable()));
            appendStatus("Evaluation finished. Measured table saved to " + result.reportFile().getAbsolutePath());
        });
    }

    private CapacityPreview loadCapacityPreview(File source, CarrierKind kind) throws IOException {
        return switch (kind) {
            case IMAGE -> {
                BufferedImage image = LSBImageStego.readCarrier(source);
                try (LSBImageStego stego = LSBImageStego.sequential()) {
                    yield new CapacityPreview(stego.capacityBytes(image), image);
                }
            }
            case AUDIO -> {
                WavData wav = LSBAudioStego.readWav(source);
                yield new CapacityPreview(new LSBAudioStego().capacityBytes(wav), null);
            }
            case TEXT -> {
                String text = Files.readString(source.toPath(), StandardCharsets.UTF_8);
                yield new CapacityPreview(new ZeroWidthStego().capacityBytes(text), null);
            }
            case PNG_EOF, PNG_METADATA -> {
                PngUtil.readPng(source);
                BufferedImage image = LSBImageStego.readCarrier(source);
                yield new CapacityPreview(DecoyMode.MAX_CONTAINER_BYTES, image);
            }
        };
    }

    private long carrierCapacity(File source, CarrierKind kind) throws IOException {
        return loadCapacityPreview(source, kind).capacity;
    }

    private HiddenOutput embedPayload(File source, File requestedOutput, CarrierKind kind, byte[] payload,
            boolean scattered, char[] scatteringPassword) throws IOException {
        return switch (kind) {
            case IMAGE -> embedImage(source, requestedOutput, payload, scattered, scatteringPassword);
            case AUDIO -> {
                WavData carrier = LSBAudioStego.readWav(source);
                WavData embedded = new LSBAudioStego().embed(carrier, payload);
                File output = LSBAudioStego.writeWav(embedded, requestedOutput);
                yield new HiddenOutput(output, null, null, "");
            }
            case TEXT -> {
                String carrier = Files.readString(source.toPath(), StandardCharsets.UTF_8);
                String embedded = new ZeroWidthStego().embed(carrier, payload);
                Files.writeString(requestedOutput.toPath(), embedded, StandardCharsets.UTF_8);
                yield new HiddenOutput(requestedOutput, null, null, "");
            }
            case PNG_EOF -> embedPngEof(source, requestedOutput, payload);
            case PNG_METADATA -> embedPngMetadata(source, requestedOutput, payload);
        };
    }

    private HiddenOutput embedImage(File source, File requestedOutput, byte[] payload, boolean scattered,
            char[] scatteringPassword) throws IOException {
        BufferedImage original = LSBImageStego.readCarrier(source);
        EmbeddingMode mode = scattered ? EmbeddingMode.PASSWORD_SCATTERED : EmbeddingMode.SEQUENTIAL;
        try (LSBImageStego stego = new LSBImageStego(mode, scatteringPassword)) {
            BufferedImage generated = stego.embed(original, payload);
            File output = LSBImageStego.writePng(generated, requestedOutput);
            double mse = ImageMetrics.meanSquaredError(original, generated);
            double psnr = ImageMetrics.peakSignalToNoiseRatio(original, generated);
            String metrics = String.format(java.util.Locale.ROOT, " (MSE %.6f, PSNR %.2f dB)", mse, psnr);
            return new HiddenOutput(output, original, generated, metrics);
        }
    }

    private HiddenOutput embedPngEof(File source, File requestedOutput, byte[] payload) throws IOException {
        File output = LSBImageStego.pngOutputFile(requestedOutput);
        File written = PngEofStego.appendAfterIend(source, payload, output);
        BufferedImage original = LSBImageStego.readCarrier(source);
        BufferedImage generated = LSBImageStego.readCarrier(written);
        return new HiddenOutput(written, original, generated, " (PNG trailing-byte fixture)");
    }

    private HiddenOutput embedPngMetadata(File source, File requestedOutput, byte[] payload) throws IOException {
        File output = LSBImageStego.pngOutputFile(requestedOutput);
        File written = PngMetadataStego.embedInTextChunk(source, payload, output);
        BufferedImage original = LSBImageStego.readCarrier(source);
        BufferedImage generated = LSBImageStego.readCarrier(written);
        return new HiddenOutput(written, original, generated, " (PNG tEXt metadata fixture)");
    }

    private byte[] extractRawPayload(File source, boolean scattered, char[] password)
            throws IOException, GeneralSecurityException {
        FileSignature signature = detectSignature(source);
        if ((signature == FileSignature.PNG || signature == FileSignature.BMP) && scattered) {
            BufferedImage image = LSBImageStego.readCarrier(source);
            try (LSBImageStego stego = LSBImageStego.passwordScattered(Arrays.copyOf(password, password.length))) {
                return stego.extract(image);
            }
        }
        if (signature == FileSignature.PNG || signature == FileSignature.BMP) {
            ExtractionAttempt attempt = extractionService.attempt(source);
            if (!attempt.successful()) {
                throw new IllegalArgumentException(attempt.message());
            }
            return attempt.payload();
        }
        if (signature == FileSignature.WAV) {
            return new LSBAudioStego().extract(LSBAudioStego.readWav(source));
        }
        String text = Files.readString(source.toPath(), StandardCharsets.UTF_8);
        return new ZeroWidthStego().extract(text);
    }

    private LsbHeatmap.Heatmap buildHeatmap(File source) {
        try {
            BufferedImage image = LSBImageStego.readCarrier(source);
            return LsbHeatmap.fromImage(image, AnalysisConstants.IMAGE_LSB_BLOCK_SIZE);
        } catch (IOException | IllegalArgumentException exception) {
            return null;
        }
    }

    private FileSignature detectSignature(File source) throws IOException {
        try (java.io.InputStream input = Files.newInputStream(source.toPath())) {
            return FileSignature.detect(input.readNBytes(16));
        }
    }

    private CarrierKind selectedHideKind() {
        return switch (hideKind.getSelectedIndex()) {
            case 0 -> CarrierKind.IMAGE;
            case 1 -> CarrierKind.AUDIO;
            case 2 -> CarrierKind.TEXT;
            case 3 -> CarrierKind.PNG_EOF;
            case 4 -> CarrierKind.PNG_METADATA;
            default -> throw new IllegalStateException("unsupported hide carrier selection");
        };
    }

    private void setRiskLabel(ScanReport report) {
        riskLabel.setText("Risk: " + report.riskScore() + "/100 — " + report.riskLevel().displayName());
        riskLabel.setBackground(switch (report.riskLevel()) {
            case CLEAN -> new Color(132, 205, 132);
            case SUSPICIOUS -> new Color(255, 200, 95);
            case LIKELY_CONTAINS_HIDDEN_DATA -> new Color(236, 122, 122);
        });
    }

    private File chooseFile(String title, int mode, String defaultName) {
        FileDialog dialog = new FileDialog(this, title, mode);
        if (defaultName != null) {
            dialog.setFile(defaultName);
        }
        dialog.setVisible(true);
        String name = dialog.getFile();
        String directory = dialog.getDirectory();
        if (name == null || directory == null) {
            return null;
        }
        return new File(directory, name);
    }

    private static boolean sameFile(File first, File second) {
        try {
            return first.getCanonicalFile().equals(second.getCanonicalFile());
        } catch (IOException exception) {
            return first.getAbsoluteFile().equals(second.getAbsoluteFile());
        }
    }

    private static TextField lockedField() {
        TextField field = new TextField();
        field.setEditable(false);
        return field;
    }

    private static TextField passwordField() {
        TextField field = new TextField();
        field.setEchoChar('*');
        return field;
    }

    private static Button navigationButton(String text, Runnable action) {
        Button button = new Button(text);
        button.addActionListener(event -> action.run());
        return button;
    }

    private static String defaultOutputName(CarrierKind kind) {
        return switch (kind) {
            case IMAGE, PNG_EOF, PNG_METADATA -> "stegoshield-stego.png";
            case AUDIO -> "stegoshield-stego.wav";
            case TEXT -> "stegoshield-stego.txt";
        };
    }

    private static String decodeUtf8(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException exception) {
            throw new IllegalArgumentException("authenticated payload is not valid UTF-8 text", exception);
        }
    }

    private void runAsync(String taskName, BackgroundTask task) {
        appendStatus("Starting " + taskName + " task...");
        Thread worker = new Thread(() -> {
            try {
                task.run();
            } catch (Exception exception) {
                appendStatus(taskName + " failed: " + safeMessage(exception));
            }
        }, "StegoShield-" + taskName.replaceAll("[^A-Za-z0-9]", ""));
        worker.setDaemon(true);
        worker.start();
    }

    private void appendStatus(String message) {
        onEdt(() -> statusArea.append(message + "\n"));
    }

    private static void onEdt(Runnable action) {
        EventQueue.invokeLater(action);
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

    private static void clear(char[] characters) {
        if (characters != null) {
            Arrays.fill(characters, '\0');
        }
    }

    private enum CarrierKind {
        IMAGE,
        AUDIO,
        TEXT,
        PNG_EOF,
        PNG_METADATA
    }

    private record CapacityPreview(long capacity, BufferedImage image) {
    }

    private record HiddenOutput(File output, BufferedImage original, BufferedImage generated, String metrics) {
    }

    @FunctionalInterface
    private interface BackgroundTask {
        void run() throws Exception;
    }
}
  }

    @FunctionalInterface
    private interface BackgroundTask {
        void run() throws Exception;
    }
}
