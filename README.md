# StegoShield

**StegoShield is an offline toolkit that helps at-risk users communicate covertly AND helps organizations detect, explain and neutralize steganography-based data leaks and payload smuggling.**

It combines encrypted hiding, structural and statistical steganalysis, extraction attempts, explainable reports, and non-destructive cleaning in one Java 17 application. It runs fully offline with only the standard JDK. It is a **steganalysis scanner, not a full antivirus**: it does not execute, disinfect, classify, or reliably detect malware.

> Use StegoShield only on files you own or are explicitly authorized to analyze. See [Ethics and authorization](#ethics-and-authorization).

## The real-life problem

Photos, audio, and text can secretly carry hidden data. Attackers can use steganography to smuggle malware or leak confidential data past filters that only inspect the apparent file type and known virus signatures. At-risk users—including journalists, activists, and whistleblowers—may need to communicate without an obviously encrypted file drawing attention. File owners may also need to prove authorship or investigate data leaks.

Many tools only hide data or only attempt detection. StegoShield brings together four offline capabilities:

1. **Hide** authenticated encrypted content in supported image, audio, and text carriers.
2. **Detect** suspicious structure and statistical indicators with a risk score and written reasons.
3. **Extract** best-effort flagged payloads and identify common magic-byte types.
4. **Clean** a copy of a carrier to neutralize supported hidden channels, then re-scan it.

## Features

- JDK-only, fully offline Java 17 implementation; no Maven, Gradle, third-party JARs, cloud APIs, AI calls, or network dependencies.
- AES-256-GCM authenticated encryption with PBKDF2WithHmacSHA256, 65,536 iterations, random 16-byte salt, and random 12-byte IV.
- PNG/BMP RGB LSB hiding: sequential or password-scattered Fisher–Yates placement, a 32-bit length header, PNG-only lossless output, MSE/PSNR, and amplified difference imagery.
- 16-bit signed little-endian PCM WAV LSB hiding while preserving the `AudioFormat`.
- Unicode zero-width text hiding with U+200B/U+200C, including detector and stripping support for U+200B–U+200D, U+2060, and U+FEFF.
- PNG IEND-trailing-data and ImageIO `tEXt` metadata fixtures for realistic scanner exercises.
- Explainable 0–100 risk scanner with file signatures, extension mismatches, carrier trailing data, entropy, embedded signatures, chi-square, LSB statistics, invisible Unicode, metadata sizing, and WAV LSB checks. The measured pair-of-values chi-square z-score is always reported as its own Findings line for qualifying images, scoring points only when triggered.
- LSB heatmap rendered as a semi-transparent per-block colour overlay on the scanned image itself, sorted background batch scan, UTF-8 report export, and payload extraction attempts.
- Original/Stego/Difference preview panels (minimum 300x200) on the Hide and Scan screens, plus coloured CLEAN/SUSPICIOUS/LIKELY risk badges next to the risk scores on the Scan and Clean screens.
- Non-destructive Stego Cleaner that randomizes—not zeroes—supported carrier LSBs and re-scans the output.
- Payload classification panel: blind structural typing of recoverable payload bytes on the Scan screen, and full authenticated triage (structural type, suspicious script keyword indicators, Shannon entropy, content verdict) of decrypted plaintext on the Extract screen. It never claims malware or safety; every verdict is paired with its evidence.
- Fixed-size decoy/real dual-password mode with documented plausible-deniability limits.
- Localhost-only timing-channel simulation and timing histogram/bimodality analysis.
- Evaluation runner that computes measured detection and false-positive rates at runtime; it never pre-fills results.
- AWT-only GUI with Hide, Extract, Scan, Clean, Evaluation, report export, preview, heatmap, and timing-demo controls.

## Project layout

```text
StegoShield/
├── README.md
├── build.sh
└── src/
    ├── core/       # shared API, payload framing, bit utilities
    ├── crypto/     # AES-GCM and PBKDF2
    ├── image/      # PNG/BMP LSB stego and image metrics
    ├── audio/      # supported WAV carrier support
    ├── text/       # zero-width Unicode stego
    ├── eof/        # PNG IEND and metadata fixtures
    ├── analysis/   # scanner, reports, heatmaps, extraction, batch scan
    ├── sanitize/   # non-destructive cleaner
    ├── decoy/      # dual-password container
    ├── network/    # localhost timing simulation
    ├── eval/       # runtime evaluation corpus and metrics
    ├── ui/         # AWT application
    └── test/       # plain-main self-tests
```

## Architecture and data formats

### Core framing

`core.Payload` serializes application bytes as:

```text
SSHD | version (1 byte) | payload length (4-byte unsigned big-endian) | CRC32 (4 bytes) | data
```

The `SSHD` frame detects accidental corruption and validates the declared length. CRC32 is not cryptographic authentication; encrypted content relies on AES-GCM authentication.

### Encryption

`crypto.CryptoUtil` uses this encrypted layout:

```text
16-byte random salt | 12-byte random GCM IV | AES-GCM ciphertext plus 16-byte tag
```

Keys are derived with `PBKDF2WithHmacSHA256` at 65,536 iterations and 256-bit AES keys. Wrong passwords and altered ciphertext raise `AEADBadTagException`. Mutable password arrays and derived key bytes are cleared after use. Passwords and plaintext are never logged.

### Image carriers

- Input carrier files: actual PNG or BMP signatures only; merely renaming JPEG data to `.png` is rejected.
- In-memory operation: `BufferedImage.TYPE_INT_RGB`.
- One payload bit per RGB channel LSB.
- A 32-bit big-endian length header precedes payload bytes.
- Sequential mode uses channel order; password-scattered mode uses a SHA-256-password-derived deterministic Fisher–Yates permutation.
- Output is always PNG. JPEG output is rejected because JPEG is lossy.

### WAV carriers

Only uncompressed, signed, **16-bit little-endian PCM WAV** is supported. One payload bit is stored in each 16-bit sample LSB. The 32-bit length header is followed by payload bits, and the original `AudioFormat` is retained when writing.

### Text carriers

Zero-width text mode stores a length header and payload bits after visible Unicode code points:

- U+200B encodes bit `0`.
- U+200C encodes bit `1`.

The embedding path rejects a carrier already containing monitored invisible characters because that would make extraction ambiguous.

### PNG auxiliary fixtures

- `PngEofStego` appends bytes after PNG IEND.
- `PngMetadataStego` Base64-encodes bytes into a PNG `tEXt` entry named `StegoShield-Payload` through the ImageIO metadata API.

These are deliberately easy for the scanner to exercise and are not confidential by themselves.

## Build and run

### Prerequisite

Install a plain **JDK 17** with both `java` and `javac` available on `PATH`.

### Required compile and run commands

```bash
javac -d out $(find src -name "*.java")
java -cp out ui.MainFrame
```

Recommended warning-enabled build:

```bash
javac -Xlint:all -d out $(find src -name "*.java")
```

### Build script

`build.sh` wraps the JDK-only workflow:

```bash
./build.sh build
./build.sh run
./build.sh test
./build.sh eval <clean-image-folder> [output-root]
```

The script invokes `javac -Xlint:all` before its selected action.

### Self-test command

```bash
java -cp out test.StegoShieldSelfTest
```

### Evaluation command

```bash
java -cp out eval.EvaluationRunner <clean-image-folder> [output-root]
```

The evaluation output directory must be outside the clean-image input folder so generated specimens cannot contaminate clean controls.

## GUI usage

Start the program with `java -cp out ui.MainFrame`.

### Hide

1. Select Image LSB, Audio LSB, Text zero-width, PNG IEND fixture, or PNG `tEXt` metadata fixture.
2. Open an appropriate carrier with FileDialog.
3. Review reported capacity.
4. Enter a non-empty secret message and encryption password.
5. For images, optionally select password-scattered placement.
6. Optionally enable decoy mode, enter a distinct harmless decoy message and decoy password.
7. Select a distinct output file and save.

Image outputs are PNG even when a BMP source is selected. WAV output must remain supported 16-bit PCM WAV. Text output is UTF-8. After hiding in an image carrier, the screen shows the original, generated, and amplified x20 difference panels side by side; each panel keeps a minimum size of 300x200 pixels.

### Extract

1. Open a carrier.
2. Choose automatic/sequential extraction or password-scattered image extraction.
3. Select standard, decoy, or real decoy-mode reveal.
4. Enter the relevant password and extract.

A standard extraction decrypts with AES-GCM, validates `Payload`, then strictly decodes UTF-8. A failure is reported as wrong password, tampering, unsupported carrier, or invalid payload rather than returning garbage. Binary plaintexts that authenticate correctly are reported as binary with their byte count instead of being mislabelled as failures. After a successful extraction, the **Payload Classification** panel below the result shows the authenticated classification of the decrypted plaintext: structural type, every matched indicator, Shannon entropy, and a content verdict of `PLAIN TEXT`, `STRUCTURED FILE` (with the type named), `SCRIPT WITH SUSPICIOUS INDICATORS` (with the matched keywords), `EXECUTABLE BINARY`, or `UNKNOWN BINARY`.

### Scan

1. Open a file and choose **Scan file**.
2. Read the risk label, score, coloured CLEAN/SUSPICIOUS/LIKELY badge, and every triggered reason. Image reports always include their own chi-square pair-of-values z-score line, which scores points only when it triggers.
3. For images, inspect the block-based LSB heatmap painted as a semi-transparent colour overlay on the scanned picture, warm and opaque marking near-even blocks. The preview panels below it show the scanned image, and — when the scanned file is the stego image most recently generated on the Hide screen in this session — its original carrier and amplified x20 difference too.
4. The **Payload Classification** panel below the risk report shows the blind structural type of any payload bytes a best-effort extraction recovers, with the note: full content classification requires extraction with the correct password. No malware claim is made.
5. Use **Batch folder** and select any file within the target folder; its parent folder is scanned recursively in a background worker.
6. Use **Export report** to save a UTF-8 `.txt` single or batch report.

The **Timing demo** is a localhost-only controlled demonstration. It intentionally takes time because it encodes bits using 50 ms and 150 ms gaps.

### Clean

1. Open a PNG/BMP/JPEG image, supported WAV, or valid UTF-8 text file.
2. Select a distinct destination.
3. Choose **Clean and re-scan**.

The Cleaner never modifies the original. It displays the applied strategy, original report, output report, and score difference, with before/after risk scores and CLEAN/SUSPICIOUS/LIKELY badges at the top of the screen. A lower score is useful feedback, not proof every possible channel was removed.

### Evaluation

Choose **Evaluation**, select any clean image inside the input folder, then choose a location in an output root outside that input folder. The runner generates runtime cases for clean controls, 10/25/50/100% LSB payloads, appended PNG data, and wrong extensions. It prints and saves the measured table.

Do not quote detection or false-positive percentages until you have run the evaluation against a documented corpus; this repository does not include fabricated accuracy figures.

## Explainable risk scoring

The final score is capped at 100. Thresholds and point values live in `analysis.AnalysisConstants`.

| Score | Label |
|---:|---|
| 0–24 | `CLEAN` |
| 25–59 | `SUSPICIOUS` |
| 60–100 | `LIKELY CONTAINS HIDDEN DATA` |

| Triggered test | Default contribution | Evidence reported |
|---|---:|---|
| Magic bytes vs extension mismatch | 25 | Detected signature and conflicting extension |
| PNG IEND or JPEG FFD9 trailing bytes | 30 | Carrier boundary and trailing byte count |
| Trailing entropy at least 7.5 bits/byte | 15 | Measured Shannon entropy |
| ZIP, EXE/MZ, PDF, or ELF after carrier data | 35 each type | Type and offset after carrier boundary |
| Pair-of-values chi-square | 18 | z-score and active degrees of freedom |
| Image LSB global/block randomness | 18 | global z-score and balanced-block fraction |
| Invisible Unicode | 35 | per-code-point counts |
| Oversized PNG textual metadata | 18 | textual metadata bytes/chunk size |
| WAV LSB randomness | 18 | sample-LSB balance z-score |

The chi-square implementation groups adjacent values such as 42/43, calculates expected values from each pair total, and uses one degree of freedom for every non-empty pair. It does not apply the test to tiny images or too few active pairs. Every qualifying image scan reports the measured chi-square z-score as its own Findings line; the line contributes points only when the z-score is at or below the threshold.

## Payload classification

`analysis.PayloadClassifier` performs heuristic static triage of recovered payload bytes in two modes and never claims that content is malware or safe.

**Mode 1 — blind (no password available).** It runs on payload bytes recovered by the best-effort extraction service, but not on bytes carrying this app's own headers: an `SSHD`-framed payload, an `SSDN` decoy container, or bytes flagged as this app's AES-GCM salt|IV|ciphertext container (the Scan screen flags the stego image most recently generated on the Hide screen in the same session). Everything else is labelled by structural type only — PNG, JPEG, BMP, WAV, ZIP, DOCX/XLSX/PPTX (ZIP plus their internal Office Open XML entries), Windows executable (MZ), ELF, PDF, or plain text by printable-ASCII ratio — with no malware claim. The panel always adds: full content classification requires extraction with the correct password.

**Mode 2 — authenticated (after successful password decryption).** The same structural detection runs on the decrypted plaintext. Printable UTF-8 with no binary markers is a plain text message unless one of the listed suspicious indicator keywords matches, in which case the verdict is `SCRIPT WITH SUSPICIOUS INDICATORS` with every match listed. The keywords, matched case-insensitively, are: `Invoke-Expression`, `-EncodedCommand`, `eval(`, `exec(`, `base64 -d`, `/bin/sh -c`, `cmd.exe /c`, `wget `, `curl `, `Add-MpPreference -ExclusionPath`, `reg add`, `New-Object Net.WebClient`. Script-like markers such as shebangs, batch headers, and VBA module headers are reported as evidence without inferring intent. The plaintext's Shannon entropy is reported as a number; high entropy alone is never translated into a verdict because compressed or legitimate binary data is also high-entropy.

The content verdict is one of `PLAIN TEXT`, `STRUCTURED FILE` (the type is named), `SCRIPT WITH SUSPICIOUS INDICATORS` (indicators listed), `EXECUTABLE BINARY`, or `UNKNOWN BINARY`, and it is always paired with the concrete evidence that produced it.

Full malware detection requires signature databases and behavioral sandboxing that are out of scope for an offline, JDK-only tool. StegoShield instead performs heuristic static triage: identifying file type by structure and flagging known suspicious code patterns, which is the same first layer real antivirus engines use before deeper analysis.

## Sanitizer behavior

| Carrier | Cleaning operation |
|---|---|
| PNG/BMP/JPEG image | Decode and re-encode to a new PNG, discard metadata/trailing bytes, randomize every RGB LSB with `SecureRandom`. |
| Supported WAV | Copy sample data, randomize every sample LSB with `SecureRandom`, preserve `AudioFormat`. |
| UTF-8 text | Remove U+200B–U+200D, U+2060, and U+FEFF, then write a new UTF-8 file. |

Randomizing LSBs is intentional. Zeroing them creates a predictable artificial pattern and can itself be suspicious.

## Decoy / plausible-deniability mode

`DecoyMode` creates a fixed-size `SSDN` container. It stores an authenticated encrypted decoy message conventionally, then scatters the real encrypted message length and ciphertext into the LSBs of otherwise random padding using a real-password-derived permutation.

A person with only the decoy password can decrypt the decoy message and sees random-looking fixed-size padding. AES-GCM ciphertext and secure random padding are indistinguishable at the byte level.

### Honest limits

This is not magical deniability and does not protect against:

- coercion, legal compulsion, endpoint compromise, keylogging, screenshots, or physical surveillance;
- traffic analysis, known-message attacks, backups, or an adversary who already expects a real message;
- source-code-aware adversaries who know StegoShield supports decoy containers;
- a suspiciously large fixed container or operational mistakes such as reusing passwords;
- forensic evidence outside the container itself.

Use distinct strong passwords. Do not claim the design proves that no second message exists.

## Network simulation

The `network` package is strictly a localhost demonstration. It does not capture live traffic and does not bind to external interfaces.

- A sender emits a synchronization token followed by one token per bit.
- A zero bit waits about 50 ms; a one bit waits about 150 ms.
- The receiver has accept/read timeouts, a length limit, loopback binding, and safe closure.
- `TimingAnalyzer` builds 25 ms histogram bins, applies inspectable two-means clustering, and flags traffic only when it is both strongly bimodal and highly regular.

Scheduling jitter, TCP buffering, and operating-system load can affect the demonstration.

## Limitations and scanner caveats

- **Low embedding rates and password-scattered embedding reduce detection accuracy.** They may leave too little statistical evidence for the implemented image tests.
- A high score is an indicator, not proof. Clean files can contain random-looking data, large metadata, compressed content, unusual extensions, or invisible Unicode for legitimate reasons.
- A low score is not assurance. Novel, adaptive, encrypted, sparse, transform-domain, or format-specific techniques can evade these checks.
- The scanner does not execute recovered files, identify malware families, inspect memory, or replace an antivirus, EDR, forensic workflow, or human review.
- Image analysis supports RGB PNG/BMP LSB checks. JPEG DCT steganography is intentionally not implemented.
- WAV support is limited to signed 16-bit little-endian PCM. Compressed WAV, MP3, and other audio formats are not supported.
- Zero-width text can be destroyed by Unicode normalization, editors, chat platforms, copy/paste, fonts, or transport transformations.
- The scanner fully loads files only up to its configured deep-analysis limit (64 MiB) and UTF-8 text only up to its text-analysis limit (8 MiB). Larger files still receive safe basic checks but not every deep heuristic.
- Statistical tests are sensitive to source content, resizing, color processing, compression history, and sample size.
- Cleaning neutralizes only supported channels. It cannot prove removal of arbitrary steganography, malicious macros, parser exploits, encryption, or external references.
- The password-scattered image permutation obscures placement; it is not a substitute for AES-GCM encryption.

## Assumptions

1. A standard JDK 17 installation provides the normal ImageIO PNG/BMP and Java Sound WAV support used by the implementation.
2. Users select valid and authorized local files; the GUI does not upload files or call external services.
3. Input text for zero-width embedding and text cleaning is UTF-8.
4. Carriers and generated payloads fit Java array/memory limits and configured scanner/evaluation safety limits.
5. Supported WAV files are signed, 16-bit, little-endian PCM with valid frame size and rates.
6. Password-scattered image extraction uses the exact same password and dimensions as embedding.
7. Timing simulation runs locally with sufficient scheduling resolution; its observations are illustrative rather than network-forensic truth.
8. Evaluation inputs are genuinely clean controls. A contaminated baseline invalidates false-positive measurements.
9. CRC32 detects accidental frame corruption; AES-GCM, not CRC32, supplies cryptographic authenticity.

## Ethics and authorization

StegoShield is for privacy, education, defensive security, incident response, and authorized research. Analyze, extract, sanitize, or transmit only files you own or have explicit permission to handle. Do not use the tool to conceal malware, exfiltrate data, bypass lawful controls, evade investigations, or violate policy, contracts, or law.

Organizations should combine scanner results with context, retention policy, endpoint telemetry, malware scanning, and qualified human review. At-risk users should consider local-device compromise, operational security, backups, and legal risk in addition to file secrecy.

## Future work

The following are deliberately out of scope for this project:

- real MP4/video codec steganography;
- live packet capture;
- MP3 steganography;
- JPEG DCT steganography.

## Viva Q&A

1. **Why AES-GCM instead of AES-CBC?**
   AES-GCM provides confidentiality and authentication together. A wrong password or modified ciphertext is detected through the authentication tag.

2. **Why is PBKDF2 used?**
   Passwords are not AES keys. PBKDF2WithHmacSHA256 stretches a password with a random salt and 65,536 iterations before AES-256-GCM uses the resulting key.

3. **What does the `Payload` CRC32 protect?**
   It validates the framing and detects accidental corruption after extraction. It is not cryptographic authentication; GCM provides that for encrypted messages.

4. **Why is PNG output required for image LSB stego?**
   PNG is lossless. JPEG re-compression can alter LSBs and destroy payload bits.

5. **Why use a 32-bit length header?**
   It lets extraction know exactly how many embedded bytes to read and reject impossible declarations before allocating memory.

6. **How does password-scattered image embedding work?**
   It derives a SHA-256 seed from the password and uses a deterministic Fisher–Yates shuffle of RGB channel positions. The same password recreates the positions for extraction.

7. **What does a chi-square z-score indicate here?**
   The scanner checks whether neighboring histogram pairs have been unusually equalized, which can be consistent with LSB replacement. It is heuristic evidence, not proof.

8. **Why randomize LSBs when cleaning instead of setting them to zero?**
   Zeroing creates an unnatural, easily detected pattern. Secure random replacement removes a deterministic embedded bitstream without introducing all-zero LSBs.

9. **How does decoy mode avoid directly exposing a second message?**
   The real ciphertext is scattered through random-looking fixed-size padding. A decoy-password holder sees an ordinary decoy ciphertext and opaque padding, but this remains only plausible deniability with important limits.

10. **Why are measured evaluation results not included in this README?**
    Detection and false-positive rates depend on the actual clean corpus, payloads, and runtime environment. The evaluation runner computes and saves real measurements instead of inventing figures.

## Public API inventory

This inventory lists project classes and their public project-facing methods. Record component names are public accessor methods.

### `core`

- `Stego<C>` — `capacityBytes(C)`, `embed(C, byte[])`, `extract(C)`.
- `BitUtil` — `getBit`, `setBit`, `readUnsignedIntBigEndian`, `unsignedIntToBigEndian`, `wholeBytesForBits`, `bitsForBytes`, `intToBits`.
- `Payload` — `wrap`, `unwrap`, `inspect`, `hasMagic`, `crc32`; nested `Header(version, payloadLength, crc32)` accessors.

### `crypto`

- `CryptoUtil` — `encrypt`, `decrypt`, `minimumEncryptedLength`.

### `image`

- `EmbeddingMode` — enum values `SEQUENTIAL`, `PASSWORD_SCATTERED`.
- `ImageMetrics` — `meanSquaredError`, `peakSignalToNoiseRatio`, `amplifiedDifference`.
- `LSBImageStego` — constructors `LSBImageStego()`, `LSBImageStego(EmbeddingMode, char[])`; `sequential`, `passwordScattered`, `mode`, `capacityBytes`, `embed`, `extract`, `readCarrier`, `writePng`, `pngOutputFile`, `copyToRgb`, `close`.

### `audio`

- `WavData` — constructor `WavData(AudioFormat, byte[])`; `format`, `pcmBytes`, `sampleCount`, `frameCount`.
- `LSBAudioStego` — `capacityBytes`, `embed`, `extract`, `readWav`, `writeWav`.

### `text`

- `ZeroWidthStego` — `capacityBytes`, `embed`, `extract`, `detectInvisibleCharacters`, `stripInvisibleCharacters`, `isMonitoredInvisible`; nested `InvisibleCharacterReport` component accessors plus `totalCount`, `bitCharacterCount`.

### `eof`

- `PngUtil` — `readPng`, `hasSignature`, `parseChunks`, `iendEnd`, `trailingBytes`; nested `Chunk(type, dataLength, dataOffset, endOffset)` accessors.
- `PngEofStego` — `appendAfterIend`, `extractAfterIend`, `trailingByteCount`.
- `PngMetadataStego` — `embedInTextChunk`, `extractFromTextChunk`.

### `analysis`

- `AnalysisConstants` — public tuning constants for labels, limits, thresholds, and score contributions.
- `RiskLevel` — `fromScore`, `displayName`.
- `Finding(test, points, reason)` — record component accessors.
- `FileSignature` — `detect`, `detectAt`, `displayName`, `matchesExtension`.
- `PayloadType` — `identify`, `displayName`.
- `Entropy` — `shannonBitsPerByte`.
- `ChiSquareResult(statistic, degreesOfFreedom, zScore)` — record component accessors.
- `LsbStatistics(totalBits, oneBits, balanceZ, blockCount, balancedBlockCount, meanOneFraction, oneFractionVariance)` — record component accessors, `oneFraction`, `balancedBlockFraction`.
- `ImageStatistics` — `pairOfValuesChiSquare`, `lsbStatistics`, `balanceZ`.
- `LsbHeatmap` — `fromImage`; nested `Heatmap(imageWidth, imageHeight, blockSize, columns, rows, intensities)` accessors and `intensityAt`.
- `LsbHeatmapCanvas` — constructor, `setHeatmap`, `setImageAndHeatmap`, `image`, `heatmap`, `paint`, `update`.
- `ScanReport` — `file`, `fileSize`, `detectedSignature`, `riskScore`, `riskLevel`, `findings`, `scannedAt`, `toText`, `failure`.
- `StegoScanner` — `scan`.
- `PayloadClassifier` — `classifyBlind`, `classifyAuthenticated`; verdict constants `VERDICT_*` and `BLIND_MODE_NOTE`; nested `Mode.displayName`; nested `Classification(mode, byteCount, structuralType, contentVerdict, matchedIndicators, entropyBitsPerByte, evidence, note)` accessors and `toText`.
- `ReportExporter` — `export`, `exportBatch`.
- `BatchScanner` — constructors, `scanFolder`, `scanAsync`; nested `Listener.onFileScanned`, `onComplete`, `onFailure`.
- `ExtractionAttempt` — `success`, `failure`, `successful`, `technique`, `payloadType`, `payload`, `message`.
- `ExtractionService` — `attempt`.

### `sanitize` and `decoy`

- `SanitizationResult` — constructor; `source`, `output`, `strategy`, `before`, `after`, `scoreReduction`.
- `StegoCleaner` — constructors, `clean`, `randomizeImageLsbs`.
- `DecoyMode` — `create`, `revealDecoy`, `revealReal`, `minimumContainerBytes`.

### `network`

- `TimingChannel` — public timing and timeout constants.
- `TimingAnalysis` — `intervalCount`, `meanMillis`, `standardDeviationMillis`, `stronglyBimodal`, `highlyRegular`, `suspicious`, `lowerClusterMeanMillis`, `upperClusterMeanMillis`, `histogram`, `reasons`; nested `HistogramBin(lowerMillis, upperMillis, count)` accessors.
- `TimingAnalyzer` — `analyze`, `analyzeMillis` and public threshold constants.
- `CovertSender` — constructor `CovertSender(int)`, `send`; nested `Transmission(payloadBytes, encodedBits, zeroGapMillis, oneGapMillis)` accessors.
- `CovertReceiver` — constructors, `port`, `receiveOnce`, `receiveAsync`, `close`; nested `Reception.payload`, `intervalsNanos`, `analysis`; nested `Listener.onReceived`, `onFailure`.

### `eval`, `ui`, and `test`

- `EvaluationScenario` — `positiveCase`, `displayName`.
- `EvaluationMetrics` — `scenario`, `total`, `flagged`, `flaggedPercent`, `formattedPercent`.
- `EvaluationResult` — `metrics`, `warnings`, `outputDirectory`, `reportFile`, `completedAt`, `overallDetectionPercent`, `falsePositivePercent`, `toTable`.
- `EvaluationRunner` — constructors, `run`, `main`.
- `ImagePreviewCanvas` — constructors `ImagePreviewCanvas()`, `ImagePreviewCanvas(String, String, String)`; `setImages`, `clear`, `paint`, `update`.
- `RiskBadge` — constructor, `setLevel`, `level`, `paint`, `update`.
- `MainFrame` — constructor, `main`.
- `StegoShieldSelfTest` — `main`.

## Final quality gate

- This tool is for privacy and defensive security on files you own or are authorized to analyze.
- No detection-accuracy figures are claimed here because no evaluation corpus has been run in this environment.
- The exact commands to compile and run are:

```bash
javac -d out $(find src -name "*.java")
java -cp out ui.MainFrame
```

- Recommended warning-enabled compile and self-test:

```bash
javac -Xlint:all -d out $(find src -name "*.java")
java -cp out test.StegoShieldSelfTest
```
