package analysis;

import core.Payload;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Heuristic static triage of recovered steganographic payload bytes. Full
 * malware detection requires signature databases and behavioral sandboxing
 * that are out of scope for an offline, JDK-only tool; this classifier instead
 * identifies file type by structure and flags known suspicious code patterns,
 * which is the same first layer real antivirus engines use before deeper
 * analysis. It never claims that content is malware or safe, and every verdict
 * is paired with the concrete evidence that produced it.
 */
public final class PayloadClassifier {
    /** Verdict for printable UTF-8 plaintext with no binary markers. */
    public static final String VERDICT_PLAIN_TEXT = "PLAIN TEXT";
    /** Verdict prefix for a recognized structured file type; the type is named. */
    public static final String VERDICT_STRUCTURED_FILE = "STRUCTURED FILE";
    /** Verdict for text containing one or more listed suspicious indicator keywords. */
    public static final String VERDICT_SCRIPT_WITH_INDICATORS = "SCRIPT WITH SUSPICIOUS INDICATORS";
    /** Verdict for Windows (MZ) or ELF executables. */
    public static final String VERDICT_EXECUTABLE_BINARY = "EXECUTABLE BINARY";
    /** Verdict for bytes with no recognized structure. */
    public static final String VERDICT_UNKNOWN_BINARY = "UNKNOWN BINARY";
    /** Note shown with every blind classification. */
    public static final String BLIND_MODE_NOTE =
            "Full content classification requires extraction with the correct password.";

    /** Four-byte ASCII marker of this app's decoy container (see DecoyMode). */
    private static final byte[] DECOY_MAGIC = {0x53, 0x53, 0x44, 0x4E};
    /** Minimum printable byte ratio before blind bytes are labelled plain text. */
    private static final double BLIND_PRINTABLE_ASCII_RATIO = 0.95d;
    /** Prefix bytes scanned for Office Open XML internal entry names. */
    private static final int OOXML_SCAN_LIMIT_BYTES = 1024 * 1024;
    /** Case-insensitive keywords listed as suspicious script indicators. */
    private static final String[] SUSPICIOUS_KEYWORDS = {
        "Invoke-Expression",
        "-EncodedCommand",
        "eval(",
        "exec(",
        "base64 -d",
        "/bin/sh -c",
        "cmd.exe /c",
        "wget ",
        "curl ",
        "Add-MpPreference -ExclusionPath",
        "reg add",
        "New-Object Net.WebClient"
    };
    /** Textual script or macro markers reported as evidence only. */
    private static final String SHEBANG_MARKER = "#!";
    private static final String BATCH_MARKER = "@echo off";
    private static final String VBA_MARKER = "attribute vb_name";
    private static final String PHP_MARKER = "<?php";

    private PayloadClassifier() {
        // Utility class.
    }

    /**
     * Mode 1 — blind structural triage of payload bytes recovered without a
     * password. Bytes carrying this app's own headers (SSHD framing, SSDN
     * decoy container, or a container flagged as this app's AES-GCM payload)
     * are reported as such and not structurally classified, because encrypted
     * containers are indistinguishable from noise. No malware claim is made;
     * results are labelled by structural type only.
     *
     * @param bytes recovered payload bytes, or null when none were recoverable
     * @param flaggedAsOwnEncryptedPayload true when the caller knows the bytes
     *        are this app's own AES-GCM salt|IV|ciphertext container
     * @return structural classification with the blind-mode note attached
     */
    public static Classification classifyBlind(byte[] bytes, boolean flaggedAsOwnEncryptedPayload) {
        List<String> indicators = new ArrayList<>();
        List<String> evidence = new ArrayList<>();
        if (bytes == null || bytes.length == 0) {
            evidence.add("no embedded payload bytes were recoverable through the known extraction paths");
            return new Classification(Mode.BLIND, bytes == null ? 0 : bytes.length,
                    "none (no recoverable payload bytes)", "", List.of(),
                    0.0d, evidence, BLIND_MODE_NOTE);
        }
        double entropy = Entropy.shannonBitsPerByte(bytes);
        if (flaggedAsOwnEncryptedPayload) {
            evidence.add("bytes are flagged as this app's own AES-GCM payload "
                    + "(random salt | GCM IV | ciphertext) and are not structurally classified");
            return new Classification(Mode.BLIND, bytes.length,
                    "StegoShield AES-GCM encrypted payload (this app's own container)", "",
                    List.of(), entropy, evidence, BLIND_MODE_NOTE);
        }
        String structuralType = structuralTypeOf(bytes, indicators, evidence, false);
        return new Classification(Mode.BLIND, bytes.length, structuralType, "",
                List.copyOf(indicators), entropy, evidence, BLIND_MODE_NOTE);
    }

    /**
     * Mode 2 — authenticated classification of plaintext recovered after a
     * successful password decryption. Runs the same structural detection,
     * scans printable text for the listed suspicious indicator keywords, and
     * reports the plaintext's Shannon entropy as a number. High entropy alone
     * is never translated into a verdict, because compressed or legitimate
     * binary data is also high-entropy.
     *
     * @param plaintext decrypted plaintext bytes
     * @return full classification including the content verdict and evidence
     */
    public static Classification classifyAuthenticated(byte[] plaintext) {
        Objects.requireNonNull(plaintext, "plaintext must not be null");
        List<String> indicators = new ArrayList<>();
        List<String> evidence = new ArrayList<>();
        double entropy = Entropy.shannonBitsPerByte(plaintext);
        if (plaintext.length == 0) {
            evidence.add("decrypted plaintext is empty (0 bytes)");
            return new Classification(Mode.AUTHENTICATED, 0, "empty (no bytes)",
                    VERDICT_PLAIN_TEXT, List.of(), 0.0d, evidence, "");
        }
        String text = printableUtf8(plaintext);
        if (text != null) {
            return classifyText(plaintext.length, text, indicators, evidence, entropy);
        }
        String structuralType = structuralTypeOf(plaintext, indicators, evidence, true);
        String verdict = switch (structuralType) {
            case "Windows executable (MZ)", "ELF executable" -> VERDICT_EXECUTABLE_BINARY;
            case "No recognized structure (unknown binary)" -> VERDICT_UNKNOWN_BINARY;
            default -> VERDICT_STRUCTURED_FILE + " — " + structuralType;
        };
        return new Classification(Mode.AUTHENTICATED, plaintext.length, structuralType,
                verdict, List.copyOf(indicators), entropy, evidence, "");
    }

    private static Classification classifyText(int byteCount, String text, List<String> indicators,
            List<String> evidence, double entropy) {
        String lowercased = text.toLowerCase(Locale.ROOT);
        for (String keyword : SUSPICIOUS_KEYWORDS) {
            int matches = countOccurrences(lowercased, keyword.toLowerCase(Locale.ROOT));
            if (matches > 0) {
                indicators.add("\"" + keyword + "\" matched " + matches + " time(s)");
            }
        }
        evidence.add("decrypted plaintext is printable UTF-8 with no binary markers");
        List<String> markers = scriptMarkers(lowercased);
        if (!markers.isEmpty()) {
            evidence.add("script-like marker(s) present: " + String.join(", ", markers));
        }
        if (indicators.isEmpty()) {
            evidence.add("none of the " + SUSPICIOUS_KEYWORDS.length
                    + " listed suspicious indicator keywords matched");
            return new Classification(Mode.AUTHENTICATED, byteCount,
                    "Plain text message (printable UTF-8)", VERDICT_PLAIN_TEXT, List.of(),
                    entropy, evidence, "");
        }
        return new Classification(Mode.AUTHENTICATED, byteCount,
                "Plain text message (printable UTF-8)", VERDICT_SCRIPT_WITH_INDICATORS,
                List.copyOf(indicators), entropy, evidence, "");
    }

    /**
     * Names the structural type of a byte sequence and records which
     * structural indicators matched, without ever claiming maliciousness.
     */
    private static String structuralTypeOf(byte[] bytes, List<String> indicators, List<String> evidence,
            boolean authenticated) {
        if (Payload.hasMagic(bytes)) {
            evidence.add("bytes begin with this app's own SSHD payload header; "
                    + "they are reported as this app's framing and not classified further");
            return "StegoShield framed payload (SSHD header)";
        }
        if (startsWith(bytes, DECOY_MAGIC)) {
            evidence.add("bytes begin with this app's own SSDN decoy container header; "
                    + "they are reported as this app's container and not classified further");
            return "StegoShield decoy container (SSDN header)";
        }
        FileSignature signature = FileSignature.detect(bytes);
        switch (signature) {
            case PNG -> {
                indicators.add("PNG signature (89 50 4E 47 0D 0A 1A 0A)");
                return "PNG image";
            }
            case JPEG -> {
                indicators.add("JPEG start-of-image marker (FF D8 FF)");
                return "JPEG image";
            }
            case BMP -> {
                indicators.add("BMP bitmap signature (42 4D)");
                return "BMP image";
            }
            case WAV -> {
                indicators.add("RIFF/WAVE audio signature");
                return "WAV audio";
            }
            case PDF -> {
                indicators.add("PDF header signature (%PDF-)");
                return "PDF document";
            }
            case WINDOWS_EXECUTABLE -> {
                indicators.add("DOS/Windows executable MZ header");
                addPeIndicator(bytes, indicators);
                return "Windows executable (MZ)";
            }
            case ELF -> {
                indicators.add("ELF executable magic (7F 45 4C 46)");
                addElfIndicators(bytes, indicators);
                return "ELF executable";
            }
            case ZIP -> {
                indicators.add("ZIP local file header (50 4B 03 04)");
                return ooxmlOrZipType(bytes, indicators);
            }
            default -> {
                double ratio = printableAsciiRatio(bytes);
                if (!authenticated && ratio >= BLIND_PRINTABLE_ASCII_RATIO) {
                    evidence.add(String.format(Locale.ROOT,
                            "%.1f%% of bytes are printable ASCII", ratio * 100.0d));
                    return "Plain text (high printable-ASCII ratio)";
                }
                evidence.add(String.format(Locale.ROOT,
                        "no recognized magic signature; printable-ASCII ratio is %.1f%%", ratio * 100.0d));
                return "No recognized structure (unknown binary)";
            }
        }
    }

    private static String ooxmlOrZipType(byte[] bytes, List<String> indicators) {
        if (containsAscii(bytes, "[Content_Types].xml")) {
            indicators.add("Office Open XML [Content_Types].xml entry present");
        }
        if (containsAscii(bytes, "word/")) {
            indicators.add("Office Open XML word/ entries present");
            return "DOCX document (Office Open XML)";
        }
        if (containsAscii(bytes, "xl/")) {
            indicators.add("Office Open XML xl/ entries present");
            return "XLSX workbook (Office Open XML)";
        }
        if (containsAscii(bytes, "ppt/")) {
            indicators.add("Office Open XML ppt/ entries present");
            return "PPTX presentation (Office Open XML)";
        }
        return "ZIP archive";
    }

    private static void addPeIndicator(byte[] bytes, List<String> indicators) {
        if (bytes.length < 0x40) {
            return;
        }
        int peOffset = ((bytes[0x3C] & 0xFF))
                | ((bytes[0x3D] & 0xFF) << 8)
                | ((bytes[0x3E] & 0xFF) << 16)
                | ((bytes[0x3F] & 0xFF) << 24);
        if (peOffset >= 0 && peOffset <= bytes.length - 4
                && (bytes[peOffset] & 0xFF) == 0x50 && (bytes[peOffset + 1] & 0xFF) == 0x45
                && bytes[peOffset + 2] == 0 && bytes[peOffset + 3] == 0) {
            indicators.add("PE header signature (PE 00 00) at offset " + peOffset);
        }
    }

    private static void addElfIndicators(byte[] bytes, List<String> indicators) {
        if (bytes.length >= 5) {
            int classByte = bytes[4] & 0xFF;
            if (classByte == 1) {
                indicators.add("ELF class: 32-bit");
            } else if (classByte == 2) {
                indicators.add("ELF class: 64-bit");
            }
        }
        if (bytes.length >= 18) {
            int type = (bytes[16] & 0xFF) | ((bytes[17] & 0xFF) << 8);
            if (type == 2) {
                indicators.add("ELF type: executable (ET_EXEC)");
            } else if (type == 3) {
                indicators.add("ELF type: shared object (ET_DYN)");
            }
        }
    }

    private static List<String> scriptMarkers(String lowercased) {
        List<String> markers = new ArrayList<>();
        if (lowercased.startsWith(SHEBANG_MARKER)) {
            markers.add("shebang (#!) first line");
        }
        if (containsNearStart(lowercased, PHP_MARKER, 32)) {
            markers.add("PHP opening tag (<?php)");
        }
        if (containsNearStart(lowercased, BATCH_MARKER, 64)) {
            markers.add("batch @echo off header");
        }
        if (lowercased.contains(VBA_MARKER)) {
            markers.add("VBA macro module header (Attribute VB_Name)");
        }
        return markers;
    }

    private static boolean containsNearStart(String lowercased, String marker, int limit) {
        String head = lowercased.length() <= limit ? lowercased : lowercased.substring(0, limit);
        return head.contains(marker);
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        int index = 0;
        while ((index = haystack.indexOf(needle, index)) >= 0) {
            count++;
            index += needle.length();
        }
        return count;
    }

    private static double printableAsciiRatio(byte[] bytes) {
        long printable = 0L;
        for (byte value : bytes) {
            int unsigned = value & 0xFF;
            if (unsigned == 0x09 || unsigned == 0x0A || unsigned == 0x0D
                    || (unsigned >= 0x20 && unsigned <= 0x7E)) {
                printable++;
            }
        }
        return bytes.length == 0 ? 0.0d : (double) printable / bytes.length;
    }

    /**
     * Returns the decoded text when every code point is printable UTF-8 with
     * no binary markers (control characters other than tab, line feed, and
     * carriage return), otherwise null.
     */
    private static String printableUtf8(byte[] bytes) {
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException exception) {
            return null;
        }
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            boolean allowedControl = character == '\t' || character == '\n' || character == '\r';
            if (Character.isISOControl(character) && !allowedControl) {
                return null;
            }
        }
        return text;
    }

    private static boolean startsWith(byte[] bytes, byte[] prefix) {
        if (bytes.length < prefix.length) {
            return false;
        }
        for (int index = 0; index < prefix.length; index++) {
            if (bytes[index] != prefix[index]) {
                return false;
            }
        }
        return true;
    }

    private static boolean containsAscii(byte[] bytes, String ascii) {
        byte[] pattern = ascii.getBytes(StandardCharsets.ISO_8859_1);
        int limit = Math.min(bytes.length, OOXML_SCAN_LIMIT_BYTES);
        if (pattern.length == 0 || limit < pattern.length) {
            return false;
        }
        outer:
        for (int index = 0; index + pattern.length <= limit; index++) {
            for (int offset = 0; offset < pattern.length; offset++) {
                if (bytes[index + offset] != pattern[offset]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    /** Which triage mode produced a classification. */
    public enum Mode {
        /** Mode 1: structural type only, no password available. */
        BLIND("Blind (no password available)"),
        /** Mode 2: authenticated classification of decrypted plaintext. */
        AUTHENTICATED("Authenticated (decrypted plaintext)");

        private final String displayName;

        Mode(String displayName) {
            this.displayName = displayName;
        }

        /**
         * Returns the label used in the classification panel.
         *
         * @return display name
         */
        public String displayName() {
            return displayName;
        }
    }

    /**
     * Immutable result of one payload classification.
     *
     * @param mode triage mode that produced this result
     * @param byteCount number of analyzed bytes
     * @param structuralType structural type label, never blank
     * @param contentVerdict one of the VERDICT_* values for authenticated
     *        classifications, or empty in blind mode
     * @param matchedIndicators every matched indicator, structural markers or
     *        keyword matches, with no fabricated entries
     * @param entropyBitsPerByte Shannon entropy of the analyzed bytes
     * @param evidence concrete observations behind the labels
     * @param note additional context, for example the blind-mode note
     */
    public record Classification(Mode mode, int byteCount, String structuralType, String contentVerdict,
            List<String> matchedIndicators, double entropyBitsPerByte, List<String> evidence, String note) {

        /**
         * Validates fields and defensively copies the lists.
         */
        public Classification {
            Objects.requireNonNull(mode, "mode must not be null");
            if (byteCount < 0) {
                throw new IllegalArgumentException("byte count must not be negative");
            }
            if (structuralType == null || structuralType.isBlank()) {
                throw new IllegalArgumentException("structural type must not be blank");
            }
            if (mode == Mode.BLIND && contentVerdict != null && !contentVerdict.isBlank()) {
                throw new IllegalArgumentException("blind classification must not carry a content verdict");
            }
            if (mode == Mode.AUTHENTICATED && (contentVerdict == null || contentVerdict.isBlank())) {
                throw new IllegalArgumentException("authenticated classification requires a content verdict");
            }
            if (contentVerdict != null && contentVerdict.startsWith(VERDICT_SCRIPT_WITH_INDICATORS)
                    && (matchedIndicators == null || matchedIndicators.isEmpty())) {
                throw new IllegalArgumentException("script verdict requires at least one matched indicator");
            }
            matchedIndicators = matchedIndicators == null ? List.of() : List.copyOf(matchedIndicators);
            evidence = evidence == null ? List.of() : List.copyOf(evidence);
            if (!Double.isFinite(entropyBitsPerByte) || entropyBitsPerByte < 0.0d
                    || entropyBitsPerByte > 8.0d) {
                throw new IllegalArgumentException("entropy must be between zero and eight bits per byte");
            }
            structuralType = structuralType.strip();
            contentVerdict = contentVerdict == null ? "" : contentVerdict.strip();
            note = note == null ? "" : note.strip();
        }

        /**
         * Renders this classification for the Payload Classification panel.
         * Every verdict line is preceded by the evidence that produced it.
         *
         * @return plain-text rendering using line-feed separators
         */
        public String toText() {
            StringBuilder text = new StringBuilder();
            text.append("Mode: ").append(mode.displayName()).append('\n');
            text.append("Analyzed bytes: ").append(byteCount).append('\n');
            text.append("Structural type: ").append(structuralType).append('\n');
            if (mode == Mode.AUTHENTICATED) {
                text.append("Content verdict: ").append(contentVerdict).append('\n');
            }
            if (!matchedIndicators.isEmpty()) {
                text.append("Matched indicators:").append('\n');
                for (String indicator : matchedIndicators) {
                    text.append("- ").append(indicator).append('\n');
                }
            }
            if (!evidence.isEmpty()) {
                text.append("Evidence:").append('\n');
                for (String line : evidence) {
                    text.append("- ").append(line).append('\n');
                }
            }
            if (byteCount > 0) {
                text.append(String.format(Locale.ROOT,
                        "Shannon entropy: %.3f bits/byte (high entropy alone is not a verdict; "
                                + "compressed or legitimate binary data is also high-entropy)\n",
                        entropyBitsPerByte));
            }
            if (!note.isBlank()) {
                text.append(note).append('\n');
            }
            return text.toString();
        }
    }
}
