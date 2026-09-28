package audio;

import core.Stego;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Objects;
import javax.sound.sampled.AudioFileFormat;
import javax.sound.sampled.AudioFormat;
import javax.sound.sampled.AudioInputStream;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.UnsupportedAudioFileException;

/**
 * LSB steganography for uncompressed, signed 16-bit little-endian PCM WAV.
 * One bit is stored in the low byte's least-significant bit of each sample,
 * across all audio channels. A 32-bit big-endian byte-length header precedes
 * the payload. The carrier's validated {@link AudioFormat} is preserved when
 * writing a new WAV file.
 */
public final class LSBAudioStego implements Stego<WavData> {
    /** Bits reserved for the unsigned payload-length header. */
    public static final int LENGTH_HEADER_BITS = Integer.SIZE;
    /** One carrier sample stores one payload bit. */
    public static final int BITS_PER_PAYLOAD_BYTE = Byte.SIZE;

    /**
     * Calculates available payload capacity after the 32-bit length header.
     *
     * @param carrier validated PCM carrier
     * @return payload capacity in bytes
     */
    @Override
    public long capacityBytes(WavData carrier) {
        Objects.requireNonNull(carrier, "WAV carrier must not be null");
        long samples = carrier.sampleCount();
        if (samples <= LENGTH_HEADER_BITS) {
            return 0L;
        }
        return (samples - LENGTH_HEADER_BITS) / BITS_PER_PAYLOAD_BYTE;
    }

    /**
     * Embeds non-empty bytes in a copy of the carrier's PCM samples.
     *
     * @param carrier validated PCM WAV carrier
     * @param payload bytes to embed
     * @return new WAV carrier with an embedded 32-bit length and payload
     */
    @Override
    public WavData embed(WavData carrier, byte[] payload) {
        Objects.requireNonNull(carrier, "WAV carrier must not be null");
        Objects.requireNonNull(payload, "payload must not be null");
        if (payload.length == 0) {
            throw new IllegalArgumentException("payload must not be empty");
        }
        long capacity = capacityBytes(carrier);
        if ((long) payload.length > capacity) {
            throw new IllegalArgumentException("payload is " + payload.length
                    + " bytes but WAV capacity is only " + capacity + " bytes");
        }
        byte[] output = carrier.pcmBytes();
        writeLength(output, Integer.toUnsignedLong(payload.length));
        long sampleIndex = LENGTH_HEADER_BITS;
        for (byte payloadByte : payload) {
            int value = Byte.toUnsignedInt(payloadByte);
            for (int shift = BITS_PER_PAYLOAD_BYTE - 1; shift >= 0; shift--) {
                writeSampleBit(output, sampleIndex++, (value >>> shift) & 1);
            }
        }
        return new WavData(carrier.format(), output);
    }

    /**
     * Extracts a length-delimited payload from WAV sample LSBs.
     *
     * @param carrier validated PCM WAV carrier
     * @return extracted bytes
     */
    @Override
    public byte[] extract(WavData carrier) {
        Objects.requireNonNull(carrier, "WAV carrier must not be null");
        long capacity = capacityBytes(carrier);
        if (capacity <= 0L) {
            throw new IllegalArgumentException("WAV is too small to contain an LSB length header");
        }
        byte[] samples = carrier.pcmBytes();
        long declaredLength = readLength(samples);
        if (declaredLength == 0L) {
            throw new IllegalArgumentException("WAV LSB length header declares an empty payload");
        }
        if (declaredLength > capacity) {
            throw new IllegalArgumentException("WAV LSB length header declares " + declaredLength
                    + " bytes, exceeding WAV capacity of " + capacity + " bytes");
        }
        final int payloadLength;
        try {
            payloadLength = Math.toIntExact(declaredLength);
        } catch (ArithmeticException exception) {
            throw new IllegalArgumentException("declared WAV payload is too large to allocate", exception);
        }
        byte[] payload = new byte[payloadLength];
        long sampleIndex = LENGTH_HEADER_BITS;
        for (int byteIndex = 0; byteIndex < payload.length; byteIndex++) {
            int value = 0;
            for (int bit = 0; bit < BITS_PER_PAYLOAD_BYTE; bit++) {
                value = (value << 1) | readSampleBit(samples, sampleIndex++);
            }
            payload[byteIndex] = (byte) value;
        }
        return payload;
    }

    /**
     * Reads a regular WAV file and rejects compressed, unsigned, big-endian,
     * non-16-bit, or malformed frame data with a clear error.
     *
     * @param source WAV file to load
     * @return validated PCM carrier
     * @throws IOException if the file cannot be read as supported WAV data
     */
    public static WavData readWav(File source) throws IOException {
        requireWaveSignature(source);
        try (AudioInputStream stream = AudioSystem.getAudioInputStream(source)) {
            AudioFormat format = stream.getFormat();
            validateFormat(format);
            byte[] pcmBytes = stream.readAllBytes();
            return new WavData(format, pcmBytes);
        } catch (UnsupportedAudioFileException exception) {
            throw new IOException("file is not a supported 16-bit signed PCM WAV: " + source, exception);
        }
    }

    /**
     * Writes PCM sample data as a WAV file while retaining its original format.
     * The source carrier is never changed.
     *
     * @param carrier validated carrier to write
     * @param output new WAV destination
     * @return output file
     * @throws IOException if writing fails or no WAV writer is available
     */
    public static File writeWav(WavData carrier, File output) throws IOException {
        Objects.requireNonNull(carrier, "WAV carrier must not be null");
        if (output == null) {
            throw new IllegalArgumentException("WAV output file must not be null");
        }
        if (output.isDirectory()) {
            throw new IOException("WAV output path is a directory: " + output);
        }
        File parent = output.getAbsoluteFile().getParentFile();
        if (parent != null && !parent.isDirectory()) {
            throw new IOException("WAV output directory does not exist: " + parent);
        }
        byte[] pcmBytes = carrier.pcmBytes();
        long frames = carrier.frameCount();
        try (ByteArrayInputStream bytes = new ByteArrayInputStream(pcmBytes);
                AudioInputStream stream = new AudioInputStream(bytes, carrier.format(), frames)) {
            int written = AudioSystem.write(stream, AudioFileFormat.Type.WAVE, output);
            if (written <= 0) {
                throw new IOException("no WAV writer is available in this JDK");
            }
        }
        return output;
    }

    /**
     * Validates the exact PCM profile implemented by this class.
     *
     * @param format audio format to validate
     * @throws IllegalArgumentException if the format is unsupported
     */
    static void validateFormat(AudioFormat format) {
        Objects.requireNonNull(format, "audio format must not be null");
        if (!AudioFormat.Encoding.PCM_SIGNED.equals(format.getEncoding())) {
            throw new IllegalArgumentException("unsupported WAV encoding; only signed PCM is supported");
        }
        if (format.getSampleSizeInBits() != Short.SIZE) {
            throw new IllegalArgumentException("unsupported WAV sample size; only 16-bit PCM is supported");
        }
        if (format.isBigEndian()) {
            throw new IllegalArgumentException("unsupported WAV byte order; only little-endian PCM is supported");
        }
        if (format.getChannels() <= 0) {
            throw new IllegalArgumentException("WAV channel count must be positive");
        }
        if (format.getFrameSize() != format.getChannels() * Short.BYTES) {
            throw new IllegalArgumentException("unsupported WAV frame size for 16-bit PCM");
        }
        if (format.getSampleRate() <= 0.0f || format.getFrameRate() <= 0.0f) {
            throw new IllegalArgumentException("WAV sample and frame rates must be specified and positive");
        }
    }

    private static void writeLength(byte[] samples, long byteLength) {
        for (int bit = LENGTH_HEADER_BITS - 1; bit >= 0; bit--) {
            long sampleIndex = LENGTH_HEADER_BITS - 1L - bit;
            writeSampleBit(samples, sampleIndex, (int) ((byteLength >>> bit) & 1L));
        }
    }

    private static long readLength(byte[] samples) {
        long length = 0L;
        for (long sampleIndex = 0L; sampleIndex < LENGTH_HEADER_BITS; sampleIndex++) {
            length = (length << 1) | readSampleBit(samples, sampleIndex);
        }
        return length;
    }

    private static void writeSampleBit(byte[] samples, long sampleIndex, int bit) {
        if (bit != 0 && bit != 1) {
            throw new IllegalArgumentException("sample bit must be zero or one");
        }
        int byteIndex = sampleByteIndex(samples, sampleIndex);
        samples[byteIndex] = (byte) ((samples[byteIndex] & 0xFE) | bit);
    }

    private static int readSampleBit(byte[] samples, long sampleIndex) {
        return samples[sampleByteIndex(samples, sampleIndex)] & 1;
    }

    private static int sampleByteIndex(byte[] samples, long sampleIndex) {
        if (sampleIndex < 0L || sampleIndex >= samples.length / (long) Short.BYTES) {
            throw new IllegalArgumentException("sample index is outside the PCM carrier");
        }
        return Math.toIntExact(sampleIndex * Short.BYTES);
    }

    private static void requireWaveSignature(File source) throws IOException {
        if (source == null) {
            throw new IllegalArgumentException("WAV source file must not be null");
        }
        if (!source.isFile()) {
            throw new IOException("WAV source is not a readable regular file: " + source);
        }
        byte[] header = new byte[12];
        try (BufferedInputStream input = new BufferedInputStream(new FileInputStream(source))) {
            int offset = 0;
            while (offset < header.length) {
                int count = input.read(header, offset, header.length - offset);
                if (count < 0) {
                    break;
                }
                offset += count;
            }
            if (offset < header.length
                    || header[0] != 'R' || header[1] != 'I' || header[2] != 'F' || header[3] != 'F'
                    || header[8] != 'W' || header[9] != 'A' || header[10] != 'V' || header[11] != 'E') {
                throw new IOException("file does not have a valid RIFF/WAVE signature: " + source);
            }
        }
    }
}
