package audio;

import java.util.Arrays;
import java.util.Objects;
import javax.sound.sampled.AudioFormat;

/**
 * Immutable-in-practice container for validated 16-bit little-endian PCM WAV
 * sample bytes and their original {@link AudioFormat}. The constructor copies
 * sample data so callers cannot alter a carrier after validation.
 */
public final class WavData {
    private final AudioFormat format;
    private final byte[] pcmBytes;

    /**
     * Creates a carrier after validating its PCM representation.
     *
     * @param format original audio format
     * @param pcmBytes signed PCM frames in little-endian byte order
     */
    public WavData(AudioFormat format, byte[] pcmBytes) {
        LSBAudioStego.validateFormat(format);
        Objects.requireNonNull(pcmBytes, "PCM bytes must not be null");
        if (pcmBytes.length % format.getFrameSize() != 0) {
            throw new IllegalArgumentException("PCM data length is not aligned to the audio frame size");
        }
        this.format = format;
        this.pcmBytes = Arrays.copyOf(pcmBytes, pcmBytes.length);
    }

    /**
     * Returns the original PCM format. {@code AudioFormat} is value-like and
     * contains no mutable sample data.
     *
     * @return source audio format
     */
    public AudioFormat format() {
        return format;
    }

    /**
     * Returns a copy of the signed PCM sample bytes.
     *
     * @return PCM byte copy
     */
    public byte[] pcmBytes() {
        return Arrays.copyOf(pcmBytes, pcmBytes.length);
    }

    /**
     * Returns the number of 16-bit samples across every channel.
     *
     * @return total sample count
     */
    public long sampleCount() {
        return pcmBytes.length / (long) Short.BYTES;
    }

    /**
     * Returns the number of complete audio frames.
     *
     * @return frame count
     */
    public long frameCount() {
        return pcmBytes.length / (long) format.getFrameSize();
    }
}
