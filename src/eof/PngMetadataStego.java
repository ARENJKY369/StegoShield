package eof;

import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.Base64;
import java.util.Iterator;
import java.util.Locale;
import java.util.Objects;
import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.ImageTypeSpecifier;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.metadata.IIOMetadata;
import javax.imageio.metadata.IIOMetadataNode;
import javax.imageio.stream.ImageInputStream;
import javax.imageio.stream.ImageOutputStream;
import org.w3c.dom.Node;

/**
 * Stores byte payloads in a PNG tEXt metadata chunk using only the JDK ImageIO
 * metadata API. Bytes are Base64-encoded because PNG tEXt values are textual.
 * Rewriting with this fixture preserves pixels but may not preserve unrelated
 * metadata; it is intended for realistic scanner test cases, not archival use.
 */
public final class PngMetadataStego {
    /** PNG tEXt keyword used to locate this tool's Base64 payload. */
    public static final String KEYWORD = "StegoShield-Payload";
    private static final String PNG_METADATA_FORMAT = "javax_imageio_png_1.0";

    private PngMetadataStego() {
        // Utility class.
    }

    /**
     * Writes a new PNG containing a Base64 representation of {@code payload} in
     * a tEXt entry with {@link #KEYWORD}. Source and output must be different.
     *
     * @param source PNG source image
     * @param payload non-empty bytes to place in metadata
     * @param output distinct output PNG
     * @return output file
     * @throws IOException if decoding or writing fails
     */
    public static File embedInTextChunk(File source, byte[] payload, File output) throws IOException {
        Objects.requireNonNull(payload, "metadata payload must not be null");
        if (payload.length == 0) {
            throw new IllegalArgumentException("metadata payload must not be empty");
        }
        PngUtil.readPng(source);
        validateDistinctOutput(source, output);
        BufferedImage image = readImage(source);
        ImageWriter writer = pngWriter();
        try {
            ImageWriteParam parameters = writer.getDefaultWriteParam();
            IIOMetadata metadata = writer.getDefaultImageMetadata(
                    ImageTypeSpecifier.createFromRenderedImage(image), parameters);
            IIOMetadataNode root = metadataRoot(metadata);
            IIOMetadataNode textNode = directChild(root, "tEXt");
            if (textNode == null) {
                textNode = new IIOMetadataNode("tEXt");
                root.appendChild(textNode);
            }
            IIOMetadataNode entry = new IIOMetadataNode("tEXtEntry");
            entry.setAttribute("keyword", KEYWORD);
            entry.setAttribute("value", Base64.getEncoder().encodeToString(payload));
            textNode.appendChild(entry);
            metadata.mergeTree(PNG_METADATA_FORMAT, root);
            try (ImageOutputStream stream = ImageIO.createImageOutputStream(output)) {
                if (stream == null) {
                    throw new IOException("cannot open PNG metadata output: " + output);
                }
                writer.setOutput(stream);
                writer.write(null, new IIOImage(copyToRgb(image), null, metadata), parameters);
            }
        } finally {
            writer.dispose();
        }
        return output;
    }

    /**
     * Reads and Base64-decodes the tEXt value stored under {@link #KEYWORD}.
     *
     * @param source PNG file to inspect
     * @return embedded bytes
     * @throws IOException if the metadata entry is absent or malformed
     */
    public static byte[] extractFromTextChunk(File source) throws IOException {
        PngUtil.readPng(source);
        try (ImageInputStream input = ImageIO.createImageInputStream(source)) {
            if (input == null) {
                throw new IOException("cannot open PNG metadata source: " + source);
            }
            Iterator<ImageReader> readers = ImageIO.getImageReaders(input);
            if (!readers.hasNext()) {
                throw new IOException("no ImageIO reader is available for PNG metadata");
            }
            ImageReader reader = readers.next();
            try {
                reader.setInput(input, true, false);
                IIOMetadata metadata = reader.getImageMetadata(0);
                if (metadata == null
                        || !PNG_METADATA_FORMAT.equals(metadata.getNativeMetadataFormatName())) {
                    throw new IOException("PNG reader does not expose the native PNG metadata format");
                }
                Node root = metadata.getAsTree(PNG_METADATA_FORMAT);
                String encoded = findTextValue(root, KEYWORD);
                if (encoded == null) {
                    throw new IOException("PNG does not contain a " + KEYWORD + " tEXt entry");
                }
                try {
                    return Base64.getDecoder().decode(encoded);
                } catch (IllegalArgumentException exception) {
                    throw new IOException("PNG metadata payload is not valid Base64", exception);
                }
            } finally {
                reader.dispose();
            }
        }
    }

    private static BufferedImage readImage(File source) throws IOException {
        BufferedImage image = ImageIO.read(source);
        if (image == null) {
            throw new IOException("PNG source cannot be decoded as an image: " + source);
        }
        return image;
    }

    private static ImageWriter pngWriter() throws IOException {
        Iterator<ImageWriter> writers = ImageIO.getImageWritersByFormatName("png");
        if (!writers.hasNext()) {
            throw new IOException("no PNG ImageIO writer is available in this JDK");
        }
        return writers.next();
    }

    private static IIOMetadataNode metadataRoot(IIOMetadata metadata) throws IOException {
        if (metadata == null) {
            throw new IOException("PNG writer did not provide image metadata");
        }
        if (metadata.isReadOnly()) {
            throw new IOException("PNG writer returned read-only metadata");
        }
        if (!PNG_METADATA_FORMAT.equals(metadata.getNativeMetadataFormatName())) {
            throw new IOException("PNG writer does not provide the native PNG metadata format");
        }
        Node root = metadata.getAsTree(PNG_METADATA_FORMAT);
        if (!(root instanceof IIOMetadataNode pngRoot)) {
            throw new IOException("PNG writer returned an unsupported metadata tree");
        }
        return pngRoot;
    }

    private static IIOMetadataNode directChild(IIOMetadataNode parent, String name) {
        for (Node child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (name.equals(child.getNodeName()) && child instanceof IIOMetadataNode metadataNode) {
                return metadataNode;
            }
        }
        return null;
    }

    private static String findTextValue(Node node, String keyword) {
        if (node == null) {
            return null;
        }
        if ("tEXtEntry".equals(node.getNodeName()) && node.getAttributes() != null
                && node.getAttributes().getNamedItem("keyword") != null
                && keyword.equals(node.getAttributes().getNamedItem("keyword").getNodeValue())
                && node.getAttributes().getNamedItem("value") != null) {
            return node.getAttributes().getNamedItem("value").getNodeValue();
        }
        for (Node child = node.getFirstChild(); child != null; child = child.getNextSibling()) {
            String value = findTextValue(child, keyword);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private static BufferedImage copyToRgb(BufferedImage image) {
        BufferedImage copy = new BufferedImage(image.getWidth(), image.getHeight(), BufferedImage.TYPE_INT_RGB);
        Graphics2D graphics = copy.createGraphics();
        try {
            graphics.drawImage(image, 0, 0, null);
        } finally {
            graphics.dispose();
        }
        return copy;
    }

    private static void validateDistinctOutput(File source, File output) throws IOException {
        if (output == null) {
            throw new IllegalArgumentException("output PNG file must not be null");
        }
        if (output.isDirectory()) {
            throw new IOException("output PNG path is a directory: " + output);
        }
        if (!output.getName().toLowerCase(Locale.ROOT).endsWith(".png")) {
            throw new IllegalArgumentException("metadata stego output must use a .png filename");
        }
        File parent = output.getAbsoluteFile().getParentFile();
        if (parent != null && !parent.isDirectory()) {
            throw new IOException("output PNG directory does not exist: " + parent);
        }
        if (source.getCanonicalFile().equals(output.getCanonicalFile())) {
            throw new IllegalArgumentException("output PNG must differ from the source; original files are not modified");
        }
    }
}
