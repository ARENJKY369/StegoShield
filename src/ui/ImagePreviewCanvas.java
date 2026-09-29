package ui;

import java.awt.Canvas;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Image;
import java.awt.image.BufferedImage;

/**
 * AWT canvas that displays original and generated images side by side without
 * altering either image. It is updated only by {@link MainFrame} on the AWT
 * event thread after background image work finishes.
 */
public final class ImagePreviewCanvas extends Canvas {
    private static final long serialVersionUID = 1L;

    private transient BufferedImage original;
    private transient BufferedImage generated;
    private transient BufferedImage difference;

    /** Creates a blank preview canvas. */
    public ImagePreviewCanvas() {
        setPreferredSize(new Dimension(620, 270));
        setBackground(Color.WHITE);
    }

    /**
     * Sets original and generated images. Either image may be null to clear its side.
     *
     * @param original original carrier image
     * @param generated generated stego or cleaned image
     */
    public void setImages(BufferedImage original, BufferedImage generated) {
        this.original = original;
        this.generated = generated;
        this.difference = original != null && generated != null
                ? image.ImageMetrics.amplifiedDifference(original, generated, 20.0d) : null;
        repaint();
    }

    /** Clears both preview slots. */
    public void clear() {
        setImages(null, null);
    }

    /** Paints preview labels, scaled images, and empty-state placeholders. */
    @Override
    public void paint(Graphics graphics) {
        int width = getWidth();
        int height = getHeight();
        graphics.setColor(getBackground());
        graphics.fillRect(0, 0, width, height);
        int gap = 10;
        int slotWidth = Math.max(1, (width - 2 * gap) / 3);
        drawSlot(graphics, original, 0, 0, slotWidth, height, "ORIGINAL");
        drawSlot(graphics, generated, slotWidth + gap, 0, slotWidth, height, "STEGO IMAGE");
        drawSlot(graphics, difference, 2 * (slotWidth + gap), 0, width - 2 * (slotWidth + gap), height,
                "DIFFERENCE x20");
    }

    /** Avoids background flicker. */
    @Override
    public void update(Graphics graphics) {
        paint(graphics);
    }

    private static void drawSlot(Graphics graphics, BufferedImage image, int x, int y, int width, int height,
            String title) {
        graphics.setColor(Color.DARK_GRAY);
        graphics.drawRect(x, y, Math.max(0, width - 1), Math.max(0, height - 1));
        graphics.drawString(title, x + 8, y + 18);
        if (image == null) {
            graphics.setColor(Color.GRAY);
            graphics.drawString("No image selected", x + 8, y + Math.max(40, height / 2));
            return;
        }
        int availableWidth = Math.max(1, width - 16);
        int availableHeight = Math.max(1, height - 36);
        double scale = Math.min((double) availableWidth / image.getWidth(),
                (double) availableHeight / image.getHeight());
        int drawWidth = Math.max(1, (int) Math.round(image.getWidth() * scale));
        int drawHeight = Math.max(1, (int) Math.round(image.getHeight() * scale));
        int drawX = x + (width - drawWidth) / 2;
        int drawY = y + 24 + (availableHeight - drawHeight) / 2;
        graphics.drawImage(image.getScaledInstance(drawWidth, drawHeight, Image.SCALE_SMOOTH), drawX, drawY, null);
    }
}
