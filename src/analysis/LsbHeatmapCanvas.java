package analysis;

import java.awt.Canvas;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Image;
import java.awt.image.BufferedImage;
import java.util.Objects;

/**
 * AWT Canvas that renders block-based image LSB heatmap data as a
 * semi-transparent colour overlay on top of the analysed image itself, so
 * near-even blocks can be located visually instead of as a detached solid
 * grid. Cooler, fainter blocks are imbalanced; warmer, more opaque blocks have
 * near-even zero/one LSB counts. The visualization must be interpreted with
 * scanner findings rather than as standalone proof.
 */
public final class LsbHeatmapCanvas extends Canvas {
    private static final long serialVersionUID = 1L;
    private static final int MARGIN = 10;
    private static final int LEGEND_RESERVE = 18;

    private transient BufferedImage image;
    private transient LsbHeatmap.Heatmap heatmap;

    /**
     * Creates an empty heatmap canvas with a practical preview size.
     */
    public LsbHeatmapCanvas() {
        image = null;
        heatmap = null;
        setPreferredSize(new Dimension(360, 240));
        setMinimumSize(new Dimension(300, 200));
        setBackground(Color.DARK_GRAY);
    }

    /**
     * Sets the rendered heatmap without an underlying image. The blocks are
     * then drawn semi-transparently across the whole canvas. This method may
     * be called by UI code on the AWT event thread.
     *
     * @param heatmap data to render, or null to clear the canvas
     */
    public void setHeatmap(LsbHeatmap.Heatmap heatmap) {
        this.image = null;
        this.heatmap = heatmap;
        repaint();
    }

    /**
     * Sets the analysed image together with its heatmap. The heatmap is
     * rendered as a semi-transparent colour overlay on a letterboxed,
     * aspect-preserving rendering of the image. This method may be called by
     * UI code on the AWT event thread.
     *
     * @param image analysed image, or null to clear the canvas
     * @param heatmap per-block near-even intensities for the same image
     */
    public void setImageAndHeatmap(BufferedImage image, LsbHeatmap.Heatmap heatmap) {
        this.image = image;
        this.heatmap = heatmap;
        repaint();
    }

    /**
     * Returns the image currently displayed under the overlay, or null.
     *
     * @return displayed image
     */
    public BufferedImage image() {
        return image;
    }

    /**
     * Returns current heatmap data, or null when no image has been analyzed.
     *
     * @return current heatmap
     */
    public LsbHeatmap.Heatmap heatmap() {
        return heatmap;
    }

    /**
     * Paints the image with its translucent block overlay, or a minimal
     * empty-state message.
     *
     * @param graphics AWT graphics context
     */
    @Override
    public void paint(Graphics graphics) {
        Objects.requireNonNull(graphics, "graphics must not be null");
        int width = getWidth();
        int height = getHeight();
        graphics.setColor(getBackground());
        graphics.fillRect(0, 0, width, height);
        if (image == null && heatmap == null) {
            graphics.setColor(Color.LIGHT_GRAY);
            graphics.drawString("LSB heatmap overlay appears after an image scan.", 12, Math.max(24, height / 2));
            return;
        }
        if (image != null) {
            paintImageWithOverlay(graphics, width, height);
        } else {
            paintBlockGrid(graphics, width, height);
        }
        graphics.setColor(new Color(255, 255, 255, 200));
        graphics.drawString("Overlay: cool/faint = imbalanced LSBs, warm/opaque = near-even LSBs", 8,
                Math.max(14, height - 6));
    }

    /**
     * Reduces background flicker by painting directly into the current graphics context.
     *
     * @param graphics AWT graphics context
     */
    @Override
    public void update(Graphics graphics) {
        paint(graphics);
    }

    private void paintImageWithOverlay(Graphics graphics, int width, int height) {
        int boxWidth = Math.max(1, width - 2 * MARGIN);
        int boxHeight = Math.max(1, height - 2 * MARGIN - LEGEND_RESERVE);
        double scale = Math.min((double) boxWidth / image.getWidth(),
                (double) boxHeight / image.getHeight());
        int drawWidth = Math.max(1, (int) Math.round(image.getWidth() * scale));
        int drawHeight = Math.max(1, (int) Math.round(image.getHeight() * scale));
        int drawX = MARGIN + (boxWidth - drawWidth) / 2;
        int drawY = MARGIN + (boxHeight - drawHeight) / 2;
        graphics.drawImage(image.getScaledInstance(drawWidth, drawHeight, Image.SCALE_SMOOTH),
                drawX, drawY, null);
        if (heatmap != null) {
            for (int row = 0; row < heatmap.rows(); row++) {
                int top = drawY + drawHeight * row / heatmap.rows();
                int bottom = drawY + drawHeight * (row + 1) / heatmap.rows();
                for (int column = 0; column < heatmap.columns(); column++) {
                    int left = drawX + drawWidth * column / heatmap.columns();
                    int right = drawX + drawWidth * (column + 1) / heatmap.columns();
                    graphics.setColor(colorFor(heatmap.intensityAt(column, row)));
                    graphics.fillRect(left, top, Math.max(1, right - left), Math.max(1, bottom - top));
                }
            }
        }
        graphics.setColor(Color.WHITE);
        graphics.drawRect(drawX - 1, drawY - 1, drawWidth + 1, drawHeight + 1);
    }

    private void paintBlockGrid(Graphics graphics, int width, int height) {
        for (int row = 0; row < heatmap.rows(); row++) {
            int top = row * height / heatmap.rows();
            int bottom = (row + 1) * height / heatmap.rows();
            for (int column = 0; column < heatmap.columns(); column++) {
                int left = column * width / heatmap.columns();
                int right = (column + 1) * width / heatmap.columns();
                graphics.setColor(colorFor(heatmap.intensityAt(column, row)));
                graphics.fillRect(left, top, Math.max(1, right - left), Math.max(1, bottom - top));
            }
        }
    }

    private static Color colorFor(double intensity) {
        int red = (int) Math.round(30.0d + 225.0d * intensity);
        int green = (int) Math.round(70.0d + 140.0d * (1.0d - Math.abs(intensity - 0.5d) * 2.0d));
        int blue = (int) Math.round(220.0d * (1.0d - intensity));
        int alpha = (int) Math.round(72.0d + 156.0d * intensity);
        return new Color(clamp(red), clamp(green), clamp(blue), clamp(alpha));
    }

    private static int clamp(int value) {
        return Math.max(0, Math.min(255, value));
    }
}
