package analysis;

import java.awt.Canvas;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.util.Objects;

/**
 * AWT Canvas that renders block-based image LSB heatmap data. Cooler colors
 * represent imbalanced blocks; warmer colors represent blocks with near-even
 * zero/one LSB counts. The visualization must be interpreted with scanner
 * findings rather than as standalone proof.
 */
public final class LsbHeatmapCanvas extends Canvas {
    private static final long serialVersionUID = 1L;

    private transient LsbHeatmap.Heatmap heatmap;

    /**
     * Creates an empty heatmap canvas with a practical preview size.
     */
    public LsbHeatmapCanvas() {
        heatmap = null;
        setPreferredSize(new Dimension(360, 240));
        setBackground(Color.DARK_GRAY);
    }

    /**
     * Sets the rendered heatmap and requests a repaint. This method may be
     * called by UI code on the AWT event thread.
     *
     * @param heatmap data to render, or null to clear the canvas
     */
    public void setHeatmap(LsbHeatmap.Heatmap heatmap) {
        this.heatmap = heatmap;
        repaint();
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
     * Paints heatmap blocks and a minimal empty-state message.
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
        LsbHeatmap.Heatmap current = heatmap;
        if (current == null) {
            graphics.setColor(Color.LIGHT_GRAY);
            graphics.drawString("LSB heatmap appears after an image scan.", 12, Math.max(24, height / 2));
            return;
        }
        for (int row = 0; row < current.rows(); row++) {
            int top = row * height / current.rows();
            int bottom = (row + 1) * height / current.rows();
            for (int column = 0; column < current.columns(); column++) {
                int left = column * width / current.columns();
                int right = (column + 1) * width / current.columns();
                graphics.setColor(colorFor(current.intensityAt(column, row)));
                graphics.fillRect(left, top, Math.max(1, right - left), Math.max(1, bottom - top));
            }
        }
        graphics.setColor(new Color(255, 255, 255, 160));
        graphics.drawString("Cool: imbalanced LSBs    Warm: near-even LSBs", 8, Math.max(14, height - 8));
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

    private static Color colorFor(double intensity) {
        int red = (int) Math.round(30.0d + 225.0d * intensity);
        int green = (int) Math.round(70.0d + 140.0d * (1.0d - Math.abs(intensity - 0.5d) * 2.0d));
        int blue = (int) Math.round(220.0d * (1.0d - intensity));
        return new Color(clamp(red), clamp(green), clamp(blue));
    }

    private static int clamp(int value) {
        return Math.max(0, Math.min(255, value));
    }
}
