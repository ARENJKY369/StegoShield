package ui;

import analysis.RiskLevel;
import java.awt.Canvas;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.util.Objects;

/**
 * Small AWT badge that renders the risk verdict as a coloured rectangle with
 * CLEAN, SUSPICIOUS, or LIKELY text. It is displayed next to the numeric risk
 * score on the Scan and Clean screens and mirrors the report's risk level
 * rather than adding a new signal.
 */
public final class RiskBadge extends Canvas {
    private static final long serialVersionUID = 1L;

    private static final Color CLEAN_FILL = new Color(46, 160, 67);
    private static final Color SUSPICIOUS_FILL = new Color(241, 173, 48);
    private static final Color LIKELY_FILL = new Color(215, 58, 73);
    private static final Color CLEAN_TEXT = Color.WHITE;
    private static final Color SUSPICIOUS_TEXT = new Color(32, 26, 0);
    private static final Color LIKELY_TEXT = Color.WHITE;
    private static final Color IDLE_FILL = new Color(70, 82, 95);
    private static final Color IDLE_TEXT = new Color(222, 231, 238);
    private static final Font BADGE_FONT = new Font("Dialog", Font.BOLD, 12);

    private RiskLevel level;

    /**
     * Creates an unset badge showing NO RESULT.
     */
    public RiskBadge() {
        level = null;
        setPreferredSize(new Dimension(170, 26));
        setMinimumSize(new Dimension(130, 22));
        setBackground(Theme.SURFACE);
    }

    /**
     * Sets the displayed risk level and requests a repaint. A null level
     * shows the neutral NO RESULT state.
     *
     * @param level risk level from the latest scan report, or null
     */
    public void setLevel(RiskLevel level) {
        this.level = level;
        repaint();
    }

    /**
     * Returns the displayed risk level, or null when unset.
     *
     * @return displayed level
     */
    public RiskLevel level() {
        return level;
    }

    /**
     * Paints the coloured badge with its centered verdict text.
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
        Color fill = IDLE_FILL;
        Color textColor = IDLE_TEXT;
        String text = "NO RESULT";
        if (level != null) {
            fill = switch (level) {
                case CLEAN -> CLEAN_FILL;
                case SUSPICIOUS -> SUSPICIOUS_FILL;
                case LIKELY_CONTAINS_HIDDEN_DATA -> LIKELY_FILL;
            };
            textColor = switch (level) {
                case CLEAN -> CLEAN_TEXT;
                case SUSPICIOUS -> SUSPICIOUS_TEXT;
                case LIKELY_CONTAINS_HIDDEN_DATA -> LIKELY_TEXT;
            };
            text = switch (level) {
                case CLEAN -> "CLEAN";
                case SUSPICIOUS -> "SUSPICIOUS";
                case LIKELY_CONTAINS_HIDDEN_DATA -> "LIKELY";
            };
        }
        graphics.setColor(fill);
        graphics.fillRoundRect(1, 1, Math.max(1, width - 2), Math.max(1, height - 2), 8, 8);
        graphics.setFont(BADGE_FONT);
        FontMetrics metrics = graphics.getFontMetrics(BADGE_FONT);
        int textX = Math.max(1, (width - metrics.stringWidth(text)) / 2);
        int textY = Math.max(metrics.getAscent(), (height - metrics.getHeight()) / 2 + metrics.getAscent());
        graphics.setColor(textColor);
        graphics.drawString(text, textX, textY);
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
}
