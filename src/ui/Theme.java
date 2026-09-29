package ui;

import java.awt.Button;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Font;
import java.awt.Label;
import java.awt.Panel;
import java.awt.TextArea;
import java.awt.TextField;

/** Shared dark dashboard palette and conservative AWT styling helpers. */
public final class Theme {
    public static final Color BACKGROUND = new Color(8, 18, 32);
    public static final Color SURFACE = new Color(15, 30, 48);
    public static final Color SURFACE_ALT = new Color(19, 39, 60);
    public static final Color BORDER = new Color(42, 78, 105);
    public static final Color CYAN = new Color(48, 211, 197);
    public static final Color TEXT = new Color(224, 235, 242);
    public static final Color MUTED = new Color(145, 169, 185);
    public static final Color TERMINAL = new Color(5, 15, 24);
    public static final Color SUCCESS = new Color(79, 218, 157);
    private static final Font BODY = new Font("Dialog", Font.PLAIN, 13);
    private static final Font HEADING = new Font("Dialog", Font.BOLD, 14);
    private static final Font BRAND = new Font("Dialog", Font.BOLD, 20);

    private Theme() { }

    public static Panel surface(Panel panel) {
        panel.setBackground(SURFACE);
        panel.setForeground(TEXT);
        return panel;
    }

    public static Label heading(String text) {
        Label label = new Label(text);
        label.setFont(HEADING);
        label.setForeground(CYAN);
        label.setBackground(SURFACE);
        return label;
    }

    public static Label brand(String text) {
        Label label = new Label(text);
        label.setFont(BRAND);
        label.setForeground(CYAN);
        label.setBackground(BACKGROUND);
        return label;
    }

    public static void apply(Component component) {
        component.setFont(BODY);
        component.setForeground(TEXT);
        component.setBackground(SURFACE);
        if (component instanceof Button button) {
            button.setBackground(SURFACE_ALT);
            button.setForeground(TEXT);
        } else if (component instanceof TextArea || component instanceof TextField) {
            component.setBackground(TERMINAL);
            component.setForeground(TEXT);
        }
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) apply(child);
        }
    }
}
