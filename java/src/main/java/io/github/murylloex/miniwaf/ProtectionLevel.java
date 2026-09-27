package io.github.murylloex.miniwaf;

/**
 * Protection levels control which rules are active: a rule runs when the
 * configured level is at least its {@code minLevel}
 * ({@code LOW < BALANCED < HIGH < PARANOID}).
 */
public enum ProtectionLevel {
    /** High signal, low false positives. */
    LOW,
    /** The default. */
    BALANCED,
    /** Aggressive heuristics and the transport decoders. */
    HIGH,
    /** Legacy rules with elevated false positives. */
    PARANOID;

    public String asStr() {
        return name().toLowerCase(java.util.Locale.ROOT);
    }
}
