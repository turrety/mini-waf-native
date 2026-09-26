package io.github.murylloex.miniwaf;

/**
 * Verbosity when logging is enabled: {@code ERROR} = blocks only,
 * {@code INFO} = blocks + audit, {@code DEBUG} = + connections.
 */
public enum WafLogLevel {
    ERROR,
    INFO,
    DEBUG;

    public String asStr() {
        return name().toLowerCase(java.util.Locale.ROOT);
    }
}
