package io.github.murylloex.miniwaf;

/**
 * Structured logging options. Events go to the console; the injectable sink
 * of the Rust API is not available from Java.
 *
 * @param level default {@code INFO}
 */
public record WafLoggingOptions(WafLogLevel level) {
    public WafLoggingOptions() {
        this(null);
    }
}
