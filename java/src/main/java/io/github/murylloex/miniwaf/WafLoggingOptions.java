package io.github.murylloex.miniwaf;

/**
 * Structured logging options. Events go to the console, or to
 * {@link WafEngineOptions#logger}.
 *
 * @param level default {@code INFO}
 */
public record WafLoggingOptions(WafLogLevel level) {
    public WafLoggingOptions() {
        this(null);
    }
}
