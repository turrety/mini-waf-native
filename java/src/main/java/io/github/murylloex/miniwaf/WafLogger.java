package io.github.murylloex.miniwaf;

/**
 * Receives log events while {@code WafConfig.logging} is on, filtered by its
 * level ({@code ERROR}: blocked; {@code INFO}: + audit; {@code DEBUG}: +
 * connection). Called on the evaluating thread, possibly from several at
 * once, before {@code handle} / {@code protect} returns; an exception it
 * throws comes out of that call. {@code ctx} is read-only and, like
 * {@code rule}, valid only during the call.
 */
public interface WafLogger {
    void blocked(WafHttpContext ctx, WafRule rule);

    void audit(WafHttpContext ctx, WafRule rule);

    void connection(WafHttpContext ctx);
}
