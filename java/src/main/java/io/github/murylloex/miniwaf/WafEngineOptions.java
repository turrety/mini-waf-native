package io.github.murylloex.miniwaf;

/**
 * Engine-level injectables for
 * {@link MiniWaf#createMiniWaf(WafConfig, WafEngineOptions)}.
 * {@code null} members take the default.
 *
 * @param rateLimitStore a shared store (default: a new one per instance)
 * @param logger the logging sink while {@code WafConfig.logging} is on
 *     (default: the console)
 */
public record WafEngineOptions(
    RateLimitStore rateLimitStore,
    WafLogger logger
) {
    public WafEngineOptions() {
        this(null, null);
    }
}
