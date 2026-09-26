package io.github.murylloex.miniwaf;

/**
 * {@code WafConfig.decisionCache}: a short-TTL LRU of allow/block decisions
 * keyed by a request fingerprint. {@code null} members take the default.
 *
 * @param max default 256
 * @param ttlMs default 1000 ms
 */
public record DecisionCacheConfig(Long max, Long ttlMs) {
    public DecisionCacheConfig() {
        this(null, null);
    }
}
