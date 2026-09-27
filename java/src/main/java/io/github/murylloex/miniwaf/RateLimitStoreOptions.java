package io.github.murylloex.miniwaf;

/**
 * {@code RateLimitStoreOptions}: {@code null} members take the default.
 *
 * @param maxKeys distinct keys retained, evicting the coldest (default
 *     10000)
 * @param idleMs drop keys idle this long (default 120000 ms)
 * @param pruneEveryHits full idle prune every N hits, 0 to disable
 *     (default 1024)
 */
public record RateLimitStoreOptions(
    Long maxKeys,
    Long idleMs,
    Long pruneEveryHits
) {
    public RateLimitStoreOptions() {
        this(null, null, null);
    }
}
