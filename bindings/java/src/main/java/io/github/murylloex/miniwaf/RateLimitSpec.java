package io.github.murylloex.miniwaf;

import java.util.Optional;

/** Sliding-window rate limit of a field condition. */
public final class RateLimitSpec {

    private final long max;
    private final long windowMs;
    private String keyPrefix;

    /**
     * @param max maximum hits inside the window before the condition matches
     * @param windowMs sliding window length in milliseconds
     */
    public RateLimitSpec(long max, long windowMs) {
        this.max = max;
        this.windowMs = windowMs;
    }

    /**
     * Key override. Defaults to the resolved field value (the IP for
     * {@code ip}).
     */
    public RateLimitSpec keyPrefix(String prefix) {
        this.keyPrefix = prefix;
        return this;
    }

    public long max() {
        return max;
    }

    public long windowMs() {
        return windowMs;
    }

    public Optional<String> keyPrefix() {
        return Optional.ofNullable(keyPrefix);
    }
}
