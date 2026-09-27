package io.github.murylloex.miniwaf;

/** What a matching rule does. */
public enum WafAction {
    /** Stop evaluating and let the request through. */
    ALLOW,
    /** Reject the request (the first matching block wins). */
    BLOCK,
    /** Record the match and keep evaluating. */
    LOG;

    public String asStr() {
        return name().toLowerCase(java.util.Locale.ROOT);
    }
}
