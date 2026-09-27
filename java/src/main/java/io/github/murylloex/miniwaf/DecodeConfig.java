package io.github.murylloex.miniwaf;

/**
 * {@code WafConfig.decode}: transport decoders. {@code null} members are
 * automatic: off at {@code LOW} / {@code BALANCED}, on at {@code HIGH}+.
 *
 * @param base64 whole-value Base64 blobs
 * @param url percent-encoding on surfaces the framework does not decode
 * @param comments inline SQL comments used as token separators
 */
public record DecodeConfig(Boolean base64, Boolean url, Boolean comments) {
    public DecodeConfig() {
        this(null, null, null);
    }
}
