package io.github.murylloex.miniwaf;

import java.util.List;

/**
 * One header value; repeated headers ({@code Set-Cookie},
 * {@code X-Forwarded-For}) may arrive as several.
 */
public sealed interface HeaderValue {
    record Single(String value) implements HeaderValue {}

    record Multi(List<String> values) implements HeaderValue {
        public Multi {
            values = List.copyOf(values);
        }
    }

    static HeaderValue from(String value) {
        return new Single(value);
    }

    static HeaderValue from(List<String> values) {
        return new Multi(values);
    }
}
