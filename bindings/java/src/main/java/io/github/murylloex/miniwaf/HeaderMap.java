package io.github.murylloex.miniwaf;

import java.util.LinkedHashMap;

/**
 * Request headers in arrival order. Keys should be lowercase, as HTTP/2 and
 * most frameworks already do; {@code headers.<name>} rules look names up
 * lowercased.
 */
public final class HeaderMap extends LinkedHashMap<String, HeaderValue> {

    private static final long serialVersionUID = 1L;

    /** Insert a single value. */
    public HeaderMap insert(String name, String value) {
        put(name, HeaderValue.from(value));
        return this;
    }
}
