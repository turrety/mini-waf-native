package io.github.murylloex.miniwaf;

import java.util.LinkedHashMap;

/** Query parameters ({@code name -> value}). */
public final class QueryMap extends LinkedHashMap<String, QueryValue> {

    private static final long serialVersionUID = 1L;

    /** Insert a string value. */
    public QueryMap insert(String name, String value) {
        put(name, QueryValue.from(value));
        return this;
    }
}
