package io.github.murylloex.miniwaf;

/**
 * A query-string value. Frameworks with "extended" parsers turn
 * {@code ?filter[status]=open} into a nested object and {@code ?a[]=1&a[]=2}
 * into an array, so the model is recursive. The variants carry the Rust
 * names, so {@code QueryValue.String} and {@code QueryValue.Object} shadow
 * {@code java.lang} inside this type.
 */
public sealed interface QueryValue {
    record Null() implements QueryValue {}

    record Bool(boolean value) implements QueryValue {}

    record Number(double value) implements QueryValue {}

    record String(java.lang.String value) implements QueryValue {}

    record Array(java.util.List<QueryValue> values) implements QueryValue {
        public Array {
            values = java.util.List.copyOf(values);
        }
    }

    record Object(QueryMap map) implements QueryValue {}

    static QueryValue from(java.lang.String value) {
        return new String(value);
    }
}
