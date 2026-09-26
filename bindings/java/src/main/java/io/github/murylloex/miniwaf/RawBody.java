package io.github.murylloex.miniwaf;

import java.nio.charset.StandardCharsets;

/** A request body in whatever shape the framework produced it. */
public sealed interface RawBody {
    record Empty() implements RawBody {}

    record Text(String text) implements RawBody {}

    /** Bytes, decoded as UTF-8 (lossily) for inspection. */
    record Bytes(byte[] bytes) implements RawBody {
        public Bytes {
            bytes = bytes.clone();
        }

        @Override
        public byte[] bytes() {
            return bytes.clone();
        }

        @Override
        public boolean equals(java.lang.Object other) {
            return (
                other instanceof Bytes that &&
                java.util.Arrays.equals(bytes, that.bytes)
            );
        }

        @Override
        public int hashCode() {
            return java.util.Arrays.hashCode(bytes);
        }

        @Override
        public String toString() {
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    static RawBody from(String text) {
        return text == null ? new Empty() : new Text(text);
    }

    static RawBody from(byte[] bytes) {
        return bytes == null ? new Empty() : new Bytes(bytes);
    }
}
