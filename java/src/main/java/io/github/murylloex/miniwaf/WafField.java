package io.github.murylloex.miniwaf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Objects;

/**
 * Supported request fields. Nested accessors use dotted paths in their
 * string form ({@code query.id}, {@code headers.user-agent}).
 *
 * <p>Multi-value fields ({@code QUERY}, {@code HEADERS}, {@code COOKIES},
 * {@code FILES}) yield every value, and a condition matches when any of
 * them does.
 */
public final class WafField {

    public static final WafField IP = new WafField(Kind.UNIT, "ip");
    public static final WafField METHOD = new WafField(Kind.UNIT, "method");
    public static final WafField PATH = new WafField(Kind.UNIT, "path");
    public static final WafField URL = new WafField(Kind.UNIT, "url");
    public static final WafField BODY = new WafField(Kind.UNIT, "body");
    public static final WafField FILES = new WafField(Kind.UNIT, "files");
    public static final WafField QUERY = new WafField(Kind.UNIT, "query");
    public static final WafField HEADERS = new WafField(Kind.UNIT, "headers");
    public static final WafField COOKIES = new WafField(Kind.UNIT, "cookies");

    private enum Kind {
        UNIT,
        QUERY_PARAM,
        HEADER,
        COOKIE,
    }

    private final Kind kind;
    private final String name;

    private WafField(Kind kind, String name) {
        this.kind = kind;
        this.name = Objects.requireNonNull(name);
    }

    /** {@code query.<name>} */
    public static WafField query(String name) {
        return new WafField(Kind.QUERY_PARAM, name);
    }

    /** {@code headers.<name>}; the name is matched lowercased. */
    public static WafField header(String name) {
        return new WafField(Kind.HEADER, name);
    }

    /** {@code cookies.<name>} */
    public static WafField cookie(String name) {
        return new WafField(Kind.COOKIE, name);
    }

    /**
     * Parse the dotted path form; throws {@link InvalidField} when unsupported.
     */
    public static WafField fromStr(String field) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment text = Native.text(arena, field);
            MemorySegment error = arena.allocate(Native.POINTER);
            MemorySegment handle = Api.wafFieldFromStr(
                text,
                Native.length(text),
                error
            );
            if (handle.equals(MemorySegment.NULL)) {
                throw new InvalidField(
                    Native.takeString(error.get(Native.POINTER, 0))
                );
            }
            try {
                return parsed(Native.takeString(Api.wafFieldToString(handle)));
            } finally {
                Api.wafFieldFree(handle);
            }
        }
    }

    /** A field from its (valid) path form. */
    private static WafField parsed(String path) {
        int dot = path.indexOf('.');
        if (dot < 0) {
            return new WafField(Kind.UNIT, path);
        }
        String name = path.substring(dot + 1);
        return switch (path.substring(0, dot)) {
            case "query" -> query(name);
            case "headers" -> header(name);
            default -> cookie(name);
        };
    }

    /** A native {@code WafField} handle; the caller frees it. */
    MemorySegment toNative(Arena arena) {
        MemorySegment text = Native.text(arena, name);
        long length = Native.length(text);
        return switch (kind) {
            case UNIT -> Api.wafFieldFromStr(text, length, MemorySegment.NULL);
            case QUERY_PARAM -> Api.wafFieldQuery(text, length);
            case HEADER -> Api.wafFieldHeader(text, length);
            case COOKIE -> Api.wafFieldCookie(text, length);
        };
    }

    /** The dotted path form. */
    @Override
    public String toString() {
        return switch (kind) {
            case UNIT -> name;
            case QUERY_PARAM -> "query." + name;
            case HEADER -> "headers." + name;
            case COOKIE -> "cookies." + name;
        };
    }

    @Override
    public boolean equals(Object other) {
        return (
            other instanceof WafField that &&
            kind == that.kind &&
            name.equals(that.name)
        );
    }

    @Override
    public int hashCode() {
        return Objects.hash(kind, name);
    }
}
