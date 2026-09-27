package io.github.murylloex.miniwaf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

/**
 * The request of a log event: a read-only {@link WafHttpContext} over the
 * engine's, valid while the logger callback runs.
 */
final class ContextRef implements WafHttpContext {

    private final MemorySegment ctx;

    ContextRef(MemorySegment ctx) {
        this.ctx = ctx;
    }

    private interface TextGetter {
        MemorySegment get(MemorySegment ctx, MemorySegment len);
    }

    private String text(TextGetter getter) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment len = arena.allocate(Native.SIZE);
            MemorySegment data = getter.get(ctx, len);
            String value = Native.string(data, Native.getSize(len, 0));
            return value == null ? "" : value;
        }
    }

    @Override
    public String framework() {
        return text(Api::wafHttpContextRefFramework);
    }

    @Override
    public String getMethod() {
        return text(Api::wafHttpContextRefGetMethod);
    }

    @Override
    public String getUrl() {
        return text(Api::wafHttpContextRefGetUrl);
    }

    @Override
    public String getPath() {
        return text(Api::wafHttpContextRefGetPath);
    }

    @Override
    public String getIp() {
        return text(Api::wafHttpContextRefGetIp);
    }

    @Override
    public String getProtocol() {
        return text(Api::wafHttpContextRefGetProtocol);
    }

    @Override
    public int getLocalPort() {
        return Short.toUnsignedInt(Api.wafHttpContextRefGetLocalPort(ctx));
    }

    @Override
    public Optional<String> getHeader(String name) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment text = Native.text(arena, name);
            MemorySegment len = arena.allocate(Native.SIZE);
            MemorySegment value = Api.wafHttpContextRefGetHeader(
                ctx,
                text,
                Native.length(text),
                len
            );
            return Optional.ofNullable(
                Native.string(value, Native.getSize(len, 0))
            );
        }
    }

    @Override
    public HeaderMap getHeaders() {
        MemorySegment map = Api.wafHttpContextRefGetHeaders(ctx);
        HeaderMap headers = new HeaderMap();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment name = arena.allocate(Native.STR);
            MemorySegment multi = arena.allocate(Native.BOOL);
            MemorySegment count = arena.allocate(Native.SIZE);
            MemorySegment value = arena.allocate(Native.STR);
            for (
                long index = 0;
                Api.headerMapGetAt(map, index, name, multi, count);
                index++
            ) {
                List<String> values = new ArrayList<>();
                for (long item = 0; item < Native.getSize(count, 0); item++) {
                    Api.headerMapGetValueAt(map, index, item, value);
                    values.add(Native.readStr(value));
                }
                headers.put(
                    Native.readStr(name),
                    multi.get(Native.BOOL, 0)
                        ? HeaderValue.from(values)
                        : HeaderValue.from(values.get(0))
                );
            }
        }
        return headers;
    }

    @Override
    public QueryMap getQuery() {
        return query(Api.wafHttpContextRefGetQuery(ctx));
    }

    private static QueryMap query(MemorySegment map) {
        QueryMap query = new QueryMap();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocate(Native.STR);
            for (long index = 0; index < Api.queryMapLen(map); index++) {
                MemorySegment value = Api.queryMapGetAt(map, index, key);
                query.put(Native.readStr(key), queryValue(value));
            }
        }
        return query;
    }

    private static QueryValue queryValue(MemorySegment value) {
        return switch (Api.queryValueKind(value)) {
            case 1 -> new QueryValue.Bool(Api.queryValueGetBool(value));
            case 2 -> new QueryValue.Number(Api.queryValueGetNumber(value));
            case 3 -> {
                try (Arena arena = Arena.ofConfined()) {
                    MemorySegment text = arena.allocate(Native.STR);
                    Api.queryValueGetString(value, text);
                    yield new QueryValue.String(Native.readStr(text));
                }
            }
            case 4 -> {
                List<QueryValue> items = new ArrayList<>();
                long count = Api.queryValueArrayLen(value);
                for (long index = 0; index < count; index++) {
                    items.add(queryValue(Api.queryValueArrayGet(value, index)));
                }
                yield new QueryValue.Array(items);
            }
            case 5 -> new QueryValue.Object(
                query(Api.queryValueGetObject(value))
            );
            default -> new QueryValue.Null();
        };
    }

    @Override
    public CookieMap getCookies() {
        MemorySegment map = Api.wafHttpContextRefGetCookies(ctx);
        CookieMap cookies = new CookieMap();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment name = arena.allocate(Native.STR);
            MemorySegment value = arena.allocate(Native.STR);
            for (
                long index = 0;
                Api.cookieMapGetAt(map, index, name, value);
                index++
            ) {
                cookies.put(Native.readStr(name), Native.readStr(value));
            }
        }
        return cookies;
    }

    @Override
    public String getRawBody() {
        return text(Api::wafHttpContextRefGetRawBody);
    }

    @Override
    public List<UploadedFile> getFiles() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment count = arena.allocate(Native.SIZE);
            MemorySegment files = Api.wafHttpContextRefGetFiles(ctx, count);
            long size = Native.getSize(count, 0);
            MemorySegment array = files.reinterpret(
                size * Native.UPLOADED_FILE.byteSize()
            );
            List<UploadedFile> converted = new ArrayList<>();
            for (long index = 0; index < size; index++) {
                MemorySegment file = array.asSlice(
                    index * Native.UPLOADED_FILE.byteSize(),
                    Native.UPLOADED_FILE
                );
                converted.add(
                    new UploadedFile(
                        member(file, "fieldname"),
                        member(file, "name"),
                        member(file, "filename"),
                        member(file, "originalname")
                    )
                );
            }
            return List.copyOf(converted);
        }
    }

    private static String member(MemorySegment file, String name) {
        return Native.readStr(
            file.asSlice(
                Native.offset(Native.UPLOADED_FILE, name),
                Native.STR
            )
        );
    }

    @Override
    public void setResponseHeader(String name, String value) {
        throw readOnly();
    }

    @Override
    public void removeResponseHeader(String name) {
        throw readOnly();
    }

    @Override
    public boolean isBlocked() {
        return Api.wafHttpContextRefIsBlocked(ctx);
    }

    @Override
    public void drop(OptionalInt statusCode, Optional<String> body) {
        throw readOnly();
    }

    private static UnsupportedOperationException readOnly() {
        return new UnsupportedOperationException(
            "a logged request is read-only"
        );
    }
}
