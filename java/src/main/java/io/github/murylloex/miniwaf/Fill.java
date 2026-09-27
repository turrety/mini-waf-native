package io.github.murylloex.miniwaf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.List;
import java.util.Map;

/** Write Java values into the native out-parameters of callbacks. */
final class Fill {

    private Fill() {}

    static void string(MemorySegment out, String value) {
        if (value == null) {
            return;
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment text = Native.text(arena, value);
            Api.stringSet(out, text, Native.length(text));
        }
    }

    static void headers(MemorySegment out, HeaderMap headers) {
        if (headers == null) {
            return;
        }
        try (Arena arena = Arena.ofConfined()) {
            for (Map.Entry<String, HeaderValue> header : headers.entrySet()) {
                List<String> values = switch (header.getValue()) {
                    case HeaderValue.Single single -> List.of(single.value());
                    case HeaderValue.Multi multi -> multi.values();
                };
                MemorySegment name = Native.text(arena, header.getKey());
                Api.headerMapInsert(
                    out,
                    name,
                    Native.length(name),
                    Native.strs(arena, values),
                    values.size()
                );
            }
        }
    }

    static void query(MemorySegment out, QueryMap query) {
        if (query == null) {
            return;
        }
        try (Arena arena = Arena.ofConfined()) {
            for (Map.Entry<String, QueryValue> entry : query.entrySet()) {
                MemorySegment key = Native.text(arena, entry.getKey());
                MemorySegment value = queryValue(entry.getValue());
                try {
                    Api.queryMapInsert(out, key, Native.length(key), value);
                } finally {
                    Api.queryValueFree(value);
                }
            }
        }
    }

    /** A native {@code QueryValue}; the caller frees it. */
    private static MemorySegment queryValue(QueryValue value) {
        return switch (value) {
            case QueryValue.Null ignored -> Api.queryValueNull();
            case QueryValue.Bool flag -> Api.queryValueBool(flag.value());
            case QueryValue.Number number -> Api.queryValueNumber(
                number.value()
            );
            case QueryValue.String text -> {
                try (Arena arena = Arena.ofConfined()) {
                    MemorySegment bytes = Native.text(arena, text.value());
                    yield Api.queryValueString(bytes, Native.length(bytes));
                }
            }
            case QueryValue.Array array -> queryArray(array.values());
            case QueryValue.Object object -> {
                MemorySegment map = Api.queryMapNew();
                try {
                    query(map, object.map());
                    yield Api.queryValueObject(map);
                } finally {
                    Api.queryMapFree(map);
                }
            }
        };
    }

    private static MemorySegment queryArray(List<QueryValue> values) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment items = arena.allocate(
                Native.POINTER,
                Math.max(1, values.size())
            );
            for (int index = 0; index < values.size(); index++) {
                items.setAtIndex(
                    Native.POINTER,
                    index,
                    queryValue(values.get(index))
                );
            }
            try {
                return Api.queryValueArray(items, values.size());
            } finally {
                for (int index = 0; index < values.size(); index++) {
                    Api.queryValueFree(items.getAtIndex(Native.POINTER, index));
                }
            }
        }
    }

    static void cookies(MemorySegment out, CookieMap cookies) {
        if (cookies == null) {
            return;
        }
        try (Arena arena = Arena.ofConfined()) {
            for (Map.Entry<String, String> cookie : cookies.entrySet()) {
                MemorySegment name = Native.text(arena, cookie.getKey());
                MemorySegment value = Native.text(arena, cookie.getValue());
                Api.cookieMapInsert(
                    out,
                    name,
                    Native.length(name),
                    value,
                    Native.length(value)
                );
            }
        }
    }

    static void body(MemorySegment out, RawBody body) {
        if (body == null) {
            return;
        }
        try (Arena arena = Arena.ofConfined()) {
            switch (body) {
                case RawBody.Empty ignored -> {
                }
                case RawBody.Text text -> {
                    MemorySegment bytes = Native.text(arena, text.text());
                    Api.rawBodyText(out, bytes, Native.length(bytes));
                }
                case RawBody.Bytes bytes -> {
                    byte[] data = bytes.bytes();
                    MemorySegment segment = arena.allocate(
                        Math.max(1, data.length)
                    );
                    MemorySegment.copy(
                        data,
                        0,
                        segment,
                        java.lang.foreign.ValueLayout.JAVA_BYTE,
                        0,
                        data.length
                    );
                    Api.rawBodyBytes(out, segment, data.length);
                }
            }
        }
    }

    static void files(MemorySegment out, FilesBag bag) {
        if (bag == null) {
            return;
        }
        try (Arena arena = Arena.ofConfined()) {
            switch (bag) {
                case FilesBag.List list -> Api.filesBagList(
                    out,
                    uploadedFiles(arena, list.files()),
                    list.files().size()
                );
                case FilesBag.Fields fields -> {
                    for (Map.Entry<String, List<UploadedFile>> field : fields
                        .fields()
                        .entrySet()) {
                        MemorySegment name = Native.text(arena, field.getKey());
                        List<UploadedFile> files = field.getValue();
                        Api.filesBagFieldsInsert(
                            out,
                            name,
                            Native.length(name),
                            uploadedFiles(arena, files),
                            files.size()
                        );
                    }
                }
            }
        }
    }

    private static MemorySegment uploadedFiles(
        Arena arena,
        List<UploadedFile> files
    ) {
        long size = Native.UPLOADED_FILE.byteSize();
        long str = Native.STR.byteSize();
        MemorySegment array = arena.allocate(
            Native.UPLOADED_FILE,
            Math.max(1, files.size())
        );
        for (int index = 0; index < files.size(); index++) {
            UploadedFile file = files.get(index);
            MemorySegment item = array.asSlice(index * size, size);
            Native.writeStr(arena, item.asSlice(0, str), file.fieldname());
            Native.writeStr(arena, item.asSlice(str, str), file.name());
            Native.writeStr(arena, item.asSlice(2 * str, str), file.filename());
            Native.writeStr(
                arena,
                item.asSlice(3 * str, str),
                file.originalname()
            );
        }
        return array;
    }
}
