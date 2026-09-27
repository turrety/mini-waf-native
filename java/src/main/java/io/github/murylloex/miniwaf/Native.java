package io.github.murylloex.miniwaf;

import java.lang.foreign.AddressLayout;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * The C API of {@code libmini_waf} ({@code mini_waf.h}), bound through the
 * Foreign Function &amp; Memory API.
 *
 * <p>The library is looked up in the directory named by the
 * {@code mini_waf.library.path} system property or the
 * {@code MINI_WAF_LIBRARY_PATH} environment variable, then on the system
 * library path ({@code LD_LIBRARY_PATH}, {@code PATH}, ...).
 */
final class Native {

    private Native() {}

    static final Linker LINKER = Linker.nativeLinker();
    static final SymbolLookup LIBRARY = loadLibrary();
    /** Marks {@link #SIZE} in function descriptors. */
    private static final String SIZE_T = "size_t";

    static final AddressLayout POINTER = ValueLayout.ADDRESS;
    /**
     * {@code size_t} as this platform defines it: 8 bytes on 64-bit
     * platforms, 4 on 32-bit ones. Java code always handles it as a
     * {@code long}; {@link #function} and {@link #upcall} convert.
     */
    static final ValueLayout SIZE = canonical("size_t").withName(SIZE_T);
    static final ValueLayout.OfInt ENUM = ValueLayout.JAVA_INT;
    static final ValueLayout.OfBoolean BOOL = ValueLayout.JAVA_BOOLEAN;
    static final ValueLayout.OfShort U16 = ValueLayout.JAVA_SHORT;
    /** {@code int64_t} / {@code uint64_t}, aligned as this platform does. */
    static final ValueLayout.OfLong I64 = (ValueLayout.OfLong) canonical(
        "long long"
    );
    static final ValueLayout.OfDouble F64 = ValueLayout.JAVA_DOUBLE;

    /** {@code MiniWafStr}: borrowed text. */
    static final StructLayout STR = MemoryLayout.structLayout(
        POINTER.withName("data"),
        SIZE.withName("len")
    );
    /** {@code RateLimitSpec}. */
    static final StructLayout RATE_LIMIT_SPEC = MemoryLayout.structLayout(
        I64.withName("max"),
        I64.withName("window_ms"),
        STR.withName("key_prefix")
    );
    /** {@code DecisionCacheConfig}. */
    static final StructLayout DECISION_CACHE_CONFIG = MemoryLayout.structLayout(
        POINTER.withName("max"),
        POINTER.withName("ttl_ms")
    );
    /** {@code DecodeConfig}. */
    static final StructLayout DECODE_CONFIG = MemoryLayout.structLayout(
        POINTER.withName("base64"),
        POINTER.withName("url"),
        POINTER.withName("comments")
    );
    /** {@code WafLoggingOptions}. */
    static final StructLayout LOGGING_OPTIONS = MemoryLayout.structLayout(
        POINTER.withName("level")
    );
    /** {@code UploadedFile}. */
    static final StructLayout UPLOADED_FILE = MemoryLayout.structLayout(
        STR.withName("fieldname"),
        STR.withName("name"),
        STR.withName("filename"),
        STR.withName("originalname")
    );

    private static ValueLayout canonical(String type) {
        return (ValueLayout) Linker.nativeLinker()
            .canonicalLayouts()
            .get(type);
    }

    private static SymbolLookup loadLibrary() {
        String name = System.mapLibraryName("mini_waf");
        String directory = System.getProperty(
            "mini_waf.library.path",
            System.getenv("MINI_WAF_LIBRARY_PATH")
        );
        if (directory != null) {
            Path path = Path.of(directory, name);
            if (Files.exists(path)) {
                return SymbolLookup.libraryLookup(path, Arena.global());
            }
        }
        return SymbolLookup.libraryLookup(name, Arena.global());
    }

    /** A downcall to the exported function {@code name}. */
    static MethodHandle function(String name, FunctionDescriptor descriptor) {
        MemorySegment symbol = LIBRARY.find(name).orElseThrow(() ->
            new UnsatisfiedLinkError("libmini_waf has no " + name)
        );
        MethodHandle handle = LINKER.downcallHandle(symbol, descriptor);
        return MethodHandles.explicitCastArguments(
            handle,
            widened(handle.type(), descriptor)
        );
    }

    /**
     * {@code type} with every {@code size_t} of {@code descriptor} as a
     * {@code long}. Leading parameters the descriptor does not list (the
     * allocator of a struct return) are kept.
     */
    private static MethodType widened(
        MethodType type,
        FunctionDescriptor descriptor
    ) {
        List<MemoryLayout> arguments = descriptor.argumentLayouts();
        int offset = type.parameterCount() - arguments.size();
        MethodType result = type;
        for (int index = 0; index < arguments.size(); index++) {
            if (isSize(arguments.get(index))) {
                result = result.changeParameterType(offset + index, long.class);
            }
        }
        boolean sizeResult = descriptor.returnLayout().map(Native::isSize)
            .orElse(false);
        return sizeResult ? result.changeReturnType(long.class) : result;
    }

    private static boolean isSize(MemoryLayout layout) {
        return layout.name().filter(SIZE_T::equals).isPresent();
    }

    /** Read a {@code size_t} at {@code offset}. */
    static long getSize(MemorySegment segment, long offset) {
        if (SIZE instanceof ValueLayout.OfLong wide) {
            return segment.get(wide, offset);
        }
        return Integer.toUnsignedLong(
            segment.get((ValueLayout.OfInt) SIZE, offset)
        );
    }

    /** The byte offset of the member {@code name} of {@code layout}. */
    static long offset(StructLayout layout, String name) {
        return layout.byteOffset(MemoryLayout.PathElement.groupElement(name));
    }

    /** A new {@code size_t} holding {@code value}. */
    static MemorySegment allocateSize(Arena arena, long value) {
        MemorySegment size = arena.allocate(SIZE);
        setSize(size, 0, value);
        return size;
    }

    /** Write a {@code size_t} at {@code offset}. */
    static void setSize(MemorySegment segment, long offset, long value) {
        if (SIZE instanceof ValueLayout.OfLong wide) {
            segment.set(wide, offset, value);
        } else {
            segment.set((ValueLayout.OfInt) SIZE, offset, (int) value);
        }
    }

    /**
     * A C function pointer to the static method {@code name} of the lookup
     * class.
     */
    static MemorySegment upcall(
        MethodHandles.Lookup lookup,
        String name,
        FunctionDescriptor descriptor
    ) {
        try {
            MethodType type = descriptor.toMethodType();
            MethodHandle target = lookup.findStatic(
                lookup.lookupClass(),
                name,
                widened(type, descriptor)
            );
            return LINKER.upcallStub(
                MethodHandles.explicitCastArguments(target, type),
                descriptor,
                Arena.global()
            );
        } catch (ReflectiveOperationException error) {
            throw new ExceptionInInitializerError(error);
        }
    }

    static FunctionDescriptor returns(
        MemoryLayout result,
        MemoryLayout... arguments
    ) {
        return FunctionDescriptor.of(result, arguments);
    }

    static FunctionDescriptor returnsVoid(MemoryLayout... arguments) {
        return FunctionDescriptor.ofVoid(arguments);
    }

    /** UTF-8 bytes of {@code text}, NUL-terminated, in {@code arena}. */
    static MemorySegment text(Arena arena, String text) {
        return arena.allocateFrom(text);
    }

    /** Byte length of a segment made by {@link #text}. */
    static long length(MemorySegment text) {
        return text.byteSize() - 1;
    }

    /** A {@code MiniWafStr} array of {@code values}. */
    static MemorySegment strs(Arena arena, List<String> values) {
        MemorySegment array = arena.allocate(STR, Math.max(1, values.size()));
        for (int index = 0; index < values.size(); index++) {
            writeStr(
                arena,
                array.asSlice(index * STR.byteSize(), STR),
                values.get(index)
            );
        }
        return array;
    }

    /**
     * An array of the resources' handles. The caller keeps {@code resources}
     * reachable until the native call returns.
     */
    static MemorySegment handles(
        Arena arena,
        List<? extends NativeResource> resources
    ) {
        MemorySegment array = arena.allocate(
            POINTER,
            Math.max(1, resources.size())
        );
        for (int index = 0; index < resources.size(); index++) {
            array.setAtIndex(POINTER, index, resources.get(index).address());
        }
        return array;
    }

    /**
     * Write a {@code MiniWafStr}: {@code NULL} data for a null {@code value}.
     */
    static void writeStr(Arena arena, MemorySegment str, String value) {
        if (value == null) {
            str.set(POINTER, 0, MemorySegment.NULL);
            setSize(str, POINTER.byteSize(), 0L);
            return;
        }
        MemorySegment bytes = text(arena, value);
        str.set(POINTER, 0, bytes);
        setSize(str, POINTER.byteSize(), length(bytes));
    }

    /**
     * Read {@code len} bytes of UTF-8 at {@code data}; null for {@code NULL}.
     */
    static String string(MemorySegment data, long len) {
        if (data.equals(MemorySegment.NULL)) {
            return null;
        }
        byte[] bytes = data.reinterpret(len).toArray(ValueLayout.JAVA_BYTE);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /** Read a NUL-terminated string the library allocated, then free it. */
    static String takeString(MemorySegment owned) {
        if (owned.equals(MemorySegment.NULL)) {
            return null;
        }
        try {
            return owned.reinterpret(Long.MAX_VALUE).getString(0);
        } finally {
            Api.stringFree(owned);
        }
    }

    /** Rethrow anything a downcall throws, which is only ever a bug here. */
    static RuntimeException rethrow(Throwable error) {
        if (error instanceof RuntimeException runtime) {
            return runtime;
        }
        if (error instanceof Error fatal) {
            throw fatal;
        }
        return new IllegalStateException(error);
    }
}
