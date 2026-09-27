package io.github.murylloex.miniwaf;

import static io.github.murylloex.miniwaf.Native.BOOL;
import static io.github.murylloex.miniwaf.Native.POINTER;
import static io.github.murylloex.miniwaf.Native.SIZE;
import static io.github.murylloex.miniwaf.Native.U16;
import static io.github.murylloex.miniwaf.Native.returns;
import static io.github.murylloex.miniwaf.Native.returnsVoid;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandles;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.function.Supplier;

/**
 * The callbacks the library makes while evaluating, and the per-thread
 * frames they read their Java target from.
 *
 * <p>Evaluation is synchronous: the library calls back on the thread that
 * called {@code handle} / {@code protect}, before it returns. So the target
 * travels in a thread-local frame, not through the native pointers. An
 * exception thrown by Java code is parked in the frame (it must not unwind
 * through native code) and rethrown once the native call returns.
 */
final class Upcalls {

    private Upcalls() {}

    /** One native call in progress on this thread. */
    static final class Frame {

        final Object target;
        final Object request;
        final Object response;
        Throwable error;

        Frame(Object target, Object request, Object response) {
            this.target = target;
            this.request = request;
            this.response = response;
        }
    }

    private static final ThreadLocal<ArrayDeque<Frame>> FRAMES =
        ThreadLocal.withInitial(ArrayDeque::new);

    /**
     * Run {@code body} inside {@code frame}, rethrowing what its callbacks
     * threw.
     */
    static <T> T within(Frame frame, Supplier<T> body) {
        ArrayDeque<Frame> frames = FRAMES.get();
        frames.push(frame);
        T result;
        try {
            result = body.get();
        } finally {
            frames.pop();
        }
        if (frame.error instanceof RuntimeException runtime) {
            throw runtime;
        }
        if (frame.error instanceof Error fatal) {
            throw fatal;
        }
        if (frame.error != null) {
            throw new IllegalStateException(frame.error);
        }
        return result;
    }

    /** Run {@code body} in a frame of its own, for predicates it may call. */
    static <T> T guarded(Supplier<T> body) {
        return within(new Frame(null, null, null), body);
    }

    /** Record {@code error} in the innermost frame (the first error wins). */
    static void fail(Throwable error) {
        Frame frame = FRAMES.get().peek();
        if (frame != null && frame.error == null) {
            frame.error = error;
        }
    }

    /** The innermost frame, or null once a callback in it has failed. */
    private static Frame live() {
        Frame frame = FRAMES.get().peek();
        return frame == null || frame.error != null ? null : frame;
    }

    private static WafHttpContext context() {
        Frame frame = live();
        return frame == null ? null : (WafHttpContext) frame.target;
    }

    @SuppressWarnings("unchecked")
    private static CustomAdapterHandlers<Object, Object> handlers(Frame frame) {
        return (CustomAdapterHandlers<Object, Object>) frame.target;
    }

    private static MemorySegment stub(
        String name,
        FunctionDescriptor descriptor
    ) {
        return Native.upcall(MethodHandles.lookup(), name, descriptor);
    }

    private static final FunctionDescriptor TEXT = returnsVoid(
        POINTER,
        POINTER
    );
    private static final FunctionDescriptor FILL = returnsVoid(
        POINTER,
        POINTER
    );

    /** A {@code WafHttpContext} table, in the order of the C struct. */
    static final List<MemorySegment> CONTEXT = List.of(
        stub("framework", TEXT),
        stub("contextMethod", TEXT),
        stub("contextUrl", TEXT),
        stub("contextPath", TEXT),
        stub("contextIp", TEXT),
        stub("contextProtocol", TEXT),
        stub("contextLocalPort", returns(U16, POINTER)),
        stub("contextHeader", returns(BOOL, POINTER, POINTER, SIZE, POINTER)),
        stub("contextHeaders", FILL),
        stub("contextQuery", FILL),
        stub("contextCookies", FILL),
        stub("contextRawBody", TEXT),
        stub("contextFiles", FILL),
        stub(
            "contextSetResponseHeader",
            returnsVoid(POINTER, POINTER, SIZE, POINTER, SIZE)
        ),
        stub(
            "contextRemoveResponseHeader",
            returnsVoid(POINTER, POINTER, SIZE)
        ),
        stub("contextIsBlocked", returns(BOOL, POINTER)),
        stub("contextDrop", returnsVoid(POINTER, POINTER, POINTER, SIZE))
    );

    /** Write a {@code WafHttpContext} struct: {@code self} then the table. */
    static MemorySegment contextTable(Arena arena) {
        MemorySegment table = arena.allocate(POINTER, CONTEXT.size() + 1L);
        table.setAtIndex(POINTER, 0, MemorySegment.NULL);
        for (int index = 0; index < CONTEXT.size(); index++) {
            table.setAtIndex(POINTER, index + 1L, CONTEXT.get(index));
        }
        return table;
    }

    private static void framework(MemorySegment self, MemorySegment out) {
        WafHttpContext ctx = context();
        if (ctx != null) {
            try {
                Fill.string(out, ctx.framework());
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void contextMethod(MemorySegment self, MemorySegment out) {
        WafHttpContext ctx = context();
        if (ctx != null) {
            try {
                Fill.string(out, ctx.getMethod());
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void contextUrl(MemorySegment self, MemorySegment out) {
        WafHttpContext ctx = context();
        if (ctx != null) {
            try {
                Fill.string(out, ctx.getUrl());
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void contextPath(MemorySegment self, MemorySegment out) {
        WafHttpContext ctx = context();
        if (ctx != null) {
            try {
                Fill.string(out, ctx.getPath());
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void contextIp(MemorySegment self, MemorySegment out) {
        WafHttpContext ctx = context();
        if (ctx != null) {
            try {
                Fill.string(out, ctx.getIp());
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void contextProtocol(MemorySegment self, MemorySegment out) {
        WafHttpContext ctx = context();
        if (ctx != null) {
            try {
                Fill.string(out, ctx.getProtocol());
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static short contextLocalPort(MemorySegment self) {
        WafHttpContext ctx = context();
        if (ctx != null) {
            try {
                return (short) ctx.getLocalPort();
            } catch (Throwable error) {
                fail(error);
            }
        }
        return 0;
    }

    private static boolean contextHeader(
        MemorySegment self,
        MemorySegment name,
        long nameLen,
        MemorySegment out
    ) {
        WafHttpContext ctx = context();
        if (ctx != null) {
            try {
                Optional<String> value = ctx.getHeader(
                    Native.string(name, nameLen)
                );
                value.ifPresent(text -> Fill.string(out, text));
                return value.isPresent();
            } catch (Throwable error) {
                fail(error);
            }
        }
        return false;
    }

    private static void contextHeaders(MemorySegment self, MemorySegment out) {
        WafHttpContext ctx = context();
        if (ctx != null) {
            try {
                Fill.headers(out, ctx.getHeaders());
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void contextQuery(MemorySegment self, MemorySegment out) {
        WafHttpContext ctx = context();
        if (ctx != null) {
            try {
                Fill.query(out, ctx.getQuery());
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void contextCookies(MemorySegment self, MemorySegment out) {
        WafHttpContext ctx = context();
        if (ctx != null) {
            try {
                Fill.cookies(out, ctx.getCookies());
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void contextRawBody(MemorySegment self, MemorySegment out) {
        WafHttpContext ctx = context();
        if (ctx != null) {
            try {
                Fill.string(out, ctx.getRawBody());
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void contextFiles(MemorySegment self, MemorySegment out) {
        WafHttpContext ctx = context();
        if (ctx != null) {
            try {
                Fill.files(out, FilesBag.from(ctx.getFiles()));
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void contextSetResponseHeader(
        MemorySegment self,
        MemorySegment name,
        long nameLen,
        MemorySegment value,
        long valueLen
    ) {
        WafHttpContext ctx = context();
        if (ctx != null) {
            try {
                ctx.setResponseHeader(
                    Native.string(name, nameLen),
                    Native.string(value, valueLen)
                );
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void contextRemoveResponseHeader(
        MemorySegment self,
        MemorySegment name,
        long nameLen
    ) {
        WafHttpContext ctx = context();
        if (ctx != null) {
            try {
                ctx.removeResponseHeader(Native.string(name, nameLen));
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static boolean contextIsBlocked(MemorySegment self) {
        WafHttpContext ctx = context();
        if (ctx != null) {
            try {
                return ctx.isBlocked();
            } catch (Throwable error) {
                fail(error);
            }
        }
        return false;
    }

    private static void contextDrop(
        MemorySegment self,
        MemorySegment statusCode,
        MemorySegment body,
        long bodyLen
    ) {
        WafHttpContext ctx = context();
        if (ctx != null) {
            try {
                OptionalInt status = statusCode.equals(MemorySegment.NULL)
                    ? OptionalInt.empty()
                    : OptionalInt.of(
                          Short.toUnsignedInt(
                              statusCode.reinterpret(2).get(U16, 0)
                          )
                      );
                ctx.drop(
                    status,
                    Optional.ofNullable(Native.string(body, bodyLen))
                );
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    /** The {@code CustomAdapterHandlers} callbacks, keyed by handler. */
    static final Map<String, MemorySegment> ADAPTER = Map.ofEntries(
        Map.entry("get_method", stub("adapterMethod", TEXT)),
        Map.entry("get_url", stub("adapterUrl", TEXT)),
        Map.entry("get_path", stub("adapterPath", TEXT)),
        Map.entry("get_ip", stub("adapterIp", TEXT)),
        Map.entry("get_protocol", stub("adapterProtocol", TEXT)),
        Map.entry(
            "get_local_port",
            stub("adapterLocalPort", returns(U16, POINTER, POINTER))
        ),
        Map.entry(
            "get_header",
            stub(
                "adapterHeader",
                returns(BOOL, POINTER, POINTER, SIZE, POINTER)
            )
        ),
        Map.entry("get_headers", stub("adapterHeaders", FILL)),
        Map.entry("get_query", stub("adapterQuery", FILL)),
        Map.entry("get_cookies", stub("adapterCookies", FILL)),
        Map.entry("get_raw_body", stub("adapterRawBody", FILL)),
        Map.entry("get_files", stub("adapterFiles", FILL)),
        Map.entry(
            "set_response_header",
            stub(
                "adapterSetResponseHeader",
                returnsVoid(POINTER, POINTER, SIZE, POINTER, SIZE)
            )
        ),
        Map.entry(
            "remove_response_header",
            stub(
                "adapterRemoveResponseHeader",
                returnsVoid(POINTER, POINTER, SIZE)
            )
        ),
        Map.entry(
            "drop",
            stub(
                "adapterDrop",
                returnsVoid(POINTER, POINTER, U16, POINTER, SIZE)
            )
        )
    );

    private static void adapterMethod(
        MemorySegment request,
        MemorySegment out
    ) {
        Frame frame = live();
        if (frame != null) {
            try {
                Fill.string(
                    out,
                    handlers(frame).getMethod.apply(frame.request)
                );
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void adapterUrl(MemorySegment request, MemorySegment out) {
        Frame frame = live();
        if (frame != null) {
            try {
                Fill.string(out, handlers(frame).getUrl.apply(frame.request));
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void adapterPath(MemorySegment request, MemorySegment out) {
        Frame frame = live();
        if (frame != null) {
            try {
                Fill.string(out, handlers(frame).getPath.apply(frame.request));
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void adapterIp(MemorySegment request, MemorySegment out) {
        Frame frame = live();
        if (frame != null) {
            try {
                Fill.string(out, handlers(frame).getIp.apply(frame.request));
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void adapterProtocol(
        MemorySegment request,
        MemorySegment out
    ) {
        Frame frame = live();
        if (frame != null) {
            try {
                Fill.string(
                    out,
                    handlers(frame).getProtocol.apply(frame.request)
                );
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static short adapterLocalPort(
        MemorySegment request,
        MemorySegment response
    ) {
        Frame frame = live();
        if (frame != null) {
            try {
                return (short) handlers(frame).getLocalPort.applyAsInt(
                    frame.request,
                    frame.response
                );
            } catch (Throwable error) {
                fail(error);
            }
        }
        return 0;
    }

    private static boolean adapterHeader(
        MemorySegment request,
        MemorySegment name,
        long nameLen,
        MemorySegment out
    ) {
        Frame frame = live();
        if (frame != null) {
            try {
                Optional<String> value = handlers(frame).getHeader.apply(
                    frame.request,
                    Native.string(name, nameLen)
                );
                value.ifPresent(text -> Fill.string(out, text));
                return value.isPresent();
            } catch (Throwable error) {
                fail(error);
            }
        }
        return false;
    }

    private static void adapterHeaders(
        MemorySegment request,
        MemorySegment out
    ) {
        Frame frame = live();
        if (frame != null) {
            try {
                Fill.headers(
                    out,
                    handlers(frame).getHeaders.apply(frame.request)
                );
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void adapterQuery(MemorySegment request, MemorySegment out) {
        Frame frame = live();
        if (frame != null) {
            try {
                Fill.query(out, handlers(frame).getQuery.apply(frame.request));
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void adapterCookies(
        MemorySegment request,
        MemorySegment out
    ) {
        Frame frame = live();
        if (frame != null) {
            try {
                Fill.cookies(
                    out,
                    handlers(frame).getCookies.apply(frame.request)
                );
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void adapterRawBody(
        MemorySegment request,
        MemorySegment out
    ) {
        Frame frame = live();
        if (frame != null) {
            try {
                Fill.body(out, handlers(frame).getRawBody.apply(frame.request));
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void adapterFiles(MemorySegment request, MemorySegment out) {
        Frame frame = live();
        if (frame != null) {
            try {
                Fill.files(out, handlers(frame).getFiles.apply(frame.request));
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void adapterSetResponseHeader(
        MemorySegment response,
        MemorySegment name,
        long nameLen,
        MemorySegment value,
        long valueLen
    ) {
        Frame frame = live();
        if (frame != null) {
            try {
                handlers(frame).setResponseHeader.set(
                    frame.response,
                    Native.string(name, nameLen),
                    Native.string(value, valueLen)
                );
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void adapterRemoveResponseHeader(
        MemorySegment response,
        MemorySegment name,
        long nameLen
    ) {
        Frame frame = live();
        if (frame != null) {
            try {
                handlers(frame).removeResponseHeader.accept(
                    frame.response,
                    Native.string(name, nameLen)
                );
            } catch (Throwable error) {
                fail(error);
            }
        }
    }

    private static void adapterDrop(
        MemorySegment request,
        MemorySegment response,
        short statusCode,
        MemorySegment body,
        long bodyLen
    ) {
        Frame frame = live();
        if (frame != null) {
            try {
                handlers(frame).drop.drop(
                    frame.request,
                    frame.response,
                    Short.toUnsignedInt(statusCode),
                    Native.string(body, bodyLen)
                );
            } catch (Throwable error) {
                fail(error);
            }
        }
    }
}
