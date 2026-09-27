package io.github.murylloex.miniwaf;

import static io.github.murylloex.miniwaf.Native.LOGGER;
import static io.github.murylloex.miniwaf.Native.POINTER;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandles;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * The Java loggers behind {@link WafEngineOptions#logger}: the library holds
 * an id as {@code user_data} and calls back with it.
 */
final class Loggers {

    private Loggers() {}

    private static final Map<Long, WafLogger> REGISTRY =
        new ConcurrentHashMap<>();
    private static final AtomicLong NEXT_ID = new AtomicLong(1);

    private static final MemorySegment BLOCKED = Native.upcall(
        MethodHandles.lookup(),
        "blocked",
        Native.returnsVoid(POINTER, POINTER, POINTER)
    );
    private static final MemorySegment AUDIT = Native.upcall(
        MethodHandles.lookup(),
        "audit",
        Native.returnsVoid(POINTER, POINTER, POINTER)
    );
    private static final MemorySegment CONNECTION = Native.upcall(
        MethodHandles.lookup(),
        "connection",
        Native.returnsVoid(POINTER, POINTER)
    );
    private static final MemorySegment DROP = Native.upcall(
        MethodHandles.lookup(),
        "drop",
        Native.returnsVoid(POINTER)
    );

    /** A native {@code WafLogger} over {@code logger}, in {@code arena}. */
    static MemorySegment register(Arena arena, WafLogger logger) {
        long id = NEXT_ID.getAndIncrement();
        REGISTRY.put(id, logger);
        MemorySegment sink = arena.allocate(LOGGER);
        sink.set(
            POINTER,
            Native.offset(LOGGER, "user_data"),
            MemorySegment.ofAddress(id)
        );
        sink.set(POINTER, Native.offset(LOGGER, "blocked"), BLOCKED);
        sink.set(POINTER, Native.offset(LOGGER, "audit"), AUDIT);
        sink.set(POINTER, Native.offset(LOGGER, "connection"), CONNECTION);
        sink.set(POINTER, Native.offset(LOGGER, "drop"), DROP);
        return sink;
    }

    private static void blocked(
        MemorySegment userData,
        MemorySegment ctx,
        MemorySegment rule
    ) {
        event(userData, logger ->
            logger.blocked(new ContextRef(ctx), Upcalls.rule(rule))
        );
    }

    private static void audit(
        MemorySegment userData,
        MemorySegment ctx,
        MemorySegment rule
    ) {
        event(userData, logger ->
            logger.audit(new ContextRef(ctx), Upcalls.rule(rule))
        );
    }

    private static void connection(MemorySegment userData, MemorySegment ctx) {
        event(userData, logger -> logger.connection(new ContextRef(ctx)));
    }

    private static void drop(MemorySegment userData) {
        REGISTRY.remove(userData.address());
    }

    private static void event(
        MemorySegment userData,
        Consumer<WafLogger> body
    ) {
        WafLogger logger = REGISTRY.get(userData.address());
        if (logger == null) {
            return;
        }
        try {
            body.accept(logger);
        } catch (Throwable error) {
            Upcalls.fail(error);
        }
    }
}
