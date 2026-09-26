package io.github.murylloex.miniwaf;

import static io.github.murylloex.miniwaf.Native.BOOL;
import static io.github.murylloex.miniwaf.Native.POINTER;
import static io.github.murylloex.miniwaf.Native.SIZE;

import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandles;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;

/**
 * The Java predicates behind {@link MatchPattern#predicate}: the library
 * holds an id as {@code user_data} and calls back with it.
 */
final class Predicates {

    private Predicates() {}

    private static final Map<Long, Predicate<String>> REGISTRY =
        new ConcurrentHashMap<>();
    private static final AtomicLong NEXT_ID = new AtomicLong(1);

    static final MemorySegment TEST = Native.upcall(
        MethodHandles.lookup(),
        "test",
        Native.returns(BOOL, POINTER, POINTER, SIZE)
    );
    static final MemorySegment DROP = Native.upcall(
        MethodHandles.lookup(),
        "drop",
        Native.returnsVoid(POINTER)
    );

    /** Register {@code test}; the id travels as {@code user_data}. */
    static MemorySegment register(Predicate<String> test) {
        long id = NEXT_ID.getAndIncrement();
        REGISTRY.put(id, test);
        return MemorySegment.ofAddress(id);
    }

    /**
     * A throwing predicate counts as no match; the error surfaces from the
     * call.
     */
    private static boolean test(
        MemorySegment userData,
        MemorySegment value,
        long len
    ) {
        Predicate<String> test = REGISTRY.get(userData.address());
        try {
            return test != null && test.test(Native.string(value, len));
        } catch (Throwable error) {
            Upcalls.fail(error);
            return false;
        }
    }

    private static void drop(MemorySegment userData) {
        REGISTRY.remove(userData.address());
    }
}
