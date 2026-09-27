package io.github.murylloex.miniwaf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * Rate-limit buckets an engine counts in. Give one to several instances
 * ({@link WafEngineOptions}) so they share counters, such as a rebuilt
 * instance taking over from the one it replaces. Instances using a store
 * keep it alive, so closing this reference early is safe.
 */
public final class RateLimitStore extends NativeResource {

    public RateLimitStore() {
        this(new RateLimitStoreOptions());
    }

    public RateLimitStore(RateLimitStoreOptions options) {
        this(create(options));
    }

    RateLimitStore(MemorySegment store) {
        super(store, Api::rateLimitStoreFree);
    }

    private static MemorySegment create(RateLimitStoreOptions options) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nativeOptions = arena.allocate(
                Native.RATE_LIMIT_STORE_OPTIONS
            );
            nativeOptions.set(
                Native.POINTER,
                Native.offset(Native.RATE_LIMIT_STORE_OPTIONS, "max_keys"),
                options.maxKeys() == null
                    ? MemorySegment.NULL
                    : Native.allocateSize(arena, options.maxKeys())
            );
            nativeOptions.set(
                Native.POINTER,
                Native.offset(Native.RATE_LIMIT_STORE_OPTIONS, "idle_ms"),
                optionalLong(arena, options.idleMs())
            );
            nativeOptions.set(
                Native.POINTER,
                Native.offset(
                    Native.RATE_LIMIT_STORE_OPTIONS,
                    "prune_every_hits"
                ),
                optionalLong(arena, options.pruneEveryHits())
            );
            return Api.rateLimitStoreNew(nativeOptions);
        }
    }

    private static MemorySegment optionalLong(Arena arena, Long value) {
        return value == null
            ? MemorySegment.NULL
            : arena.allocateFrom(Native.I64, value);
    }
}
