package io.github.murylloex.miniwaf;

import java.lang.foreign.MemorySegment;
import java.lang.ref.Cleaner;
import java.lang.ref.Reference;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * An object owning one native handle. The handle is freed by {@link #close()}
 * or, failing that, once the object is unreachable.
 */
abstract class NativeResource implements AutoCloseable {

    private static final Cleaner CLEANER = Cleaner.create();

    /**
     * The handle and its release, shared with the cleaner (never {@code this}).
     */
    private static final class State implements Runnable {

        private final MemorySegment address;
        private final Consumer<MemorySegment> free;
        private volatile boolean closed;

        State(MemorySegment address, Consumer<MemorySegment> free) {
            this.address = address;
            this.free = free;
        }

        @Override
        public void run() {
            closed = true;
            free.accept(address);
        }
    }

    private final State state;
    private final Cleaner.Cleanable cleanable;

    NativeResource(MemorySegment address, Consumer<MemorySegment> free) {
        if (address.equals(MemorySegment.NULL)) {
            throw new IllegalStateException("mini-waf returned a null handle");
        }
        this.state = new State(address, free);
        this.cleanable = CLEANER.register(this, state);
    }

    /**
     * Run {@code body} with the handle, keeping this object alive meanwhile.
     */
    final <T> T with(Function<MemorySegment, T> body) {
        try {
            return body.apply(address());
        } finally {
            Reference.reachabilityFence(this);
        }
    }

    final void run(Consumer<MemorySegment> body) {
        with(address -> {
            body.accept(address);
            return null;
        });
    }

    /**
     * The handle. Callers keep this object reachable until the native call
     * returns ({@link Reference#reachabilityFence}), or use {@link #with}.
     */
    final MemorySegment address() {
        if (state.closed) {
            throw new IllegalStateException(
                getClass().getSimpleName() + " is closed"
            );
        }
        return state.address;
    }

    /**
     * Free the native handle now. Later uses throw
     * {@link IllegalStateException}.
     */
    @Override
    public void close() {
        cleanable.clean();
    }
}
