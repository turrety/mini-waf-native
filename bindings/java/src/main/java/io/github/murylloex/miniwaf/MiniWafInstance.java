package io.github.murylloex.miniwaf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * A WAF instance: presets and rules resolved, level-filtered, sorted and
 * compiled once. Thread-safe: build it at startup and share it across every
 * request handler.
 */
public final class MiniWafInstance extends NativeResource {

    MiniWafInstance(MemorySegment address) {
        super(address, Api::miniWafInstanceFree);
    }

    /** The active rules, in evaluation order. */
    public List<WafRule> rules() {
        return with(instance -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment count = arena.allocate(Native.SIZE);
                MemorySegment rules = Api.miniWafInstanceRules(instance, count);
                return views(rules, count.get(Native.SIZE, 0));
            }
        });
    }

    /**
     * Evaluate a request through its context. On block, calls
     * {@link WafHttpContext#drop} with the configured status and body;
     * rate-limited rules also set {@code X-RateLimit-*} response headers.
     */
    public WafEvaluationResult handle(WafHttpContext ctx) {
        Upcalls.Frame frame = new Upcalls.Frame(ctx, null, null);
        return with(instance ->
            Upcalls.within(frame, () -> {
                try (Arena arena = Arena.ofConfined()) {
                    MemorySegment table = Upcalls.contextTable(arena);
                    return result(Api.miniWafInstanceHandle(instance, table));
                }
            })
        );
    }

    /** Run the engine against an adapter and a native request / response. */
    public <TRequest, TResponse> WafEvaluationResult protect(
        CustomAdapter<TRequest, TResponse> adapter,
        TRequest request,
        TResponse response
    ) {
        Upcalls.Frame frame = new Upcalls.Frame(
            adapter.handlers,
            request,
            response
        );
        return with(instance ->
            adapter.with(nativeAdapter ->
                Upcalls.within(frame, () ->
                    result(
                        Api.miniWafInstanceProtect(
                            instance,
                            nativeAdapter,
                            MemorySegment.NULL,
                            MemorySegment.NULL
                        )
                    )
                )
            )
        );
    }

    private WafEvaluationResult result(MemorySegment result) {
        if (result.equals(MemorySegment.NULL)) {
            throw new IllegalStateException("mini-waf: evaluation failed");
        }
        try (Arena arena = Arena.ofConfined()) {
            WafDecision decision = WafDecision.values()[
                Api.wafEvaluationResultGetDecision(result)
            ];
            MemorySegment matched = Api.wafEvaluationResultGetMatchedRule(
                result
            );
            Optional<WafRule> matchedRule = matched.equals(MemorySegment.NULL)
                ? Optional.empty()
                : Optional.of(WafRule.view(matched, this));
            MemorySegment len = arena.allocate(Native.SIZE);
            MemorySegment reasonText = Api.wafEvaluationResultGetReason(
                result,
                len
            );
            String reason = Native.string(reasonText, len.get(Native.SIZE, 0));
            MemorySegment count = arena.allocate(Native.SIZE);
            MemorySegment logged = Api.wafEvaluationResultGetLoggedRules(
                result,
                count
            );
            List<WafRule> loggedRules = views(
                logged,
                count.get(Native.SIZE, 0)
            );
            return new WafEvaluationResult(
                decision,
                matchedRule,
                Optional.ofNullable(reason),
                loggedRules
            );
        } finally {
            Api.wafEvaluationResultFree(result);
        }
    }

    private List<WafRule> views(MemorySegment rules, long count) {
        MemorySegment array = rules.reinterpret(
            count * Native.POINTER.byteSize()
        );
        List<WafRule> views = new ArrayList<>((int) count);
        for (long index = 0; index < count; index++) {
            views.add(
                WafRule.view(array.getAtIndex(Native.POINTER, index), this)
            );
        }
        return List.copyOf(views);
    }
}
