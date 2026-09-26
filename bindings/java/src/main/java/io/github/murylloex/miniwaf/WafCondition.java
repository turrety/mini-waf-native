package io.github.murylloex.miniwaf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.ref.Reference;
import java.util.List;

/**
 * A rule condition: a field match, or {@code all} / {@code anyOf} /
 * {@code not}.
 */
public final class WafCondition extends NativeResource {

    WafCondition(MemorySegment address) {
        super(address, Api::wafConditionFree);
    }

    /**
     * {@code WafCondition::Field}, the {@code From<FieldCondition>} conversion.
     */
    public static WafCondition from(FieldCondition condition) {
        return condition.with(field ->
            new WafCondition(Api.wafConditionField(field))
        );
    }

    /** Logical AND. */
    public static WafCondition all(WafCondition... conditions) {
        return all(List.of(conditions));
    }

    public static WafCondition all(List<WafCondition> conditions) {
        return combine(conditions, true);
    }

    /** Logical OR. */
    public static WafCondition anyOf(WafCondition... conditions) {
        return anyOf(List.of(conditions));
    }

    public static WafCondition anyOf(List<WafCondition> conditions) {
        return combine(conditions, false);
    }

    /** Negation. */
    public static WafCondition not(WafCondition condition) {
        return condition.with(inner ->
            new WafCondition(Api.wafConditionNot(inner))
        );
    }

    public static WafCondition not(FieldCondition condition) {
        try (WafCondition inner = from(condition)) {
            return not(inner);
        }
    }

    private static WafCondition combine(
        List<WafCondition> conditions,
        boolean all
    ) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment array = Native.handles(arena, conditions);
            MemorySegment combined = all
                ? Api.wafConditionAll(array, conditions.size())
                : Api.wafConditionAnyOf(array, conditions.size());
            return new WafCondition(combined);
        } finally {
            Reference.reachabilityFence(conditions);
        }
    }
}
