package io.github.murylloex.miniwaf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.List;

/**
 * Match a single request field. With {@code matches} / {@code equals} /
 * {@code includes} the condition matches when any value satisfies any of
 * them. With only {@code rateLimit} it matches once the field's bucket
 * exceeds the limit; combined, the pattern gates the counter.
 *
 * <p>{@link #equals(String)} is the Rust builder of the same name: it sets
 * the value to compare with and returns this condition.
 */
public final class FieldCondition extends NativeResource {

    public FieldCondition(WafField field) {
        super(create(field), Api::fieldConditionFree);
    }

    private static MemorySegment create(WafField field) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment nativeField = field.toNative(arena);
            try {
                return Api.fieldConditionNew(nativeField);
            } finally {
                Api.wafFieldFree(nativeField);
            }
        }
    }

    /** Regex, exact string, list of strings (OR) or predicate. */
    public FieldCondition matches(MatchPattern pattern) {
        run(condition ->
            pattern.run(nativePattern ->
                Api.fieldConditionMatches(condition, nativePattern)
            )
        );
        return this;
    }

    /** Case-sensitive equality. */
    public FieldCondition equals(String value) {
        run(condition -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment text = Native.text(arena, value);
                Api.fieldConditionEquals(condition, text, Native.length(text));
            }
        });
        return this;
    }

    /** Case-insensitive substring. */
    public FieldCondition includes(String needle) {
        run(condition -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment text = Native.text(arena, needle);
                Api.fieldConditionIncludes(
                    condition,
                    text,
                    Native.length(text)
                );
            }
        });
        return this;
    }

    public FieldCondition rateLimit(RateLimitSpec spec) {
        run(condition -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment nativeSpec = arena.allocate(
                    Native.RATE_LIMIT_SPEC
                );
                nativeSpec.set(Native.I64, 0, spec.max());
                nativeSpec.set(Native.I64, 8, spec.windowMs());
                Native.writeStr(
                    arena,
                    nativeSpec.asSlice(16, Native.STR),
                    spec.keyPrefix().orElse(null)
                );
                Api.fieldConditionRateLimit(condition, nativeSpec);
            }
        });
        return this;
    }

    /**
     * Cheap prefilter: the value must contain one of these literals before
     * the pattern runs. List a literal every match contains, or the rule
     * stops detecting.
     */
    public FieldCondition requires(String... literals) {
        return requires(List.of(literals));
    }

    public FieldCondition requires(List<String> literals) {
        run(condition -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment strs = Native.strs(arena, literals);
                Api.fieldConditionRequires(condition, strs, literals.size());
            }
        });
        return this;
    }

    /**
     * {@code WafCondition::Field}: this condition as a {@link WafCondition}.
     */
    public WafCondition into() {
        return WafCondition.from(this);
    }
}
