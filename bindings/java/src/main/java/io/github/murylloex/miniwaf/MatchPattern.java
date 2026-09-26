package io.github.murylloex.miniwaf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.List;
import java.util.function.Predicate;

/**
 * Match target of {@link FieldCondition#matches}: literal, regex, string
 * list, or predicate.
 */
public final class MatchPattern extends NativeResource {

    private MatchPattern(MemorySegment address) {
        super(address, Api::matchPatternFree);
    }

    /** Compile a regex pattern with no flags. */
    public static MatchPattern regex(String pattern) {
        return regexWithFlags(pattern, "");
    }

    /**
     * Compile a regex pattern with JavaScript-style flags ({@code "i"},
     * {@code "im"}, ...). The dialect is linear-time: no look-around, no
     * backreferences.
     */
    public static MatchPattern regexWithFlags(String pattern, String flags) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment text = Native.text(arena, pattern);
            MemorySegment flagText = Native.text(arena, flags);
            MemorySegment error = arena.allocate(Native.POINTER);
            MemorySegment handle = Api.matchPatternRegexWithFlags(
                text,
                Native.length(text),
                flagText,
                Native.length(flagText),
                error
            );
            if (handle.equals(MemorySegment.NULL)) {
                throw new RegexError(
                    Native.takeString(error.get(Native.POINTER, 0))
                );
            }
            return new MatchPattern(handle);
        }
    }

    /** Case-sensitive exact equality. */
    public static MatchPattern exact(String value) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment text = Native.text(arena, value);
            return new MatchPattern(
                Api.matchPatternExact(text, Native.length(text))
            );
        }
    }

    /** Exact equality with any of the listed strings. */
    public static MatchPattern oneOf(String... values) {
        return oneOf(List.of(values));
    }

    public static MatchPattern oneOf(List<String> values) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment strs = Native.strs(arena, values);
            return new MatchPattern(Api.matchPatternOneOf(strs, values.size()));
        }
    }

    /**
     * An arbitrary predicate. It runs on every evaluating thread, so it must
     * be thread-safe; an exception it throws counts as no match and is
     * rethrown by the evaluation.
     */
    public static MatchPattern predicate(Predicate<String> test) {
        MemorySegment userData = Predicates.register(test);
        return new MatchPattern(
            Api.matchPatternPredicate(
                Predicates.TEST,
                userData,
                Predicates.DROP
            )
        );
    }

    /** Test a candidate value. */
    public boolean isMatch(String value) {
        return with(pattern ->
            Upcalls.guarded(() -> {
                try (Arena arena = Arena.ofConfined()) {
                    MemorySegment text = Native.text(arena, value);
                    return Api.matchPatternIsMatch(
                        pattern,
                        text,
                        Native.length(text)
                    );
                }
            })
        );
    }
}
