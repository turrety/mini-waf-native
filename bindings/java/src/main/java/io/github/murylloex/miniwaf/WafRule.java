package io.github.murylloex.miniwaf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.function.Function;

/**
 * One WAF rule. Rules returned by a {@link MiniWafInstance} are views of the
 * instance's rules, valid until it is closed; the builder methods turn a
 * view into an independent copy first.
 */
public final class WafRule implements AutoCloseable {

    /** An owned native rule. */
    private static final class Owned extends NativeResource {

        Owned(MemorySegment address) {
            super(address, Api::wafRuleFree);
        }
    }

    private Owned owned;
    private final MemorySegment borrowed;
    private final NativeResource owner;

    public WafRule(String id, WafCondition when, WafAction action) {
        this(new Owned(create(id, when, action)), null, null);
    }

    public WafRule(String id, FieldCondition when, WafAction action) {
        this(id, WafCondition.from(when), action);
    }

    private WafRule(Owned owned, MemorySegment borrowed, NativeResource owner) {
        this.owned = owned;
        this.borrowed = borrowed;
        this.owner = owner;
    }

    private static MemorySegment create(
        String id,
        WafCondition when,
        WafAction action
    ) {
        return when.with(condition -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment text = Native.text(arena, id);
                return Api.wafRuleNew(
                    text,
                    Native.length(text),
                    condition,
                    action.ordinal()
                );
            }
        });
    }

    /** A view of a rule owned by {@code owner}. */
    static WafRule view(MemorySegment rule, NativeResource owner) {
        return new WafRule(null, rule, owner);
    }

    /** Take ownership of a library-allocated rule. */
    static WafRule owned(MemorySegment rule) {
        return new WafRule(new Owned(rule), null, null);
    }

    /** Run {@code body} with the native rule, keeping its owner alive. */
    <T> T with(Function<MemorySegment, T> body) {
        Owned current = owned;
        if (current != null) {
            return current.with(body);
        }
        return owner.with(ignored -> body.apply(borrowed));
    }

    /** Copy a view before its first change. */
    private MemorySegment mutable() {
        if (owned == null) {
            owned = new Owned(with(Api::wafRuleClone));
        }
        return owned.address();
    }

    private WafRule update(java.util.function.Consumer<MemorySegment> change) {
        try {
            change.accept(mutable());
        } finally {
            java.lang.ref.Reference.reachabilityFence(owned);
        }
        return this;
    }

    /** Human-readable reason used in logs / block responses. */
    public WafRule reason(String reason) {
        return update(rule -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment text = Native.text(arena, reason);
                Api.wafRuleReason(rule, text, Native.length(text));
            }
        });
    }

    /** Defaults to {@code true}. */
    public WafRule enabled(boolean enabled) {
        return update(rule -> Api.wafRuleEnabled(rule, enabled));
    }

    /** Lower numbers run first. Defaults to 100. */
    public WafRule priority(long priority) {
        return update(rule -> Api.wafRulePriority(rule, priority));
    }

    /**
     * Minimum protection level for this rule to run. Defaults to {@code LOW}.
     */
    public WafRule minLevel(ProtectionLevel level) {
        return update(rule -> Api.wafRuleMinLevel(rule, level.ordinal()));
    }

    public String id() {
        return with(rule -> readText(rule, Api::wafRuleGetId));
    }

    /** A copy of the rule's condition. */
    public WafCondition when() {
        return with(rule ->
            new WafCondition(Api.wafConditionClone(Api.wafRuleGetWhen(rule)))
        );
    }

    public WafAction action() {
        return with(rule -> WafAction.values()[Api.wafRuleGetAction(rule)]);
    }

    public Optional<String> reason() {
        return with(rule ->
            Optional.ofNullable(readText(rule, Api::wafRuleGetReason))
        );
    }

    public Optional<Boolean> enabled() {
        return with(rule -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment value = arena.allocate(Native.BOOL);
                return Api.wafRuleGetEnabled(rule, value)
                    ? Optional.of(value.get(Native.BOOL, 0))
                    : Optional.empty();
            }
        });
    }

    public OptionalLong priority() {
        return with(rule -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment value = arena.allocate(Native.I64);
                return Api.wafRuleGetPriority(rule, value)
                    ? OptionalLong.of(value.get(Native.I64, 0))
                    : OptionalLong.empty();
            }
        });
    }

    public Optional<ProtectionLevel> minLevel() {
        return with(rule -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment value = arena.allocate(Native.ENUM);
                return Api.wafRuleGetMinLevel(rule, value)
                    ? Optional.of(
                          ProtectionLevel.values()[value.get(Native.ENUM, 0)]
                      )
                    : Optional.empty();
            }
        });
    }

    private interface TextGetter {
        MemorySegment get(MemorySegment rule, MemorySegment len);
    }

    private static String readText(MemorySegment rule, TextGetter getter) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment len = arena.allocate(Native.SIZE);
            MemorySegment text = getter.get(rule, len);
            return Native.string(text, len.get(Native.SIZE, 0));
        }
    }

    @Override
    public String toString() {
        return "WafRule(" + id() + ")";
    }

    /** Free an owned rule now; a view is released with its instance. */
    @Override
    public void close() {
        if (owned != null) {
            owned.close();
        }
    }
}
