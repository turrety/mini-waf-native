package io.github.murylloex.miniwaf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.ref.Reference;
import java.util.List;

/**
 * Everything the engine needs to build its immutable rule list. Every
 * setting is optional; unset ones take the documented defaults.
 */
public final class WafConfig extends NativeResource {

    public WafConfig() {
        super(Api.wafConfigNew(), Api::wafConfigFree);
    }

    /**
     * Only rules with {@code minLevel <= level} are applied. Default:
     * {@code BALANCED}.
     */
    public WafConfig level(ProtectionLevel level) {
        run(config -> Api.wafConfigLevel(config, level.ordinal()));
        return this;
    }

    /** Custom rules evaluated after (or instead of) presets. */
    public WafConfig rules(WafRule... rules) {
        return rules(List.of(rules));
    }

    public WafConfig rules(List<WafRule> rules) {
        run(config -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment array = arena.allocate(
                    Native.POINTER,
                    Math.max(1, rules.size())
                );
                for (int index = 0; index < rules.size(); index++) {
                    MemorySegment rule = rules
                        .get(index)
                        .with(address -> address);
                    array.setAtIndex(Native.POINTER, index, rule);
                }
                Api.wafConfigRules(config, array, rules.size());
            } finally {
                Reference.reachabilityFence(rules);
            }
        });
        return this;
    }

    /** Built-in rule packs to include. */
    public WafConfig presets(WafPresetName... presets) {
        return presets(List.of(presets));
    }

    public WafConfig presets(List<WafPresetName> presets) {
        run(config -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment array = arena.allocate(
                    Native.ENUM,
                    Math.max(1, presets.size())
                );
                for (int index = 0; index < presets.size(); index++) {
                    array.setAtIndex(
                        Native.ENUM,
                        index,
                        presets.get(index).ordinal()
                    );
                }
                Api.wafConfigPresets(config, array, presets.size());
            }
        });
        return this;
    }

    /**
     * Only these ids remain after presets + custom merge and level filtering.
     */
    public WafConfig enabledRuleIds(String... ids) {
        return enabledRuleIds(List.of(ids));
    }

    public WafConfig enabledRuleIds(List<String> ids) {
        run(config -> {
            try (Arena arena = Arena.ofConfined()) {
                Api.wafConfigEnabledRuleIds(
                    config,
                    Native.strs(arena, ids),
                    ids.size()
                );
            }
        });
        return this;
    }

    /** Drop rules whose id is listed. */
    public WafConfig disabledRuleIds(String... ids) {
        return disabledRuleIds(List.of(ids));
    }

    public WafConfig disabledRuleIds(List<String> ids) {
        run(config -> {
            try (Arena arena = Arena.ofConfined()) {
                Api.wafConfigDisabledRuleIds(
                    config,
                    Native.strs(arena, ids),
                    ids.size()
                );
            }
        });
        return this;
    }

    /** HTTP status used on block. Default: 403. */
    public WafConfig blockStatusCode(int statusCode) {
        run(config -> Api.wafConfigBlockStatusCode(config, (short) statusCode));
        return this;
    }

    /** Response body used on block. Default: {@code "Forbidden"}. */
    public WafConfig blockBody(String body) {
        run(config -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment text = Native.text(arena, body);
                Api.wafConfigBlockBody(config, text, Native.length(text));
            }
        });
        return this;
    }

    /**
     * Logging is off by default; {@code true} logs to the console at
     * {@code INFO}.
     */
    public WafConfig logging(boolean enabled) {
        run(config -> Api.wafConfigLogging(config, enabled));
        return this;
    }

    public WafConfig logging(WafLoggingOptions options) {
        run(config -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment nativeOptions = arena.allocate(
                    Native.LOGGING_OPTIONS
                );
                MemorySegment level = MemorySegment.NULL;
                if (options.level() != null) {
                    level = arena.allocate(Native.ENUM);
                    level.set(Native.ENUM, 0, options.level().ordinal());
                }
                nativeOptions.set(Native.POINTER, 0, level);
                Api.wafConfigLoggingOptions(config, nativeOptions);
            }
        });
        return this;
    }

    /** Cap length of each scanned field value. Default 8192; 0 is unlimited. */
    public WafConfig maxFieldLength(long length) {
        run(config -> Api.wafConfigMaxFieldLength(config, length));
        return this;
    }

    /** Cap on distinct rate-limit keys. Default 10000. */
    public WafConfig maxRateLimitKeys(long keys) {
        run(config -> Api.wafConfigMaxRateLimitKeys(config, keys));
        return this;
    }

    /** Disabled automatically when any active rule uses {@code rateLimit}. */
    public WafConfig decisionCache(DecisionCacheConfig cache) {
        run(config -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment nativeCache = arena.allocate(
                    Native.DECISION_CACHE_CONFIG
                );
                nativeCache.set(
                    Native.POINTER,
                    0,
                    optionalLong(arena, cache.max())
                );
                nativeCache.set(
                    Native.POINTER,
                    8,
                    optionalLong(arena, cache.ttlMs())
                );
                Api.wafConfigDecisionCache(config, nativeCache);
            }
        });
        return this;
    }

    /** Transport decoders; automatic (off below {@code HIGH}) when unset. */
    public WafConfig decode(DecodeConfig decode) {
        run(config -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment nativeDecode = arena.allocate(
                    Native.DECODE_CONFIG
                );
                nativeDecode.set(
                    Native.POINTER,
                    0,
                    optionalBool(arena, decode.base64())
                );
                nativeDecode.set(
                    Native.POINTER,
                    8,
                    optionalBool(arena, decode.url())
                );
                nativeDecode.set(
                    Native.POINTER,
                    16,
                    optionalBool(arena, decode.comments())
                );
                Api.wafConfigDecode(config, nativeDecode);
            }
        });
        return this;
    }

    private static MemorySegment optionalLong(Arena arena, Long value) {
        return value == null
            ? MemorySegment.NULL
            : arena.allocateFrom(Native.I64, value);
    }

    private static MemorySegment optionalBool(Arena arena, Boolean value) {
        if (value == null) {
            return MemorySegment.NULL;
        }
        MemorySegment flag = arena.allocate(Native.BOOL);
        flag.set(Native.BOOL, 0, value);
        return flag;
    }
}
