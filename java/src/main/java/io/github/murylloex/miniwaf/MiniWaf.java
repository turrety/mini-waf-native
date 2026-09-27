package io.github.murylloex.miniwaf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.List;

/**
 * The free functions of the {@code mini_waf} crate, under their Rust names
 * in camelCase ({@code create_mini_waf} is {@link #createMiniWaf}).
 *
 * <pre>{@code
 * MiniWafInstance waf = MiniWaf.createMiniWaf(
 *     new WafConfig()
 *         .presets(WafPresetName.DEFAULT)
 *         .level(ProtectionLevel.BALANCED));
 * }</pre>
 */
public final class MiniWaf {

    private MiniWaf() {}

    /**
     * Build a WAF instance: the main entry point. Presets and rules are
     * resolved into a single immutable rule list, filtered by level.
     */
    public static MiniWafInstance createMiniWaf(WafConfig config) {
        return config.with(nativeConfig ->
            new MiniWafInstance(Api.createMiniWaf(nativeConfig))
        );
    }

    /**
     * {@link #createMiniWaf(WafConfig)} with engine-level injectables, such
     * as a logger or a shared rate-limit store.
     */
    public static MiniWafInstance createMiniWaf(
        WafConfig config,
        WafEngineOptions options
    ) {
        return config.with(nativeConfig -> {
            MemorySegment nativeOptions = Api.wafEngineOptionsNew();
            try (Arena arena = Arena.ofConfined()) {
                if (options.logger() != null) {
                    Api.wafEngineOptionsLogger(
                        nativeOptions,
                        Loggers.register(arena, options.logger())
                    );
                }
                RateLimitStore store = options.rateLimitStore();
                MemorySegment instance = store == null
                    ? Api.createMiniWafWithOptions(nativeConfig, nativeOptions)
                    : store.with(nativeStore -> {
                        Api.wafEngineOptionsRateLimitStore(
                            nativeOptions,
                            nativeStore
                        );
                        return Api.createMiniWafWithOptions(
                            nativeConfig,
                            nativeOptions
                        );
                    });
                return new MiniWafInstance(instance);
            } finally {
                Api.wafEngineOptionsFree(nativeOptions);
            }
        });
    }

    /**
     * Build a WAF adapter for any framework from typed request / response
     * mappers; throws {@link AdapterBuildError} listing every missing
     * required handler.
     */
    public static <TRequest, TResponse> CustomAdapter<
        TRequest,
        TResponse
    > createAdapter(CustomAdapterHandlers<TRequest, TResponse> handlers) {
        return new CustomAdapter<>(handlers);
    }

    /**
     * Parse a JSON rules document (an array of rules, or
     * {@code {"rules": [...]}}) into rules; throws {@link RuleParseError}.
     */
    public static List<WafRule> parseRulesFromJson(String input) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment text = Native.text(arena, input);
            MemorySegment count = arena.allocate(Native.SIZE);
            MemorySegment error = arena.allocate(Native.POINTER);
            MemorySegment rules = Api.parseRulesFromJson(
                text,
                Native.length(text),
                count,
                error
            );
            if (rules.equals(MemorySegment.NULL)) {
                throw new RuleParseError(
                    Native.takeString(error.get(Native.POINTER, 0))
                );
            }
            long size = Native.getSize(count, 0);
            MemorySegment array = rules.reinterpret(
                size * Native.POINTER.byteSize()
            );
            try {
                List<WafRule> parsed = new ArrayList<>();
                for (long index = 0; index < size; index++) {
                    MemorySegment rule = array.getAtIndex(
                        Native.POINTER,
                        index
                    );
                    parsed.add(WafRule.owned(Api.wafRuleClone(rule)));
                }
                return List.copyOf(parsed);
            } finally {
                Api.wafRuleArrayFree(rules, size);
            }
        }
    }

    /**
     * Normalize a client address: IPv4-mapped IPv6 to IPv4, ports and
     * brackets stripped.
     */
    public static String normalizeClientIp(String raw) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment text = Native.text(arena, raw);
            return Native.takeString(
                Api.normalizeClientIp(text, Native.length(text))
            );
        }
    }

    /** First hop of an {@code X-Forwarded-For} value, normalized. */
    public static String pickClientIpFromXff(String forwardedFor) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment text = Native.text(arena, forwardedFor);
            return Native.takeString(
                Api.pickClientIpFromXff(text, Native.length(text))
            );
        }
    }

    /**
     * Whether a {@code Host} header is a bare IP literal (with optional port).
     */
    public static boolean isHostIpLiteral(String hostHeader) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment text = Native.text(arena, hostHeader);
            return Api.isHostIpLiteral(text, Native.length(text));
        }
    }
}
