package io.github.murylloex.miniwaf;

import static io.github.murylloex.miniwaf.Native.BOOL;
import static io.github.murylloex.miniwaf.Native.DECISION_CACHE_CONFIG;
import static io.github.murylloex.miniwaf.Native.DECODE_CONFIG;
import static io.github.murylloex.miniwaf.Native.ENUM;
import static io.github.murylloex.miniwaf.Native.F64;
import static io.github.murylloex.miniwaf.Native.I64;
import static io.github.murylloex.miniwaf.Native.LOGGING_OPTIONS;
import static io.github.murylloex.miniwaf.Native.POINTER;
import static io.github.murylloex.miniwaf.Native.RATE_LIMIT_SPEC;
import static io.github.murylloex.miniwaf.Native.SIZE;
import static io.github.murylloex.miniwaf.Native.U16;
import static io.github.murylloex.miniwaf.Native.function;
import static io.github.murylloex.miniwaf.Native.rethrow;
import static io.github.murylloex.miniwaf.Native.returns;
import static io.github.murylloex.miniwaf.Native.returnsVoid;

import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;

/**
 * One static method per function of {@code mini_waf.h}, named after it in
 * camelCase without the {@code mini_waf_} prefix. Generated from the header;
 * keep the two in sync.
 */
final class Api {

    private Api() {}

    private static final MethodHandle STRING_FREE = function(
        "mini_waf_string_free",
        returnsVoid(POINTER)
    );

    static void stringFree(MemorySegment string) {
        try {
            STRING_FREE.invokeExact(string);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle MATCH_PATTERN_REGEX = function(
        "mini_waf_match_pattern_regex",
        returns(POINTER, POINTER, SIZE, POINTER)
    );

    static MemorySegment matchPatternRegex(
        MemorySegment pattern,
        long patternLen,
        MemorySegment error
    ) {
        try {
            return (MemorySegment) MATCH_PATTERN_REGEX.invokeExact(
                pattern,
                patternLen,
                error
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle MATCH_PATTERN_REGEX_WITH_FLAGS = function(
        "mini_waf_match_pattern_regex_with_flags",
        returns(POINTER, POINTER, SIZE, POINTER, SIZE, POINTER)
    );

    static MemorySegment matchPatternRegexWithFlags(
        MemorySegment pattern,
        long patternLen,
        MemorySegment flags,
        long flagsLen,
        MemorySegment error
    ) {
        try {
            return (MemorySegment) MATCH_PATTERN_REGEX_WITH_FLAGS.invokeExact(
                pattern,
                patternLen,
                flags,
                flagsLen,
                error
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle MATCH_PATTERN_EXACT = function(
        "mini_waf_match_pattern_exact",
        returns(POINTER, POINTER, SIZE)
    );

    static MemorySegment matchPatternExact(MemorySegment value, long valueLen) {
        try {
            return (MemorySegment) MATCH_PATTERN_EXACT.invokeExact(
                value,
                valueLen
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle MATCH_PATTERN_ONE_OF = function(
        "mini_waf_match_pattern_one_of",
        returns(POINTER, POINTER, SIZE)
    );

    static MemorySegment matchPatternOneOf(MemorySegment values, long count) {
        try {
            return (MemorySegment) MATCH_PATTERN_ONE_OF.invokeExact(
                values,
                count
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle MATCH_PATTERN_PREDICATE = function(
        "mini_waf_match_pattern_predicate",
        returns(POINTER, POINTER, POINTER, POINTER)
    );

    static MemorySegment matchPatternPredicate(
        MemorySegment test,
        MemorySegment userData,
        MemorySegment drop
    ) {
        try {
            return (MemorySegment) MATCH_PATTERN_PREDICATE.invokeExact(
                test,
                userData,
                drop
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle MATCH_PATTERN_IS_MATCH = function(
        "mini_waf_match_pattern_is_match",
        returns(BOOL, POINTER, POINTER, SIZE)
    );

    static boolean matchPatternIsMatch(
        MemorySegment pattern,
        MemorySegment value,
        long valueLen
    ) {
        try {
            return (boolean) MATCH_PATTERN_IS_MATCH.invokeExact(
                pattern,
                value,
                valueLen
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle MATCH_PATTERN_FREE = function(
        "mini_waf_match_pattern_free",
        returnsVoid(POINTER)
    );

    static void matchPatternFree(MemorySegment pattern) {
        try {
            MATCH_PATTERN_FREE.invokeExact(pattern);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_FIELD_FROM_STR = function(
        "mini_waf_waf_field_from_str",
        returns(POINTER, POINTER, SIZE, POINTER)
    );

    static MemorySegment wafFieldFromStr(
        MemorySegment field,
        long fieldLen,
        MemorySegment error
    ) {
        try {
            return (MemorySegment) WAF_FIELD_FROM_STR.invokeExact(
                field,
                fieldLen,
                error
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_FIELD_QUERY = function(
        "mini_waf_waf_field_query",
        returns(POINTER, POINTER, SIZE)
    );

    static MemorySegment wafFieldQuery(MemorySegment name, long nameLen) {
        try {
            return (MemorySegment) WAF_FIELD_QUERY.invokeExact(name, nameLen);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_FIELD_HEADER = function(
        "mini_waf_waf_field_header",
        returns(POINTER, POINTER, SIZE)
    );

    static MemorySegment wafFieldHeader(MemorySegment name, long nameLen) {
        try {
            return (MemorySegment) WAF_FIELD_HEADER.invokeExact(name, nameLen);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_FIELD_COOKIE = function(
        "mini_waf_waf_field_cookie",
        returns(POINTER, POINTER, SIZE)
    );

    static MemorySegment wafFieldCookie(MemorySegment name, long nameLen) {
        try {
            return (MemorySegment) WAF_FIELD_COOKIE.invokeExact(name, nameLen);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_FIELD_TO_STRING = function(
        "mini_waf_waf_field_to_string",
        returns(POINTER, POINTER)
    );

    static MemorySegment wafFieldToString(MemorySegment field) {
        try {
            return (MemorySegment) WAF_FIELD_TO_STRING.invokeExact(field);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_FIELD_FREE = function(
        "mini_waf_waf_field_free",
        returnsVoid(POINTER)
    );

    static void wafFieldFree(MemorySegment field) {
        try {
            WAF_FIELD_FREE.invokeExact(field);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle FIELD_CONDITION_NEW = function(
        "mini_waf_field_condition_new",
        returns(POINTER, POINTER)
    );

    static MemorySegment fieldConditionNew(MemorySegment field) {
        try {
            return (MemorySegment) FIELD_CONDITION_NEW.invokeExact(field);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle FIELD_CONDITION_MATCHES = function(
        "mini_waf_field_condition_matches",
        returnsVoid(POINTER, POINTER)
    );

    static void fieldConditionMatches(
        MemorySegment condition,
        MemorySegment pattern
    ) {
        try {
            FIELD_CONDITION_MATCHES.invokeExact(condition, pattern);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle FIELD_CONDITION_EQUALS = function(
        "mini_waf_field_condition_equals",
        returnsVoid(POINTER, POINTER, SIZE)
    );

    static void fieldConditionEquals(
        MemorySegment condition,
        MemorySegment value,
        long valueLen
    ) {
        try {
            FIELD_CONDITION_EQUALS.invokeExact(condition, value, valueLen);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle FIELD_CONDITION_INCLUDES = function(
        "mini_waf_field_condition_includes",
        returnsVoid(POINTER, POINTER, SIZE)
    );

    static void fieldConditionIncludes(
        MemorySegment condition,
        MemorySegment needle,
        long needleLen
    ) {
        try {
            FIELD_CONDITION_INCLUDES.invokeExact(condition, needle, needleLen);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle FIELD_CONDITION_RATE_LIMIT = function(
        "mini_waf_field_condition_rate_limit",
        returnsVoid(POINTER, RATE_LIMIT_SPEC)
    );

    static void fieldConditionRateLimit(
        MemorySegment condition,
        MemorySegment spec
    ) {
        try {
            FIELD_CONDITION_RATE_LIMIT.invokeExact(condition, spec);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle FIELD_CONDITION_REQUIRES = function(
        "mini_waf_field_condition_requires",
        returnsVoid(POINTER, POINTER, SIZE)
    );

    static void fieldConditionRequires(
        MemorySegment condition,
        MemorySegment literals,
        long count
    ) {
        try {
            FIELD_CONDITION_REQUIRES.invokeExact(condition, literals, count);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle FIELD_CONDITION_FREE = function(
        "mini_waf_field_condition_free",
        returnsVoid(POINTER)
    );

    static void fieldConditionFree(MemorySegment condition) {
        try {
            FIELD_CONDITION_FREE.invokeExact(condition);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONDITION_FIELD = function(
        "mini_waf_waf_condition_field",
        returns(POINTER, POINTER)
    );

    static MemorySegment wafConditionField(MemorySegment condition) {
        try {
            return (MemorySegment) WAF_CONDITION_FIELD.invokeExact(condition);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONDITION_ALL = function(
        "mini_waf_waf_condition_all",
        returns(POINTER, POINTER, SIZE)
    );

    static MemorySegment wafConditionAll(MemorySegment conditions, long count) {
        try {
            return (MemorySegment) WAF_CONDITION_ALL.invokeExact(
                conditions,
                count
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONDITION_ANY_OF = function(
        "mini_waf_waf_condition_any_of",
        returns(POINTER, POINTER, SIZE)
    );

    static MemorySegment wafConditionAnyOf(
        MemorySegment conditions,
        long count
    ) {
        try {
            return (MemorySegment) WAF_CONDITION_ANY_OF.invokeExact(
                conditions,
                count
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONDITION_NOT = function(
        "mini_waf_waf_condition_not",
        returns(POINTER, POINTER)
    );

    static MemorySegment wafConditionNot(MemorySegment condition) {
        try {
            return (MemorySegment) WAF_CONDITION_NOT.invokeExact(condition);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONDITION_CLONE = function(
        "mini_waf_waf_condition_clone",
        returns(POINTER, POINTER)
    );

    static MemorySegment wafConditionClone(MemorySegment condition) {
        try {
            return (MemorySegment) WAF_CONDITION_CLONE.invokeExact(condition);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONDITION_FREE = function(
        "mini_waf_waf_condition_free",
        returnsVoid(POINTER)
    );

    static void wafConditionFree(MemorySegment condition) {
        try {
            WAF_CONDITION_FREE.invokeExact(condition);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_RULE_NEW = function(
        "mini_waf_waf_rule_new",
        returns(POINTER, POINTER, SIZE, POINTER, ENUM)
    );

    static MemorySegment wafRuleNew(
        MemorySegment id,
        long idLen,
        MemorySegment when,
        int action
    ) {
        try {
            return (MemorySegment) WAF_RULE_NEW.invokeExact(
                id,
                idLen,
                when,
                action
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_RULE_REASON = function(
        "mini_waf_waf_rule_reason",
        returnsVoid(POINTER, POINTER, SIZE)
    );

    static void wafRuleReason(
        MemorySegment rule,
        MemorySegment reason,
        long reasonLen
    ) {
        try {
            WAF_RULE_REASON.invokeExact(rule, reason, reasonLen);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_RULE_ENABLED = function(
        "mini_waf_waf_rule_enabled",
        returnsVoid(POINTER, BOOL)
    );

    static void wafRuleEnabled(MemorySegment rule, boolean enabled) {
        try {
            WAF_RULE_ENABLED.invokeExact(rule, enabled);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_RULE_PRIORITY = function(
        "mini_waf_waf_rule_priority",
        returnsVoid(POINTER, I64)
    );

    static void wafRulePriority(MemorySegment rule, long priority) {
        try {
            WAF_RULE_PRIORITY.invokeExact(rule, priority);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_RULE_MIN_LEVEL = function(
        "mini_waf_waf_rule_min_level",
        returnsVoid(POINTER, ENUM)
    );

    static void wafRuleMinLevel(MemorySegment rule, int level) {
        try {
            WAF_RULE_MIN_LEVEL.invokeExact(rule, level);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_RULE_GET_ID = function(
        "mini_waf_waf_rule_get_id",
        returns(POINTER, POINTER, POINTER)
    );

    static MemorySegment wafRuleGetId(MemorySegment rule, MemorySegment len) {
        try {
            return (MemorySegment) WAF_RULE_GET_ID.invokeExact(rule, len);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_RULE_GET_WHEN = function(
        "mini_waf_waf_rule_get_when",
        returns(POINTER, POINTER)
    );

    static MemorySegment wafRuleGetWhen(MemorySegment rule) {
        try {
            return (MemorySegment) WAF_RULE_GET_WHEN.invokeExact(rule);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_RULE_GET_ACTION = function(
        "mini_waf_waf_rule_get_action",
        returns(ENUM, POINTER)
    );

    static int wafRuleGetAction(MemorySegment rule) {
        try {
            return (int) WAF_RULE_GET_ACTION.invokeExact(rule);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_RULE_GET_REASON = function(
        "mini_waf_waf_rule_get_reason",
        returns(POINTER, POINTER, POINTER)
    );

    static MemorySegment wafRuleGetReason(
        MemorySegment rule,
        MemorySegment len
    ) {
        try {
            return (MemorySegment) WAF_RULE_GET_REASON.invokeExact(rule, len);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_RULE_GET_ENABLED = function(
        "mini_waf_waf_rule_get_enabled",
        returns(BOOL, POINTER, POINTER)
    );

    static boolean wafRuleGetEnabled(
        MemorySegment rule,
        MemorySegment enabled
    ) {
        try {
            return (boolean) WAF_RULE_GET_ENABLED.invokeExact(rule, enabled);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_RULE_GET_PRIORITY = function(
        "mini_waf_waf_rule_get_priority",
        returns(BOOL, POINTER, POINTER)
    );

    static boolean wafRuleGetPriority(
        MemorySegment rule,
        MemorySegment priority
    ) {
        try {
            return (boolean) WAF_RULE_GET_PRIORITY.invokeExact(rule, priority);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_RULE_GET_MIN_LEVEL = function(
        "mini_waf_waf_rule_get_min_level",
        returns(BOOL, POINTER, POINTER)
    );

    static boolean wafRuleGetMinLevel(MemorySegment rule, MemorySegment level) {
        try {
            return (boolean) WAF_RULE_GET_MIN_LEVEL.invokeExact(rule, level);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_RULE_CLONE = function(
        "mini_waf_waf_rule_clone",
        returns(POINTER, POINTER)
    );

    static MemorySegment wafRuleClone(MemorySegment rule) {
        try {
            return (MemorySegment) WAF_RULE_CLONE.invokeExact(rule);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_RULE_FREE = function(
        "mini_waf_waf_rule_free",
        returnsVoid(POINTER)
    );

    static void wafRuleFree(MemorySegment rule) {
        try {
            WAF_RULE_FREE.invokeExact(rule);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle PARSE_RULES_FROM_JSON = function(
        "mini_waf_parse_rules_from_json",
        returns(POINTER, POINTER, SIZE, POINTER, POINTER)
    );

    static MemorySegment parseRulesFromJson(
        MemorySegment input,
        long inputLen,
        MemorySegment count,
        MemorySegment error
    ) {
        try {
            return (MemorySegment) PARSE_RULES_FROM_JSON.invokeExact(
                input,
                inputLen,
                count,
                error
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_RULE_ARRAY_FREE = function(
        "mini_waf_waf_rule_array_free",
        returnsVoid(POINTER, SIZE)
    );

    static void wafRuleArrayFree(MemorySegment rules, long count) {
        try {
            WAF_RULE_ARRAY_FREE.invokeExact(rules, count);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONFIG_NEW = function(
        "mini_waf_waf_config_new",
        returns(POINTER)
    );

    static MemorySegment wafConfigNew() {
        try {
            return (MemorySegment) WAF_CONFIG_NEW.invokeExact();
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONFIG_FREE = function(
        "mini_waf_waf_config_free",
        returnsVoid(POINTER)
    );

    static void wafConfigFree(MemorySegment config) {
        try {
            WAF_CONFIG_FREE.invokeExact(config);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONFIG_LEVEL = function(
        "mini_waf_waf_config_level",
        returnsVoid(POINTER, ENUM)
    );

    static void wafConfigLevel(MemorySegment config, int level) {
        try {
            WAF_CONFIG_LEVEL.invokeExact(config, level);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONFIG_RULES = function(
        "mini_waf_waf_config_rules",
        returnsVoid(POINTER, POINTER, SIZE)
    );

    static void wafConfigRules(
        MemorySegment config,
        MemorySegment rules,
        long count
    ) {
        try {
            WAF_CONFIG_RULES.invokeExact(config, rules, count);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONFIG_PRESETS = function(
        "mini_waf_waf_config_presets",
        returnsVoid(POINTER, POINTER, SIZE)
    );

    static void wafConfigPresets(
        MemorySegment config,
        MemorySegment presets,
        long count
    ) {
        try {
            WAF_CONFIG_PRESETS.invokeExact(config, presets, count);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONFIG_ENABLED_RULE_IDS = function(
        "mini_waf_waf_config_enabled_rule_ids",
        returnsVoid(POINTER, POINTER, SIZE)
    );

    static void wafConfigEnabledRuleIds(
        MemorySegment config,
        MemorySegment ids,
        long count
    ) {
        try {
            WAF_CONFIG_ENABLED_RULE_IDS.invokeExact(config, ids, count);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONFIG_DISABLED_RULE_IDS = function(
        "mini_waf_waf_config_disabled_rule_ids",
        returnsVoid(POINTER, POINTER, SIZE)
    );

    static void wafConfigDisabledRuleIds(
        MemorySegment config,
        MemorySegment ids,
        long count
    ) {
        try {
            WAF_CONFIG_DISABLED_RULE_IDS.invokeExact(config, ids, count);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONFIG_BLOCK_STATUS_CODE = function(
        "mini_waf_waf_config_block_status_code",
        returnsVoid(POINTER, U16)
    );

    static void wafConfigBlockStatusCode(
        MemorySegment config,
        short statusCode
    ) {
        try {
            WAF_CONFIG_BLOCK_STATUS_CODE.invokeExact(config, statusCode);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONFIG_BLOCK_BODY = function(
        "mini_waf_waf_config_block_body",
        returnsVoid(POINTER, POINTER, SIZE)
    );

    static void wafConfigBlockBody(
        MemorySegment config,
        MemorySegment body,
        long bodyLen
    ) {
        try {
            WAF_CONFIG_BLOCK_BODY.invokeExact(config, body, bodyLen);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONFIG_LOGGING = function(
        "mini_waf_waf_config_logging",
        returnsVoid(POINTER, BOOL)
    );

    static void wafConfigLogging(MemorySegment config, boolean enabled) {
        try {
            WAF_CONFIG_LOGGING.invokeExact(config, enabled);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONFIG_LOGGING_OPTIONS = function(
        "mini_waf_waf_config_logging_options",
        returnsVoid(POINTER, LOGGING_OPTIONS)
    );

    static void wafConfigLoggingOptions(
        MemorySegment config,
        MemorySegment options
    ) {
        try {
            WAF_CONFIG_LOGGING_OPTIONS.invokeExact(config, options);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONFIG_MAX_FIELD_LENGTH = function(
        "mini_waf_waf_config_max_field_length",
        returnsVoid(POINTER, SIZE)
    );

    static void wafConfigMaxFieldLength(MemorySegment config, long length) {
        try {
            WAF_CONFIG_MAX_FIELD_LENGTH.invokeExact(config, length);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONFIG_MAX_RATE_LIMIT_KEYS = function(
        "mini_waf_waf_config_max_rate_limit_keys",
        returnsVoid(POINTER, SIZE)
    );

    static void wafConfigMaxRateLimitKeys(MemorySegment config, long keys) {
        try {
            WAF_CONFIG_MAX_RATE_LIMIT_KEYS.invokeExact(config, keys);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONFIG_DECISION_CACHE = function(
        "mini_waf_waf_config_decision_cache",
        returnsVoid(POINTER, DECISION_CACHE_CONFIG)
    );

    static void wafConfigDecisionCache(
        MemorySegment config,
        MemorySegment cache
    ) {
        try {
            WAF_CONFIG_DECISION_CACHE.invokeExact(config, cache);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_CONFIG_DECODE = function(
        "mini_waf_waf_config_decode",
        returnsVoid(POINTER, DECODE_CONFIG)
    );

    static void wafConfigDecode(MemorySegment config, MemorySegment decode) {
        try {
            WAF_CONFIG_DECODE.invokeExact(config, decode);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle STRING_SET = function(
        "mini_waf_string_set",
        returnsVoid(POINTER, POINTER, SIZE)
    );

    static void stringSet(
        MemorySegment out,
        MemorySegment value,
        long valueLen
    ) {
        try {
            STRING_SET.invokeExact(out, value, valueLen);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle HEADER_MAP_INSERT = function(
        "mini_waf_header_map_insert",
        returnsVoid(POINTER, POINTER, SIZE, POINTER, SIZE)
    );

    static void headerMapInsert(
        MemorySegment headers,
        MemorySegment name,
        long nameLen,
        MemorySegment values,
        long count
    ) {
        try {
            HEADER_MAP_INSERT.invokeExact(
                headers,
                name,
                nameLen,
                values,
                count
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle QUERY_MAP_NEW = function(
        "mini_waf_query_map_new",
        returns(POINTER)
    );

    static MemorySegment queryMapNew() {
        try {
            return (MemorySegment) QUERY_MAP_NEW.invokeExact();
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle QUERY_MAP_INSERT = function(
        "mini_waf_query_map_insert",
        returnsVoid(POINTER, POINTER, SIZE, POINTER)
    );

    static void queryMapInsert(
        MemorySegment query,
        MemorySegment key,
        long keyLen,
        MemorySegment value
    ) {
        try {
            QUERY_MAP_INSERT.invokeExact(query, key, keyLen, value);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle QUERY_MAP_FREE = function(
        "mini_waf_query_map_free",
        returnsVoid(POINTER)
    );

    static void queryMapFree(MemorySegment query) {
        try {
            QUERY_MAP_FREE.invokeExact(query);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle QUERY_VALUE_NULL = function(
        "mini_waf_query_value_null",
        returns(POINTER)
    );

    static MemorySegment queryValueNull() {
        try {
            return (MemorySegment) QUERY_VALUE_NULL.invokeExact();
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle QUERY_VALUE_BOOL = function(
        "mini_waf_query_value_bool",
        returns(POINTER, BOOL)
    );

    static MemorySegment queryValueBool(boolean value) {
        try {
            return (MemorySegment) QUERY_VALUE_BOOL.invokeExact(value);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle QUERY_VALUE_NUMBER = function(
        "mini_waf_query_value_number",
        returns(POINTER, F64)
    );

    static MemorySegment queryValueNumber(double value) {
        try {
            return (MemorySegment) QUERY_VALUE_NUMBER.invokeExact(value);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle QUERY_VALUE_STRING = function(
        "mini_waf_query_value_string",
        returns(POINTER, POINTER, SIZE)
    );

    static MemorySegment queryValueString(MemorySegment value, long valueLen) {
        try {
            return (MemorySegment) QUERY_VALUE_STRING.invokeExact(
                value,
                valueLen
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle QUERY_VALUE_ARRAY = function(
        "mini_waf_query_value_array",
        returns(POINTER, POINTER, SIZE)
    );

    static MemorySegment queryValueArray(MemorySegment values, long count) {
        try {
            return (MemorySegment) QUERY_VALUE_ARRAY.invokeExact(values, count);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle QUERY_VALUE_OBJECT = function(
        "mini_waf_query_value_object",
        returns(POINTER, POINTER)
    );

    static MemorySegment queryValueObject(MemorySegment map) {
        try {
            return (MemorySegment) QUERY_VALUE_OBJECT.invokeExact(map);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle QUERY_VALUE_FREE = function(
        "mini_waf_query_value_free",
        returnsVoid(POINTER)
    );

    static void queryValueFree(MemorySegment value) {
        try {
            QUERY_VALUE_FREE.invokeExact(value);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle COOKIE_MAP_INSERT = function(
        "mini_waf_cookie_map_insert",
        returnsVoid(POINTER, POINTER, SIZE, POINTER, SIZE)
    );

    static void cookieMapInsert(
        MemorySegment cookies,
        MemorySegment name,
        long nameLen,
        MemorySegment value,
        long valueLen
    ) {
        try {
            COOKIE_MAP_INSERT.invokeExact(
                cookies,
                name,
                nameLen,
                value,
                valueLen
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle RAW_BODY_TEXT = function(
        "mini_waf_raw_body_text",
        returnsVoid(POINTER, POINTER, SIZE)
    );

    static void rawBodyText(
        MemorySegment body,
        MemorySegment value,
        long valueLen
    ) {
        try {
            RAW_BODY_TEXT.invokeExact(body, value, valueLen);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle RAW_BODY_BYTES = function(
        "mini_waf_raw_body_bytes",
        returnsVoid(POINTER, POINTER, SIZE)
    );

    static void rawBodyBytes(
        MemorySegment body,
        MemorySegment value,
        long valueLen
    ) {
        try {
            RAW_BODY_BYTES.invokeExact(body, value, valueLen);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle FILES_BAG_LIST = function(
        "mini_waf_files_bag_list",
        returnsVoid(POINTER, POINTER, SIZE)
    );

    static void filesBagList(
        MemorySegment bag,
        MemorySegment files,
        long count
    ) {
        try {
            FILES_BAG_LIST.invokeExact(bag, files, count);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle FILES_BAG_FIELDS_INSERT = function(
        "mini_waf_files_bag_fields_insert",
        returnsVoid(POINTER, POINTER, SIZE, POINTER, SIZE)
    );

    static void filesBagFieldsInsert(
        MemorySegment bag,
        MemorySegment fieldname,
        long fieldnameLen,
        MemorySegment files,
        long count
    ) {
        try {
            FILES_BAG_FIELDS_INSERT.invokeExact(
                bag,
                fieldname,
                fieldnameLen,
                files,
                count
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle NORMALIZE_CLIENT_IP = function(
        "mini_waf_normalize_client_ip",
        returns(POINTER, POINTER, SIZE)
    );

    static MemorySegment normalizeClientIp(MemorySegment raw, long rawLen) {
        try {
            return (MemorySegment) NORMALIZE_CLIENT_IP.invokeExact(raw, rawLen);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle PICK_CLIENT_IP_FROM_XFF = function(
        "mini_waf_pick_client_ip_from_xff",
        returns(POINTER, POINTER, SIZE)
    );

    static MemorySegment pickClientIpFromXff(
        MemorySegment forwardedFor,
        long forwardedForLen
    ) {
        try {
            return (MemorySegment) PICK_CLIENT_IP_FROM_XFF.invokeExact(
                forwardedFor,
                forwardedForLen
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle IS_HOST_IP_LITERAL = function(
        "mini_waf_is_host_ip_literal",
        returns(BOOL, POINTER, SIZE)
    );

    static boolean isHostIpLiteral(
        MemorySegment hostHeader,
        long hostHeaderLen
    ) {
        try {
            return (boolean) IS_HOST_IP_LITERAL.invokeExact(
                hostHeader,
                hostHeaderLen
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CUSTOM_ADAPTER_HANDLERS_NEW = function(
        "mini_waf_custom_adapter_handlers_new",
        returns(POINTER, POINTER, SIZE)
    );

    static MemorySegment customAdapterHandlersNew(
        MemorySegment name,
        long nameLen
    ) {
        try {
            return (MemorySegment) CUSTOM_ADAPTER_HANDLERS_NEW.invokeExact(
                name,
                nameLen
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CUSTOM_ADAPTER_HANDLERS_FREE = function(
        "mini_waf_custom_adapter_handlers_free",
        returnsVoid(POINTER)
    );

    static void customAdapterHandlersFree(MemorySegment handlers) {
        try {
            CUSTOM_ADAPTER_HANDLERS_FREE.invokeExact(handlers);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CUSTOM_ADAPTER_HANDLERS_GET_METHOD =
        function(
            "mini_waf_custom_adapter_handlers_get_method",
            returnsVoid(POINTER, POINTER)
        );

    static void customAdapterHandlersGetMethod(
        MemorySegment handlers,
        MemorySegment handler
    ) {
        try {
            CUSTOM_ADAPTER_HANDLERS_GET_METHOD.invokeExact(handlers, handler);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CUSTOM_ADAPTER_HANDLERS_GET_URL =
        function(
            "mini_waf_custom_adapter_handlers_get_url",
            returnsVoid(POINTER, POINTER)
        );

    static void customAdapterHandlersGetUrl(
        MemorySegment handlers,
        MemorySegment handler
    ) {
        try {
            CUSTOM_ADAPTER_HANDLERS_GET_URL.invokeExact(handlers, handler);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CUSTOM_ADAPTER_HANDLERS_GET_PATH =
        function(
            "mini_waf_custom_adapter_handlers_get_path",
            returnsVoid(POINTER, POINTER)
        );

    static void customAdapterHandlersGetPath(
        MemorySegment handlers,
        MemorySegment handler
    ) {
        try {
            CUSTOM_ADAPTER_HANDLERS_GET_PATH.invokeExact(handlers, handler);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CUSTOM_ADAPTER_HANDLERS_GET_IP = function(
        "mini_waf_custom_adapter_handlers_get_ip",
        returnsVoid(POINTER, POINTER)
    );

    static void customAdapterHandlersGetIp(
        MemorySegment handlers,
        MemorySegment handler
    ) {
        try {
            CUSTOM_ADAPTER_HANDLERS_GET_IP.invokeExact(handlers, handler);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CUSTOM_ADAPTER_HANDLERS_GET_PROTOCOL =
        function(
            "mini_waf_custom_adapter_handlers_get_protocol",
            returnsVoid(POINTER, POINTER)
        );

    static void customAdapterHandlersGetProtocol(
        MemorySegment handlers,
        MemorySegment handler
    ) {
        try {
            CUSTOM_ADAPTER_HANDLERS_GET_PROTOCOL.invokeExact(handlers, handler);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CUSTOM_ADAPTER_HANDLERS_GET_LOCAL_PORT =
        function(
            "mini_waf_custom_adapter_handlers_get_local_port",
            returnsVoid(POINTER, POINTER)
        );

    static void customAdapterHandlersGetLocalPort(
        MemorySegment handlers,
        MemorySegment handler
    ) {
        try {
            CUSTOM_ADAPTER_HANDLERS_GET_LOCAL_PORT.invokeExact(
                handlers,
                handler
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CUSTOM_ADAPTER_HANDLERS_GET_HEADER =
        function(
            "mini_waf_custom_adapter_handlers_get_header",
            returnsVoid(POINTER, POINTER)
        );

    static void customAdapterHandlersGetHeader(
        MemorySegment handlers,
        MemorySegment handler
    ) {
        try {
            CUSTOM_ADAPTER_HANDLERS_GET_HEADER.invokeExact(handlers, handler);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CUSTOM_ADAPTER_HANDLERS_GET_HEADERS =
        function(
            "mini_waf_custom_adapter_handlers_get_headers",
            returnsVoid(POINTER, POINTER)
        );

    static void customAdapterHandlersGetHeaders(
        MemorySegment handlers,
        MemorySegment handler
    ) {
        try {
            CUSTOM_ADAPTER_HANDLERS_GET_HEADERS.invokeExact(handlers, handler);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CUSTOM_ADAPTER_HANDLERS_GET_QUERY =
        function(
            "mini_waf_custom_adapter_handlers_get_query",
            returnsVoid(POINTER, POINTER)
        );

    static void customAdapterHandlersGetQuery(
        MemorySegment handlers,
        MemorySegment handler
    ) {
        try {
            CUSTOM_ADAPTER_HANDLERS_GET_QUERY.invokeExact(handlers, handler);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CUSTOM_ADAPTER_HANDLERS_GET_COOKIES =
        function(
            "mini_waf_custom_adapter_handlers_get_cookies",
            returnsVoid(POINTER, POINTER)
        );

    static void customAdapterHandlersGetCookies(
        MemorySegment handlers,
        MemorySegment handler
    ) {
        try {
            CUSTOM_ADAPTER_HANDLERS_GET_COOKIES.invokeExact(handlers, handler);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CUSTOM_ADAPTER_HANDLERS_GET_RAW_BODY =
        function(
            "mini_waf_custom_adapter_handlers_get_raw_body",
            returnsVoid(POINTER, POINTER)
        );

    static void customAdapterHandlersGetRawBody(
        MemorySegment handlers,
        MemorySegment handler
    ) {
        try {
            CUSTOM_ADAPTER_HANDLERS_GET_RAW_BODY.invokeExact(handlers, handler);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CUSTOM_ADAPTER_HANDLERS_GET_FILES =
        function(
            "mini_waf_custom_adapter_handlers_get_files",
            returnsVoid(POINTER, POINTER)
        );

    static void customAdapterHandlersGetFiles(
        MemorySegment handlers,
        MemorySegment handler
    ) {
        try {
            CUSTOM_ADAPTER_HANDLERS_GET_FILES.invokeExact(handlers, handler);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle
        CUSTOM_ADAPTER_HANDLERS_SET_RESPONSE_HEADER = function(
            "mini_waf_custom_adapter_handlers_set_response_header",
            returnsVoid(POINTER, POINTER)
        );

    static void customAdapterHandlersSetResponseHeader(
        MemorySegment handlers,
        MemorySegment handler
    ) {
        try {
            CUSTOM_ADAPTER_HANDLERS_SET_RESPONSE_HEADER.invokeExact(
                handlers,
                handler
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle
        CUSTOM_ADAPTER_HANDLERS_REMOVE_RESPONSE_HEADER = function(
            "mini_waf_custom_adapter_handlers_remove_response_header",
            returnsVoid(POINTER, POINTER)
        );

    static void customAdapterHandlersRemoveResponseHeader(
        MemorySegment handlers,
        MemorySegment handler
    ) {
        try {
            CUSTOM_ADAPTER_HANDLERS_REMOVE_RESPONSE_HEADER.invokeExact(
                handlers,
                handler
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CUSTOM_ADAPTER_HANDLERS_DROP = function(
        "mini_waf_custom_adapter_handlers_drop",
        returnsVoid(POINTER, POINTER)
    );

    static void customAdapterHandlersDrop(
        MemorySegment handlers,
        MemorySegment handler
    ) {
        try {
            CUSTOM_ADAPTER_HANDLERS_DROP.invokeExact(handlers, handler);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CREATE_ADAPTER = function(
        "mini_waf_create_adapter",
        returns(POINTER, POINTER, POINTER)
    );

    static MemorySegment createAdapter(
        MemorySegment handlers,
        MemorySegment error
    ) {
        try {
            return (MemorySegment) CREATE_ADAPTER.invokeExact(handlers, error);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CUSTOM_ADAPTER_FREE = function(
        "mini_waf_custom_adapter_free",
        returnsVoid(POINTER)
    );

    static void customAdapterFree(MemorySegment adapter) {
        try {
            CUSTOM_ADAPTER_FREE.invokeExact(adapter);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle CREATE_MINI_WAF = function(
        "mini_waf_create_mini_waf",
        returns(POINTER, POINTER)
    );

    static MemorySegment createMiniWaf(MemorySegment config) {
        try {
            return (MemorySegment) CREATE_MINI_WAF.invokeExact(config);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle MINI_WAF_INSTANCE_FREE = function(
        "mini_waf_mini_waf_instance_free",
        returnsVoid(POINTER)
    );

    static void miniWafInstanceFree(MemorySegment instance) {
        try {
            MINI_WAF_INSTANCE_FREE.invokeExact(instance);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle MINI_WAF_INSTANCE_RULES = function(
        "mini_waf_mini_waf_instance_rules",
        returns(POINTER, POINTER, POINTER)
    );

    static MemorySegment miniWafInstanceRules(
        MemorySegment instance,
        MemorySegment count
    ) {
        try {
            return (MemorySegment) MINI_WAF_INSTANCE_RULES.invokeExact(
                instance,
                count
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle MINI_WAF_INSTANCE_HANDLE = function(
        "mini_waf_mini_waf_instance_handle",
        returns(POINTER, POINTER, POINTER)
    );

    static MemorySegment miniWafInstanceHandle(
        MemorySegment instance,
        MemorySegment ctx
    ) {
        try {
            return (MemorySegment) MINI_WAF_INSTANCE_HANDLE.invokeExact(
                instance,
                ctx
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle MINI_WAF_INSTANCE_PROTECT = function(
        "mini_waf_mini_waf_instance_protect",
        returns(POINTER, POINTER, POINTER, POINTER, POINTER)
    );

    static MemorySegment miniWafInstanceProtect(
        MemorySegment instance,
        MemorySegment adapter,
        MemorySegment request,
        MemorySegment response
    ) {
        try {
            return (MemorySegment) MINI_WAF_INSTANCE_PROTECT.invokeExact(
                instance,
                adapter,
                request,
                response
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_EVALUATION_RESULT_FREE = function(
        "mini_waf_waf_evaluation_result_free",
        returnsVoid(POINTER)
    );

    static void wafEvaluationResultFree(MemorySegment result) {
        try {
            WAF_EVALUATION_RESULT_FREE.invokeExact(result);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_EVALUATION_RESULT_GET_DECISION =
        function(
            "mini_waf_waf_evaluation_result_get_decision",
            returns(ENUM, POINTER)
        );

    static int wafEvaluationResultGetDecision(MemorySegment result) {
        try {
            return (int) WAF_EVALUATION_RESULT_GET_DECISION.invokeExact(result);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_EVALUATION_RESULT_GET_MATCHED_RULE =
        function(
            "mini_waf_waf_evaluation_result_get_matched_rule",
            returns(POINTER, POINTER)
        );

    static MemorySegment wafEvaluationResultGetMatchedRule(
        MemorySegment result
    ) {
        try {
            MethodHandle handle = WAF_EVALUATION_RESULT_GET_MATCHED_RULE;
            return (MemorySegment) handle.invokeExact(result);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_EVALUATION_RESULT_GET_REASON =
        function(
            "mini_waf_waf_evaluation_result_get_reason",
            returns(POINTER, POINTER, POINTER)
        );

    static MemorySegment wafEvaluationResultGetReason(
        MemorySegment result,
        MemorySegment len
    ) {
        try {
            return (MemorySegment) WAF_EVALUATION_RESULT_GET_REASON.invokeExact(
                result,
                len
            );
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }

    private static final MethodHandle WAF_EVALUATION_RESULT_GET_LOGGED_RULES =
        function(
            "mini_waf_waf_evaluation_result_get_logged_rules",
            returns(POINTER, POINTER, POINTER)
        );

    static MemorySegment wafEvaluationResultGetLoggedRules(
        MemorySegment result,
        MemorySegment count
    ) {
        try {
            MethodHandle handle = WAF_EVALUATION_RESULT_GET_LOGGED_RULES;
            return (MemorySegment) handle.invokeExact(result, count);
        } catch (Throwable failure) {
            throw rethrow(failure);
        }
    }
}
