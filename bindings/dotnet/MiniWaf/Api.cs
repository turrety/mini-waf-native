// Generated from mini_waf.h: one method per C function, named after it in
// PascalCase without the mini_waf_ prefix. Keep the two in sync.

using System.Runtime.InteropServices;

namespace MurylloEx.MiniWaf;

internal static partial class Api
{
    private const string Library = "mini_waf";

    [LibraryImport(Library, EntryPoint = "mini_waf_string_free")]
    internal static partial void StringFree(nint @string);

    [LibraryImport(Library, EntryPoint = "mini_waf_match_pattern_regex")]
    internal static partial nint MatchPatternRegex(
        nint pattern,
        nuint patternLen,
        nint error
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_match_pattern_regex_with_flags"
    )]
    internal static partial nint MatchPatternRegexWithFlags(
        nint pattern,
        nuint patternLen,
        nint flags,
        nuint flagsLen,
        nint error
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_match_pattern_exact")]
    internal static partial nint MatchPatternExact(nint value, nuint valueLen);

    [LibraryImport(Library, EntryPoint = "mini_waf_match_pattern_one_of")]
    internal static partial nint MatchPatternOneOf(nint values, nuint count);

    [LibraryImport(Library, EntryPoint = "mini_waf_match_pattern_predicate")]
    internal static partial nint MatchPatternPredicate(
        nint test,
        nint userData,
        nint drop
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_match_pattern_is_match")]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static partial bool MatchPatternIsMatch(
        nint pattern,
        nint value,
        nuint valueLen
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_match_pattern_free")]
    internal static partial void MatchPatternFree(nint pattern);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_field_from_str")]
    internal static partial nint WafFieldFromStr(
        nint field,
        nuint fieldLen,
        nint error
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_field_query")]
    internal static partial nint WafFieldQuery(nint name, nuint nameLen);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_field_header")]
    internal static partial nint WafFieldHeader(nint name, nuint nameLen);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_field_cookie")]
    internal static partial nint WafFieldCookie(nint name, nuint nameLen);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_field_to_string")]
    internal static partial nint WafFieldToString(nint field);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_field_free")]
    internal static partial void WafFieldFree(nint field);

    [LibraryImport(Library, EntryPoint = "mini_waf_field_condition_new")]
    internal static partial nint FieldConditionNew(nint field);

    [LibraryImport(Library, EntryPoint = "mini_waf_field_condition_matches")]
    internal static partial void FieldConditionMatches(
        nint condition,
        nint pattern
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_field_condition_equals")]
    internal static partial void FieldConditionEquals(
        nint condition,
        nint value,
        nuint valueLen
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_field_condition_includes")]
    internal static partial void FieldConditionIncludes(
        nint condition,
        nint needle,
        nuint needleLen
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_field_condition_rate_limit")]
    internal static partial void FieldConditionRateLimit(
        nint condition,
        RateLimitSpecNative spec
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_field_condition_requires")]
    internal static partial void FieldConditionRequires(
        nint condition,
        nint literals,
        nuint count
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_field_condition_free")]
    internal static partial void FieldConditionFree(nint condition);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_condition_field")]
    internal static partial nint WafConditionField(nint condition);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_condition_all")]
    internal static partial nint WafConditionAll(nint conditions, nuint count);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_condition_any_of")]
    internal static partial nint WafConditionAnyOf(
        nint conditions,
        nuint count
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_condition_not")]
    internal static partial nint WafConditionNot(nint condition);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_condition_clone")]
    internal static partial nint WafConditionClone(nint condition);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_condition_free")]
    internal static partial void WafConditionFree(nint condition);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_rule_new")]
    internal static partial nint WafRuleNew(
        nint id,
        nuint idLen,
        nint when,
        int action
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_rule_reason")]
    internal static partial void WafRuleReason(
        nint rule,
        nint reason,
        nuint reasonLen
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_rule_enabled")]
    internal static partial void WafRuleEnabled(
        nint rule,
        [MarshalAs(UnmanagedType.U1)] bool enabled
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_rule_priority")]
    internal static partial void WafRulePriority(nint rule, long priority);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_rule_min_level")]
    internal static partial void WafRuleMinLevel(nint rule, int level);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_rule_get_id")]
    internal static partial nint WafRuleGetId(nint rule, nint len);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_rule_get_when")]
    internal static partial nint WafRuleGetWhen(nint rule);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_rule_get_action")]
    internal static partial int WafRuleGetAction(nint rule);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_rule_get_reason")]
    internal static partial nint WafRuleGetReason(nint rule, nint len);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_rule_get_enabled")]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static partial bool WafRuleGetEnabled(nint rule, nint enabled);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_rule_get_priority")]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static partial bool WafRuleGetPriority(nint rule, nint priority);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_rule_get_min_level")]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static partial bool WafRuleGetMinLevel(nint rule, nint level);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_rule_clone")]
    internal static partial nint WafRuleClone(nint rule);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_rule_free")]
    internal static partial void WafRuleFree(nint rule);

    [LibraryImport(Library, EntryPoint = "mini_waf_parse_rules_from_json")]
    internal static partial nint ParseRulesFromJson(
        nint input,
        nuint inputLen,
        nint count,
        nint error
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_rule_array_free")]
    internal static partial void WafRuleArrayFree(nint rules, nuint count);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_config_new")]
    internal static partial nint WafConfigNew();

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_config_free")]
    internal static partial void WafConfigFree(nint config);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_config_level")]
    internal static partial void WafConfigLevel(nint config, int level);

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_config_rules")]
    internal static partial void WafConfigRules(
        nint config,
        nint rules,
        nuint count
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_config_presets")]
    internal static partial void WafConfigPresets(
        nint config,
        nint presets,
        nuint count
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_waf_config_enabled_rule_ids"
    )]
    internal static partial void WafConfigEnabledRuleIds(
        nint config,
        nint ids,
        nuint count
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_waf_config_disabled_rule_ids"
    )]
    internal static partial void WafConfigDisabledRuleIds(
        nint config,
        nint ids,
        nuint count
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_waf_config_block_status_code"
    )]
    internal static partial void WafConfigBlockStatusCode(
        nint config,
        ushort statusCode
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_config_block_body")]
    internal static partial void WafConfigBlockBody(
        nint config,
        nint body,
        nuint bodyLen
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_config_logging")]
    internal static partial void WafConfigLogging(
        nint config,
        [MarshalAs(UnmanagedType.U1)] bool enabled
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_config_logging_options")]
    internal static partial void WafConfigLoggingOptions(
        nint config,
        WafLoggingOptionsNative options
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_waf_config_max_field_length"
    )]
    internal static partial void WafConfigMaxFieldLength(
        nint config,
        nuint length
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_waf_config_max_rate_limit_keys"
    )]
    internal static partial void WafConfigMaxRateLimitKeys(
        nint config,
        nuint keys
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_config_decision_cache")]
    internal static partial void WafConfigDecisionCache(
        nint config,
        DecisionCacheConfigNative cache
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_config_decode")]
    internal static partial void WafConfigDecode(
        nint config,
        DecodeConfigNative decode
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_string_set")]
    internal static partial void StringSet(
        nint @out,
        nint value,
        nuint valueLen
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_header_map_insert")]
    internal static partial void HeaderMapInsert(
        nint headers,
        nint name,
        nuint nameLen,
        nint values,
        nuint count
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_query_map_new")]
    internal static partial nint QueryMapNew();

    [LibraryImport(Library, EntryPoint = "mini_waf_query_map_insert")]
    internal static partial void QueryMapInsert(
        nint query,
        nint key,
        nuint keyLen,
        nint value
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_query_map_free")]
    internal static partial void QueryMapFree(nint query);

    [LibraryImport(Library, EntryPoint = "mini_waf_query_value_null")]
    internal static partial nint QueryValueNull();

    [LibraryImport(Library, EntryPoint = "mini_waf_query_value_bool")]
    internal static partial nint QueryValueBool(
        [MarshalAs(UnmanagedType.U1)] bool value
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_query_value_number")]
    internal static partial nint QueryValueNumber(double value);

    [LibraryImport(Library, EntryPoint = "mini_waf_query_value_string")]
    internal static partial nint QueryValueString(nint value, nuint valueLen);

    [LibraryImport(Library, EntryPoint = "mini_waf_query_value_array")]
    internal static partial nint QueryValueArray(nint values, nuint count);

    [LibraryImport(Library, EntryPoint = "mini_waf_query_value_object")]
    internal static partial nint QueryValueObject(nint map);

    [LibraryImport(Library, EntryPoint = "mini_waf_query_value_free")]
    internal static partial void QueryValueFree(nint value);

    [LibraryImport(Library, EntryPoint = "mini_waf_cookie_map_insert")]
    internal static partial void CookieMapInsert(
        nint cookies,
        nint name,
        nuint nameLen,
        nint value,
        nuint valueLen
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_raw_body_text")]
    internal static partial void RawBodyText(
        nint body,
        nint value,
        nuint valueLen
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_raw_body_bytes")]
    internal static partial void RawBodyBytes(
        nint body,
        nint value,
        nuint valueLen
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_files_bag_list")]
    internal static partial void FilesBagList(
        nint bag,
        nint files,
        nuint count
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_files_bag_fields_insert")]
    internal static partial void FilesBagFieldsInsert(
        nint bag,
        nint fieldname,
        nuint fieldnameLen,
        nint files,
        nuint count
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_normalize_client_ip")]
    internal static partial nint NormalizeClientIp(nint raw, nuint rawLen);

    [LibraryImport(Library, EntryPoint = "mini_waf_pick_client_ip_from_xff")]
    internal static partial nint PickClientIpFromXff(
        nint forwardedFor,
        nuint forwardedForLen
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_is_host_ip_literal")]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static partial bool IsHostIpLiteral(
        nint hostHeader,
        nuint hostHeaderLen
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_custom_adapter_handlers_new"
    )]
    internal static partial nint CustomAdapterHandlersNew(
        nint name,
        nuint nameLen
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_custom_adapter_handlers_free"
    )]
    internal static partial void CustomAdapterHandlersFree(nint handlers);

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_custom_adapter_handlers_get_method"
    )]
    internal static partial void CustomAdapterHandlersGetMethod(
        nint handlers,
        nint handler
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_custom_adapter_handlers_get_url"
    )]
    internal static partial void CustomAdapterHandlersGetUrl(
        nint handlers,
        nint handler
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_custom_adapter_handlers_get_path"
    )]
    internal static partial void CustomAdapterHandlersGetPath(
        nint handlers,
        nint handler
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_custom_adapter_handlers_get_ip"
    )]
    internal static partial void CustomAdapterHandlersGetIp(
        nint handlers,
        nint handler
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_custom_adapter_handlers_get_protocol"
    )]
    internal static partial void CustomAdapterHandlersGetProtocol(
        nint handlers,
        nint handler
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_custom_adapter_handlers_get_local_port"
    )]
    internal static partial void CustomAdapterHandlersGetLocalPort(
        nint handlers,
        nint handler
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_custom_adapter_handlers_get_header"
    )]
    internal static partial void CustomAdapterHandlersGetHeader(
        nint handlers,
        nint handler
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_custom_adapter_handlers_get_headers"
    )]
    internal static partial void CustomAdapterHandlersGetHeaders(
        nint handlers,
        nint handler
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_custom_adapter_handlers_get_query"
    )]
    internal static partial void CustomAdapterHandlersGetQuery(
        nint handlers,
        nint handler
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_custom_adapter_handlers_get_cookies"
    )]
    internal static partial void CustomAdapterHandlersGetCookies(
        nint handlers,
        nint handler
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_custom_adapter_handlers_get_raw_body"
    )]
    internal static partial void CustomAdapterHandlersGetRawBody(
        nint handlers,
        nint handler
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_custom_adapter_handlers_get_files"
    )]
    internal static partial void CustomAdapterHandlersGetFiles(
        nint handlers,
        nint handler
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_custom_adapter_handlers_set_response_header"
    )]
    internal static partial void CustomAdapterHandlersSetResponseHeader(
        nint handlers,
        nint handler
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_custom_adapter_handlers_remove_response_header"
    )]
    internal static partial void CustomAdapterHandlersRemoveResponseHeader(
        nint handlers,
        nint handler
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_custom_adapter_handlers_drop"
    )]
    internal static partial void CustomAdapterHandlersDrop(
        nint handlers,
        nint handler
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_create_adapter")]
    internal static partial nint CreateAdapter(nint handlers, nint error);

    [LibraryImport(Library, EntryPoint = "mini_waf_custom_adapter_free")]
    internal static partial void CustomAdapterFree(nint adapter);

    [LibraryImport(Library, EntryPoint = "mini_waf_create_mini_waf")]
    internal static partial nint CreateMiniWaf(nint config);

    [LibraryImport(Library, EntryPoint = "mini_waf_mini_waf_instance_free")]
    internal static partial void MiniWafInstanceFree(nint instance);

    [LibraryImport(Library, EntryPoint = "mini_waf_mini_waf_instance_rules")]
    internal static partial nint MiniWafInstanceRules(
        nint instance,
        nint count
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_mini_waf_instance_handle")]
    internal static partial nint MiniWafInstanceHandle(nint instance, nint ctx);

    [LibraryImport(Library, EntryPoint = "mini_waf_mini_waf_instance_protect")]
    internal static partial nint MiniWafInstanceProtect(
        nint instance,
        nint adapter,
        nint request,
        nint response
    );

    [LibraryImport(Library, EntryPoint = "mini_waf_waf_evaluation_result_free")]
    internal static partial void WafEvaluationResultFree(nint result);

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_waf_evaluation_result_get_decision"
    )]
    internal static partial int WafEvaluationResultGetDecision(nint result);

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_waf_evaluation_result_get_matched_rule"
    )]
    internal static partial nint WafEvaluationResultGetMatchedRule(nint result);

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_waf_evaluation_result_get_reason"
    )]
    internal static partial nint WafEvaluationResultGetReason(
        nint result,
        nint len
    );

    [LibraryImport(
        Library,
        EntryPoint = "mini_waf_waf_evaluation_result_get_logged_rules"
    )]
    internal static partial nint WafEvaluationResultGetLoggedRules(
        nint result,
        nint count
    );
}
