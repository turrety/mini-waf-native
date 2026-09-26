/*
 * mini_waf.h - C API of mini-waf, a minimalistic Web Application Firewall
 * engine with OWASP CRS-derived presets.
 *
 * Link against libmini_waf (`cargo build --release -p mini-waf-ffi`).
 *
 * The API mirrors the Rust crate name for name, in snake_case and prefixed
 * with `mini_waf_` because C has no namespaces:
 *
 *     Rust                              C
 *     create_mini_waf(config, None)     mini_waf_create_mini_waf(config)
 *     WafRule::new(id, when, action)    mini_waf_waf_rule_new(...)
 *     rule.reason(...)                  mini_waf_waf_rule_reason(rule, ...)
 *     rule.id (a public field)          mini_waf_waf_rule_get_id(rule, ...)
 *     instance.protect(&a, &req, &mut res)
 *                                       mini_waf_mini_waf_instance_protect(...)
 *
 * Conventions shared by every function:
 *
 * - Handles are opaque pointers from a constructor, released with the
 *   matching *_free. Every function accepts a NULL handle: getters return
 *   0 / false / NULL and *_free does nothing.
 * - Handles passed as arguments are borrowed and copied, never consumed:
 *   free them whenever convenient after the call.
 * - Rust builder methods (`fn reason(mut self, ...) -> Self`) update the
 *   handle in place.
 * - Input text is a (pointer, length) pair of UTF-8 bytes, copied before the
 *   call returns; invalid UTF-8 is replaced with U+FFFD. It needs no NUL
 *   terminator. A NULL pointer is the empty string, or `None` where a
 *   MiniWafStr member is optional.
 * - Output text is NUL-terminated UTF-8 borrowed from the handle it came
 *   from, valid until that handle is freed. When `len` is not NULL it
 *   receives the length in bytes, without the terminator.
 * - An optional scalar (`Option<T>`) is read through a getter returning
 *   whether it is set and writing the value to its out-parameter; as an
 *   input it is a pointer, NULL meaning `None`.
 * - Enum arguments outside their range are ignored (constructors return
 *   NULL).
 * - Strings the library allocates (`char *` results and errors) are
 *   released with mini_waf_string_free.
 * - A MiniWafInstance is immutable and thread-safe: evaluate on it from any
 *   number of threads at once. Every other handle belongs to one thread at a
 *   time. Callbacks run on the thread that called handle / protect, before
 *   it returns; predicates run on any evaluating thread.
 *
 * Not available from C: logger sinks (WafLogger), WafEngineOptions (shared
 * rate-limit stores), RawBody::Json, and the engine internals
 * (scan_rules, evaluate_condition, the rate-limit and cache primitives).
 */

#ifndef MINI_WAF_H
#define MINI_WAF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------
 * Enums
 */

typedef enum ProtectionLevel {
    PROTECTION_LEVEL_LOW,
    PROTECTION_LEVEL_BALANCED,
    PROTECTION_LEVEL_HIGH,
    PROTECTION_LEVEL_PARANOID
} ProtectionLevel;

typedef enum WafAction {
    WAF_ACTION_ALLOW,
    WAF_ACTION_BLOCK,
    WAF_ACTION_LOG
} WafAction;

typedef enum WafPresetName {
    WAF_PRESET_NAME_DEFAULT,
    WAF_PRESET_NAME_SQLI,
    WAF_PRESET_NAME_XSS,
    WAF_PRESET_NAME_SCANNERS,
    WAF_PRESET_NAME_PATH_TRAVERSAL,
    WAF_PRESET_NAME_RFI,
    WAF_PRESET_NAME_RCE,
    WAF_PRESET_NAME_PROTOCOL
} WafPresetName;

typedef enum WafDecision { WAF_DECISION_ALLOW, WAF_DECISION_BLOCK } WafDecision;

typedef enum WafLogLevel {
    WAF_LOG_LEVEL_ERROR,
    WAF_LOG_LEVEL_INFO,
    WAF_LOG_LEVEL_DEBUG
} WafLogLevel;

/* ------------------------------------------------------------------------
 * Opaque handles
 */

typedef struct MatchPattern MatchPattern;
typedef struct WafField WafField;
typedef struct FieldCondition FieldCondition;
typedef struct WafCondition WafCondition;
typedef struct WafRule WafRule;
typedef struct WafConfig WafConfig;
typedef struct MiniWafInstance MiniWafInstance;
typedef struct WafEvaluationResult WafEvaluationResult;
typedef struct CustomAdapterHandlers CustomAdapterHandlers;
typedef struct CustomAdapter CustomAdapter;

/* Values callbacks fill in. */
typedef struct MiniWafString MiniWafString;
typedef struct HeaderMap HeaderMap;
typedef struct QueryMap QueryMap;
typedef struct QueryValue QueryValue;
typedef struct CookieMap CookieMap;
typedef struct RawBody RawBody;
typedef struct FilesBag FilesBag;

/* ------------------------------------------------------------------------
 * Plain structs
 */

/* Borrowed text in lists and structs. */
typedef struct MiniWafStr {
    const char *data;
    size_t len;
} MiniWafStr;

typedef struct RateLimitSpec {
    uint64_t max;
    uint64_t window_ms;
    MiniWafStr key_prefix; /* data NULL: None */
} RateLimitSpec;

typedef struct DecisionCacheConfig {
    const size_t *max;      /* NULL: default 256 */
    const uint64_t *ttl_ms; /* NULL: default 1000 */
} DecisionCacheConfig;

typedef struct DecodeConfig {
    const bool *base64; /* NULL: automatic (on at High and above) */
    const bool *url;
    const bool *comments;
} DecodeConfig;

/* WafLoggingOptions without the sink: events go to the console. */
typedef struct WafLoggingOptions {
    const WafLogLevel *level; /* NULL: Info */
} WafLoggingOptions;

typedef struct UploadedFile {
    MiniWafStr fieldname; /* data NULL: None, for each member */
    MiniWafStr name;
    MiniWafStr filename;
    MiniWafStr originalname;
} UploadedFile;

/* ------------------------------------------------------------------------
 * Library
 */

/* Version of the library, such as "0.1.0". Static; never free it. */
const char *mini_waf_version(void);

void mini_waf_string_free(char *string);

/* ------------------------------------------------------------------------
 * MatchPattern
 */

/* NULL on an invalid pattern, with the message in `error`. */
MatchPattern *mini_waf_match_pattern_regex(const char *pattern,
                                           size_t pattern_len, char **error);

/* JavaScript-style flags: "i", "m", "s", "u" / "v"; "g", "y" and "d" are
 * accepted and ignored. */
MatchPattern *mini_waf_match_pattern_regex_with_flags(const char *pattern,
                                                      size_t pattern_len,
                                                      const char *flags,
                                                      size_t flags_len,
                                                      char **error);

MatchPattern *mini_waf_match_pattern_exact(const char *value, size_t value_len);

MatchPattern *mini_waf_match_pattern_one_of(const MiniWafStr *values,
                                            size_t count);

/*
 * A predicate called with each candidate value; it must be thread-safe.
 * `drop` (optional) receives `user_data` once no pattern refers to it.
 */
typedef bool (*MatchPredicateFn)(void *user_data, const char *value,
                                 size_t value_len);
MatchPattern *mini_waf_match_pattern_predicate(MatchPredicateFn test,
                                               void *user_data,
                                               void (*drop)(void *user_data));

bool mini_waf_match_pattern_is_match(const MatchPattern *pattern,
                                     const char *value, size_t value_len);

void mini_waf_match_pattern_free(MatchPattern *pattern);

/* ------------------------------------------------------------------------
 * WafField
 */

/* Parse a field path: "ip", "method", "path", "url", "body", "files",
 * "query", "headers", "cookies", "query.<name>", "headers.<name>",
 * "cookies.<name>". NULL with the message in `error` when unsupported. */
WafField *mini_waf_waf_field_from_str(const char *field, size_t field_len,
                                      char **error);

WafField *mini_waf_waf_field_query(const char *name, size_t name_len);

WafField *mini_waf_waf_field_header(const char *name, size_t name_len);

WafField *mini_waf_waf_field_cookie(const char *name, size_t name_len);

/* The path form ("headers.user-agent"); free with mini_waf_string_free. */
char *mini_waf_waf_field_to_string(const WafField *field);

void mini_waf_waf_field_free(WafField *field);

/* ------------------------------------------------------------------------
 * FieldCondition
 */

FieldCondition *mini_waf_field_condition_new(const WafField *field);

void mini_waf_field_condition_matches(FieldCondition *condition,
                                      const MatchPattern *pattern);

void mini_waf_field_condition_equals(FieldCondition *condition,
                                     const char *value, size_t value_len);

void mini_waf_field_condition_includes(FieldCondition *condition,
                                       const char *needle, size_t needle_len);

void mini_waf_field_condition_rate_limit(FieldCondition *condition,
                                         RateLimitSpec spec);

/* Cheap prefilter: the value must contain one of `literals` before the
 * pattern runs. List a literal every match contains, or the rule stops
 * detecting. */
void mini_waf_field_condition_requires(FieldCondition *condition,
                                       const MiniWafStr *literals,
                                       size_t count);

void mini_waf_field_condition_free(FieldCondition *condition);

/* ------------------------------------------------------------------------
 * WafCondition
 */

/* WafCondition::Field, the `From<FieldCondition>` conversion. */
WafCondition *mini_waf_waf_condition_field(const FieldCondition *condition);

WafCondition *mini_waf_waf_condition_all(const WafCondition *const *conditions,
                                         size_t count);

WafCondition *
mini_waf_waf_condition_any_of(const WafCondition *const *conditions,
                              size_t count);

WafCondition *mini_waf_waf_condition_not(const WafCondition *condition);

/* An owned copy, for instance of a rule's `when`. */
WafCondition *mini_waf_waf_condition_clone(const WafCondition *condition);

void mini_waf_waf_condition_free(WafCondition *condition);

/* ------------------------------------------------------------------------
 * WafRule
 */

WafRule *mini_waf_waf_rule_new(const char *id, size_t id_len,
                               const WafCondition *when, WafAction action);

void mini_waf_waf_rule_reason(WafRule *rule, const char *reason,
                              size_t reason_len);

void mini_waf_waf_rule_enabled(WafRule *rule, bool enabled);

void mini_waf_waf_rule_priority(WafRule *rule, int64_t priority);

void mini_waf_waf_rule_min_level(WafRule *rule, ProtectionLevel level);

const char *mini_waf_waf_rule_get_id(const WafRule *rule, size_t *len);

/* Borrowed from the rule; never free it. */
const WafCondition *mini_waf_waf_rule_get_when(const WafRule *rule);

WafAction mini_waf_waf_rule_get_action(const WafRule *rule);

const char *mini_waf_waf_rule_get_reason(const WafRule *rule, size_t *len);

bool mini_waf_waf_rule_get_enabled(const WafRule *rule, bool *enabled);

bool mini_waf_waf_rule_get_priority(const WafRule *rule, int64_t *priority);

bool mini_waf_waf_rule_get_min_level(const WafRule *rule,
                                     ProtectionLevel *level);

/* An owned copy, for instance of a rule borrowed from a result. */
WafRule *mini_waf_waf_rule_clone(const WafRule *rule);

void mini_waf_waf_rule_free(WafRule *rule);

/*
 * Parse a JSON rules document (an array, or {"rules": [...]}). Returns an
 * array of `*count` owned rules, released with mini_waf_waf_rule_array_free
 * (clone a rule to keep it longer), or NULL with the message in `error`.
 */
WafRule **mini_waf_parse_rules_from_json(const char *input, size_t input_len,
                                         size_t *count, char **error);

void mini_waf_waf_rule_array_free(WafRule **rules, size_t count);

/* ------------------------------------------------------------------------
 * WafConfig
 */

WafConfig *mini_waf_waf_config_new(void);

void mini_waf_waf_config_free(WafConfig *config);

void mini_waf_waf_config_level(WafConfig *config, ProtectionLevel level);

void mini_waf_waf_config_rules(WafConfig *config, const WafRule *const *rules,
                               size_t count);

void mini_waf_waf_config_presets(WafConfig *config,
                                 const WafPresetName *presets, size_t count);

void mini_waf_waf_config_enabled_rule_ids(WafConfig *config,
                                          const MiniWafStr *ids, size_t count);

void mini_waf_waf_config_disabled_rule_ids(WafConfig *config,
                                           const MiniWafStr *ids, size_t count);

void mini_waf_waf_config_block_status_code(WafConfig *config,
                                           uint16_t status_code);

void mini_waf_waf_config_block_body(WafConfig *config, const char *body,
                                    size_t body_len);

/* `logging(true)` / `logging(false)`. */
void mini_waf_waf_config_logging(WafConfig *config, bool enabled);

/* `logging(WafLoggingOptions { .. })`. */
void mini_waf_waf_config_logging_options(WafConfig *config,
                                         WafLoggingOptions options);

void mini_waf_waf_config_max_field_length(WafConfig *config, size_t length);

void mini_waf_waf_config_max_rate_limit_keys(WafConfig *config, size_t keys);

void mini_waf_waf_config_decision_cache(WafConfig *config,
                                        DecisionCacheConfig cache);

void mini_waf_waf_config_decode(WafConfig *config, DecodeConfig decode);

/* ------------------------------------------------------------------------
 * Values filled in by callbacks
 */

void mini_waf_string_set(MiniWafString *out, const char *value,
                         size_t value_len);

/* One value makes HeaderValue::Single, several HeaderValue::Multi. Name
 * headers in lowercase. */
void mini_waf_header_map_insert(HeaderMap *headers, const char *name,
                                size_t name_len, const MiniWafStr *values,
                                size_t count);

QueryMap *mini_waf_query_map_new(void);

/* QueryMap::parse: a raw query string, with or without the leading '?'. */
QueryMap *mini_waf_query_map_parse(const char *query, size_t query_len);

void mini_waf_query_map_insert(QueryMap *query, const char *key, size_t key_len,
                               const QueryValue *value);

void mini_waf_query_map_free(QueryMap *query);

QueryValue *mini_waf_query_value_null(void);

QueryValue *mini_waf_query_value_bool(bool value);

QueryValue *mini_waf_query_value_number(double value);

QueryValue *mini_waf_query_value_string(const char *value, size_t value_len);

QueryValue *mini_waf_query_value_array(const QueryValue *const *values,
                                       size_t count);

QueryValue *mini_waf_query_value_object(const QueryMap *map);

void mini_waf_query_value_free(QueryValue *value);

void mini_waf_cookie_map_insert(CookieMap *cookies, const char *name,
                                size_t name_len, const char *value,
                                size_t value_len);

/* RawBody::Text. A body left unset is RawBody::Empty. */
void mini_waf_raw_body_text(RawBody *body, const char *value, size_t value_len);

/* RawBody::Bytes, decoded as UTF-8 for inspection. */
void mini_waf_raw_body_bytes(RawBody *body, const char *value,
                             size_t value_len);

/* FilesBag::List. */
void mini_waf_files_bag_list(FilesBag *bag, const UploadedFile *files,
                             size_t count);

/* One entry of FilesBag::Fields (form field -> files). */
void mini_waf_files_bag_fields_insert(FilesBag *bag, const char *fieldname,
                                      size_t fieldname_len,
                                      const UploadedFile *files, size_t count);

/* ------------------------------------------------------------------------
 * IP helpers (free the results with mini_waf_string_free)
 */

char *mini_waf_normalize_client_ip(const char *raw, size_t raw_len);

char *mini_waf_pick_client_ip_from_xff(const char *forwarded_for,
                                       size_t forwarded_for_len);

bool mini_waf_is_host_ip_literal(const char *host_header,
                                 size_t host_header_len);

/* ------------------------------------------------------------------------
 * WafHttpContext: the request view, implemented with callbacks
 *
 * Every callback is required. Getters write their value through the
 * out-parameter (mini_waf_string_set, mini_waf_header_map_insert, ...);
 * each is called at most once per evaluation. `get_ip` must return the
 * normalized address (see mini_waf_normalize_client_ip). `drop` receives a
 * NULL `status_code` / `body` for `None`.
 */

typedef struct WafHttpContext {
    void *self;
    void (*framework)(void *self, MiniWafString *out);
    void (*get_method)(void *self, MiniWafString *out);
    void (*get_url)(void *self, MiniWafString *out);
    void (*get_path)(void *self, MiniWafString *out);
    void (*get_ip)(void *self, MiniWafString *out);
    void (*get_protocol)(void *self, MiniWafString *out);
    uint16_t (*get_local_port)(void *self);
    bool (*get_header)(void *self, const char *name, size_t name_len,
                       MiniWafString *out);
    void (*get_headers)(void *self, HeaderMap *out);
    void (*get_query)(void *self, QueryMap *out);
    void (*get_cookies)(void *self, CookieMap *out);
    void (*get_raw_body)(void *self, MiniWafString *out);
    void (*get_files)(void *self, FilesBag *out);
    void (*set_response_header)(void *self, const char *name, size_t name_len,
                                const char *value, size_t value_len);
    void (*remove_response_header)(void *self, const char *name,
                                   size_t name_len);
    bool (*is_blocked)(void *self);
    void (*drop)(void *self, const uint16_t *status_code, const char *body,
                 size_t body_len);
} WafHttpContext;

/* ------------------------------------------------------------------------
 * CustomAdapterHandlers / create_adapter
 *
 * The universal adapter: describe how to read your server's request and
 * write its response. `request` and `response` are the pointers given to
 * mini_waf_mini_waf_instance_protect. Required: get_method, get_url,
 * get_ip, get_headers, get_raw_body, set_response_header and drop; the
 * others have the Rust defaults (path from the URL, "http", port 0, header
 * lookup in get_headers, query parsed from the URL, cookies parsed from the
 * Cookie header, no files, no-op remove). The IP is normalized for you.
 */

typedef void (*RequestTextHandler)(const void *request, MiniWafString *out);

CustomAdapterHandlers *mini_waf_custom_adapter_handlers_new(const char *name,
                                                            size_t name_len);

void mini_waf_custom_adapter_handlers_free(CustomAdapterHandlers *handlers);

void mini_waf_custom_adapter_handlers_get_method(
    CustomAdapterHandlers *handlers, RequestTextHandler handler);

void mini_waf_custom_adapter_handlers_get_url(CustomAdapterHandlers *handlers,
                                              RequestTextHandler handler);

void mini_waf_custom_adapter_handlers_get_path(CustomAdapterHandlers *handlers,
                                               RequestTextHandler handler);

void mini_waf_custom_adapter_handlers_get_ip(CustomAdapterHandlers *handlers,
                                             RequestTextHandler handler);

void mini_waf_custom_adapter_handlers_get_protocol(
    CustomAdapterHandlers *handlers, RequestTextHandler handler);

void mini_waf_custom_adapter_handlers_get_local_port(
    CustomAdapterHandlers *handlers,
    uint16_t (*handler)(const void *request, const void *response));

void mini_waf_custom_adapter_handlers_get_header(
    CustomAdapterHandlers *handlers,
    bool (*handler)(const void *request, const char *name, size_t name_len,
                    MiniWafString *out));

void mini_waf_custom_adapter_handlers_get_headers(
    CustomAdapterHandlers *handlers,
    void (*handler)(const void *request, HeaderMap *out));

void mini_waf_custom_adapter_handlers_get_query(
    CustomAdapterHandlers *handlers,
    void (*handler)(const void *request, QueryMap *out));

void mini_waf_custom_adapter_handlers_get_cookies(
    CustomAdapterHandlers *handlers,
    void (*handler)(const void *request, CookieMap *out));

void mini_waf_custom_adapter_handlers_get_raw_body(
    CustomAdapterHandlers *handlers,
    void (*handler)(const void *request, RawBody *out));

void mini_waf_custom_adapter_handlers_get_files(
    CustomAdapterHandlers *handlers,
    void (*handler)(const void *request, FilesBag *out));

void mini_waf_custom_adapter_handlers_set_response_header(
    CustomAdapterHandlers *handlers,
    void (*handler)(void *response, const char *name, size_t name_len,
                    const char *value, size_t value_len));

void mini_waf_custom_adapter_handlers_remove_response_header(
    CustomAdapterHandlers *handlers,
    void (*handler)(void *response, const char *name, size_t name_len));

void mini_waf_custom_adapter_handlers_drop(
    CustomAdapterHandlers *handlers,
    void (*handler)(const void *request, void *response, uint16_t status_code,
                    const char *body, size_t body_len));

/* NULL when required handlers are missing, with "adapter is missing
 * required handlers: get_url, drop" in `error`. */
CustomAdapter *mini_waf_create_adapter(const CustomAdapterHandlers *handlers,
                                       char **error);

void mini_waf_custom_adapter_free(CustomAdapter *adapter);

/* ------------------------------------------------------------------------
 * create_mini_waf / MiniWafInstance
 */

MiniWafInstance *mini_waf_create_mini_waf(const WafConfig *config);

void mini_waf_mini_waf_instance_free(MiniWafInstance *instance);

/* The active rules in evaluation order, borrowed from the instance. */
const WafRule *const *
mini_waf_mini_waf_instance_rules(const MiniWafInstance *instance,
                                 size_t *count);

/* Evaluate a request through its context. NULL if a callback is missing. */
WafEvaluationResult *
mini_waf_mini_waf_instance_handle(const MiniWafInstance *instance,
                                  const WafHttpContext *ctx);

/* Evaluate a request through an adapter. */
WafEvaluationResult *
mini_waf_mini_waf_instance_protect(const MiniWafInstance *instance,
                                   const CustomAdapter *adapter,
                                   const void *request, void *response);

/* ------------------------------------------------------------------------
 * WafEvaluationResult (its rules are borrowed from the instance: free the
 * result before the instance)
 */

void mini_waf_waf_evaluation_result_free(WafEvaluationResult *result);

WafDecision
mini_waf_waf_evaluation_result_get_decision(const WafEvaluationResult *result);

/* The allow rule that short-circuited or the block rule that won. */
const WafRule *mini_waf_waf_evaluation_result_get_matched_rule(
    const WafEvaluationResult *result);

const char *
mini_waf_waf_evaluation_result_get_reason(const WafEvaluationResult *result,
                                          size_t *len);

/* Rules with action log that matched. */
const WafRule *const *mini_waf_waf_evaluation_result_get_logged_rules(
    const WafEvaluationResult *result, size_t *count);

#ifdef __cplusplus
}
#endif

#endif /* MINI_WAF_H */
