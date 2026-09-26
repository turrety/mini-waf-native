/* Tests of the C API; run them with CMake (`ctest`), see ../README.md. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mini_waf.h"

static int failures = 0;

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__,   \
                    #condition);                                               \
            failures++;                                                        \
        }                                                                      \
    } while (0)

#define CHECK_STR(actual, expected)                                            \
    do {                                                                       \
        const char *actual_ = (actual);                                        \
        if (!actual_ || strcmp(actual_, (expected)) != 0) {                    \
            fprintf(stderr, "%s:%d: expected \"%s\", got \"%s\"\n", __FILE__,  \
                    __LINE__, (expected), actual_ ? actual_ : "(null)");       \
            failures++;                                                        \
        }                                                                      \
    } while (0)

#define TEXT(literal) literal, sizeof literal - 1
#define STR(literal) {literal, sizeof literal - 1}

/* A toy server's request and response. */
typedef struct Request {
    const char *method;
    const char *url;
    const char *peer;
    const char *user_agent;
    const char *body;
    const char *upload;
} Request;

typedef struct Response {
    int status;
    char body[64];
    char headers[256];
} Response;

static void set_text(MiniWafString *out, const char *text) {
    mini_waf_string_set(out, text, strlen(text));
}

static void get_method(const void *request, MiniWafString *out) {
    set_text(out, ((const Request *)request)->method);
}

static void get_url(const void *request, MiniWafString *out) {
    set_text(out, ((const Request *)request)->url);
}

static void get_ip(const void *request, MiniWafString *out) {
    set_text(out, ((const Request *)request)->peer);
}

static void get_headers(const void *request, HeaderMap *out) {
    const char *user_agent = ((const Request *)request)->user_agent;
    MiniWafStr value = {user_agent, strlen(user_agent)};
    mini_waf_header_map_insert(out, TEXT("user-agent"), &value, 1);
}

static void get_raw_body(const void *request, RawBody *out) {
    const char *body = ((const Request *)request)->body;
    if (body) {
        mini_waf_raw_body_text(out, body, strlen(body));
    }
}

static void get_files(const void *request, FilesBag *out) {
    const char *upload = ((const Request *)request)->upload;
    if (upload) {
        UploadedFile file = {
            {NULL, 0}, {upload, strlen(upload)}, {NULL, 0}, {NULL, 0}};
        mini_waf_files_bag_list(out, &file, 1);
    }
}

static void set_response_header(void *response, const char *name,
                                size_t name_len, const char *value,
                                size_t value_len) {
    char *headers = ((Response *)response)->headers;
    size_t used = strlen(headers);
    snprintf(headers + used, 256 - used, "%.*s: %.*s\n", (int)name_len, name,
             (int)value_len, value);
}

static void drop(const void *request, void *response, uint16_t status_code,
                 const char *body, size_t body_len) {
    Response *res = response;
    (void)request;
    res->status = status_code;
    snprintf(res->body, sizeof res->body, "%.*s", (int)body_len, body);
}

static CustomAdapter *toy_adapter(void) {
    CustomAdapterHandlers *handlers =
        mini_waf_custom_adapter_handlers_new(TEXT("toy-server"));
    mini_waf_custom_adapter_handlers_get_method(handlers, get_method);
    mini_waf_custom_adapter_handlers_get_url(handlers, get_url);
    mini_waf_custom_adapter_handlers_get_ip(handlers, get_ip);
    mini_waf_custom_adapter_handlers_get_headers(handlers, get_headers);
    mini_waf_custom_adapter_handlers_get_raw_body(handlers, get_raw_body);
    mini_waf_custom_adapter_handlers_get_files(handlers, get_files);
    mini_waf_custom_adapter_handlers_set_response_header(handlers,
                                                         set_response_header);
    mini_waf_custom_adapter_handlers_drop(handlers, drop);

    char *error = NULL;
    CustomAdapter *adapter = mini_waf_create_adapter(handlers, &error);
    mini_waf_custom_adapter_handlers_free(handlers);
    if (!adapter) {
        fprintf(stderr, "create_adapter: %s\n", error);
        exit(1);
    }
    return adapter;
}

/* audit-admin (log) and login-rate-limit (1 request per minute per IP). */
static MiniWafInstance *toy_waf(void) {
    WafField *path = mini_waf_waf_field_from_str(TEXT("path"), NULL);
    WafField *ip = mini_waf_waf_field_from_str(TEXT("ip"), NULL);

    FieldCondition *is_admin = mini_waf_field_condition_new(path);
    mini_waf_field_condition_equals(is_admin, TEXT("/admin"));
    WafCondition *when_admin = mini_waf_waf_condition_field(is_admin);
    WafRule *audit =
        mini_waf_waf_rule_new(TEXT("audit-admin"), when_admin, WAF_ACTION_LOG);

    FieldCondition *is_login = mini_waf_field_condition_new(path);
    mini_waf_field_condition_equals(is_login, TEXT("/login"));
    FieldCondition *per_ip = mini_waf_field_condition_new(ip);
    RateLimitSpec spec = {1, 60000, {NULL, 0}};
    mini_waf_field_condition_rate_limit(per_ip, spec);
    const WafCondition *login_parts[] = {
        mini_waf_waf_condition_field(is_login),
        mini_waf_waf_condition_field(per_ip),
    };
    WafCondition *when_login = mini_waf_waf_condition_all(login_parts, 2);
    WafRule *rate_limit = mini_waf_waf_rule_new(TEXT("login-rate-limit"),
                                                when_login, WAF_ACTION_BLOCK);
    mini_waf_waf_rule_reason(rate_limit, TEXT("Too many login attempts"));

    WafConfig *config = mini_waf_waf_config_new();
    WafPresetName presets[] = {WAF_PRESET_NAME_DEFAULT};
    mini_waf_waf_config_presets(config, presets, 1);
    mini_waf_waf_config_level(config, PROTECTION_LEVEL_BALANCED);
    const WafRule *rules[] = {audit, rate_limit};
    mini_waf_waf_config_rules(config, rules, 2);

    MiniWafInstance *waf = mini_waf_create_mini_waf(config);

    /* Every input was copied: free the building blocks right away. */
    mini_waf_waf_config_free(config);
    mini_waf_waf_rule_free(rate_limit);
    mini_waf_waf_rule_free(audit);
    mini_waf_waf_condition_free(when_login);
    mini_waf_waf_condition_free((WafCondition *)login_parts[0]);
    mini_waf_waf_condition_free((WafCondition *)login_parts[1]);
    mini_waf_waf_condition_free(when_admin);
    mini_waf_field_condition_free(per_ip);
    mini_waf_field_condition_free(is_login);
    mini_waf_field_condition_free(is_admin);
    mini_waf_waf_field_free(ip);
    mini_waf_waf_field_free(path);
    return waf;
}

static Request get(const char *url) {
    Request request = {"GET", url, "203.0.113.7", "Mozilla/5.0", NULL, NULL};
    return request;
}

static const char *matched_id(const WafEvaluationResult *result) {
    const WafRule *rule =
        mini_waf_waf_evaluation_result_get_matched_rule(result);
    return mini_waf_waf_rule_get_id(rule, NULL);
}

static void test_version(void) { CHECK(strlen(mini_waf_version()) > 0); }

static void test_protect_blocks_attacks(void) {
    MiniWafInstance *waf = toy_waf();
    CustomAdapter *adapter = toy_adapter();

    const char *attacks[][2] = {
        {"/search?q=1'%20UNION%20SELECT%20password%20FROM%20users",
         "preset-sqli-classic-query"},
        {"/files?name=../../etc/passwd", NULL},
    };
    for (size_t index = 0; index < 2; index++) {
        Request request = get(attacks[index][0]);
        Response response = {200, "", ""};
        WafEvaluationResult *result = mini_waf_mini_waf_instance_protect(
            waf, adapter, &request, &response);
        CHECK(mini_waf_waf_evaluation_result_get_decision(result) ==
              WAF_DECISION_BLOCK);
        CHECK(response.status == 403);
        CHECK_STR(response.body, "Forbidden");
        CHECK(mini_waf_waf_evaluation_result_get_reason(result, NULL));
        if (attacks[index][1]) {
            CHECK_STR(matched_id(result), attacks[index][1]);
        }
        mini_waf_waf_evaluation_result_free(result);
    }

    Request scanner = get("/");
    scanner.user_agent = "sqlmap/1.7";
    Request xss = get("/comments");
    xss.method = "POST";
    xss.body = "{\"q\":\"<script>alert(1)</script>\"}";
    Request upload = get("/upload");
    upload.upload = "shell.php";
    Request *blocked[] = {&scanner, &xss, &upload};
    for (size_t index = 0; index < 3; index++) {
        Response response = {200, "", ""};
        WafEvaluationResult *result = mini_waf_mini_waf_instance_protect(
            waf, adapter, blocked[index], &response);
        CHECK(response.status == 403);
        mini_waf_waf_evaluation_result_free(result);
    }

    mini_waf_custom_adapter_free(adapter);
    mini_waf_mini_waf_instance_free(waf);
}

static void test_protect_allows_and_reports_logged_rules(void) {
    MiniWafInstance *waf = toy_waf();
    CustomAdapter *adapter = toy_adapter();
    Request request = get("/admin");
    Response response = {200, "", ""};

    WafEvaluationResult *result =
        mini_waf_mini_waf_instance_protect(waf, adapter, &request, &response);
    CHECK(mini_waf_waf_evaluation_result_get_decision(result) ==
          WAF_DECISION_ALLOW);
    CHECK(response.status == 200);
    CHECK(mini_waf_waf_evaluation_result_get_matched_rule(result) == NULL);
    size_t count = 0;
    const WafRule *const *logged =
        mini_waf_waf_evaluation_result_get_logged_rules(result, &count);
    CHECK(count == 1);
    CHECK_STR(mini_waf_waf_rule_get_id(logged[0], NULL), "audit-admin");
    CHECK(mini_waf_waf_rule_get_action(logged[0]) == WAF_ACTION_LOG);

    mini_waf_waf_evaluation_result_free(result);
    mini_waf_custom_adapter_free(adapter);
    mini_waf_mini_waf_instance_free(waf);
}

static void test_protect_rate_limits_with_headers(void) {
    MiniWafInstance *waf = toy_waf();
    CustomAdapter *adapter = toy_adapter();
    Request request = get("/login");

    Response first = {200, "", ""};
    WafEvaluationResult *result =
        mini_waf_mini_waf_instance_protect(waf, adapter, &request, &first);
    CHECK(first.status == 200);
    CHECK(strstr(first.headers, "X-RateLimit-Limit: 1\n") != NULL);
    mini_waf_waf_evaluation_result_free(result);

    Response second = {200, "", ""};
    result =
        mini_waf_mini_waf_instance_protect(waf, adapter, &request, &second);
    CHECK(second.status == 403);
    CHECK_STR(matched_id(result), "login-rate-limit");
    CHECK_STR(mini_waf_waf_evaluation_result_get_reason(result, NULL),
              "Too many login attempts");
    mini_waf_waf_evaluation_result_free(result);

    mini_waf_custom_adapter_free(adapter);
    mini_waf_mini_waf_instance_free(waf);
}

static void test_create_adapter_reports_missing_handlers(void) {
    CustomAdapterHandlers *handlers =
        mini_waf_custom_adapter_handlers_new(TEXT("incomplete"));
    mini_waf_custom_adapter_handlers_get_method(handlers, get_method);
    char *error = NULL;
    CHECK(mini_waf_create_adapter(handlers, &error) == NULL);
    CHECK_STR(error, "adapter is missing required handlers: get_url, get_ip, "
                     "get_headers, get_raw_body, set_response_header, drop");
    mini_waf_string_free(error);
    mini_waf_custom_adapter_handlers_free(handlers);
}

/* A WafHttpContext over a fixed POST request. */
typedef struct FixedContext {
    int status;
    bool blocked;
} FixedContext;

static void ctx_framework(void *self, MiniWafString *out) {
    (void)self;
    set_text(out, "fixed");
}

static void ctx_method(void *self, MiniWafString *out) {
    (void)self;
    set_text(out, "POST");
}

static void ctx_url(void *self, MiniWafString *out) {
    (void)self;
    set_text(out, "/api?debug=1");
}

static void ctx_path(void *self, MiniWafString *out) {
    (void)self;
    set_text(out, "/api");
}

static void ctx_ip(void *self, MiniWafString *out) {
    (void)self;
    set_text(out, "198.51.100.4");
}

static void ctx_protocol(void *self, MiniWafString *out) {
    (void)self;
    set_text(out, "https");
}

static uint16_t ctx_local_port(void *self) {
    (void)self;
    return 443;
}

static bool ctx_header(void *self, const char *name, size_t name_len,
                       MiniWafString *out) {
    (void)self;
    if (name_len == 10 && memcmp(name, "user-agent", 10) == 0) {
        set_text(out, "curl/8.0");
        return true;
    }
    return false;
}

static void ctx_headers(void *self, HeaderMap *out) {
    MiniWafStr value = STR("curl/8.0");
    (void)self;
    mini_waf_header_map_insert(out, TEXT("user-agent"), &value, 1);
}

static void ctx_query(void *self, QueryMap *out) {
    QueryValue *value = mini_waf_query_value_string(TEXT("1"));
    (void)self;
    mini_waf_query_map_insert(out, TEXT("debug"), value);
    mini_waf_query_value_free(value);
}

static void ctx_cookies(void *self, CookieMap *out) {
    (void)self;
    mini_waf_cookie_map_insert(out, TEXT("session"), TEXT("abc"));
}

static void ctx_raw_body(void *self, MiniWafString *out) {
    (void)self;
    set_text(out, "name=<script>alert(1)</script>");
}

static void ctx_files(void *self, FilesBag *out) {
    (void)self;
    (void)out;
}

static void ctx_set_header(void *self, const char *name, size_t name_len,
                           const char *value, size_t value_len) {
    (void)self, (void)name, (void)name_len, (void)value, (void)value_len;
}

static void ctx_remove_header(void *self, const char *name, size_t len) {
    (void)self, (void)name, (void)len;
}

static bool ctx_is_blocked(void *self) {
    return ((FixedContext *)self)->blocked;
}

static void ctx_drop(void *self, const uint16_t *status_code, const char *body,
                     size_t body_len) {
    FixedContext *ctx = self;
    (void)body, (void)body_len;
    ctx->blocked = true;
    ctx->status = status_code ? *status_code : 403;
}

static void test_handle_evaluates_a_context(void) {
    MiniWafInstance *waf = toy_waf();
    FixedContext state = {0, false};
    WafHttpContext ctx = {
        &state,         ctx_framework, ctx_method,     ctx_url,
        ctx_path,       ctx_ip,        ctx_protocol,   ctx_local_port,
        ctx_header,     ctx_headers,   ctx_query,      ctx_cookies,
        ctx_raw_body,   ctx_files,     ctx_set_header, ctx_remove_header,
        ctx_is_blocked, ctx_drop,
    };

    WafEvaluationResult *result = mini_waf_mini_waf_instance_handle(waf, &ctx);
    CHECK(mini_waf_waf_evaluation_result_get_decision(result) ==
          WAF_DECISION_BLOCK);
    CHECK(state.blocked);
    CHECK(state.status == 403);
    mini_waf_waf_evaluation_result_free(result);

    ctx.drop = NULL;
    CHECK(mini_waf_mini_waf_instance_handle(waf, &ctx) == NULL);
    mini_waf_mini_waf_instance_free(waf);
}

static bool is_even_length(void *user_data, const char *value, size_t len) {
    (void)value;
    ++*(int *)user_data;
    return len % 2 == 0;
}

static void test_match_patterns(void) {
    char *error = NULL;
    CHECK(mini_waf_match_pattern_regex(TEXT("(unclosed"), &error) == NULL);
    CHECK(error != NULL);
    mini_waf_string_free(error);

    MatchPattern *regex = mini_waf_match_pattern_regex_with_flags(
        TEXT("union\\s+select"), TEXT("i"), NULL);
    CHECK(mini_waf_match_pattern_is_match(regex, TEXT("1 UNION  SELECT 2")));
    CHECK(!mini_waf_match_pattern_is_match(regex, TEXT("union")));
    mini_waf_match_pattern_free(regex);

    MiniWafStr methods[] = {STR("TRACE"), STR("TRACK")};
    MatchPattern *one_of = mini_waf_match_pattern_one_of(methods, 2);
    CHECK(mini_waf_match_pattern_is_match(one_of, TEXT("TRACK")));
    CHECK(!mini_waf_match_pattern_is_match(one_of, TEXT("GET")));
    mini_waf_match_pattern_free(one_of);

    int calls = 0;
    MatchPattern *even =
        mini_waf_match_pattern_predicate(is_even_length, &calls, NULL);
    CHECK(mini_waf_match_pattern_is_match(even, TEXT("ab")));
    CHECK(!mini_waf_match_pattern_is_match(even, TEXT("abc")));
    CHECK(calls == 2);
    mini_waf_match_pattern_free(even);
}

static void test_fields(void) {
    char *error = NULL;
    CHECK(mini_waf_waf_field_from_str(TEXT("header.host"), &error) == NULL);
    CHECK_STR(error, "unsupported field \"header.host\"");
    mini_waf_string_free(error);

    WafField *field = mini_waf_waf_field_header(TEXT("user-agent"));
    char *path = mini_waf_waf_field_to_string(field);
    CHECK_STR(path, "headers.user-agent");
    mini_waf_string_free(path);
    mini_waf_waf_field_free(field);
}

static void test_rule_fields(void) {
    WafField *method = mini_waf_waf_field_from_str(TEXT("method"), NULL);
    FieldCondition *condition = mini_waf_field_condition_new(method);
    mini_waf_field_condition_equals(condition, TEXT("TRACE"));
    WafCondition *when = mini_waf_waf_condition_field(condition);
    WafRule *rule =
        mini_waf_waf_rule_new(TEXT("no-trace"), when, WAF_ACTION_BLOCK);

    bool enabled = true;
    int64_t priority = 0;
    ProtectionLevel level = PROTECTION_LEVEL_LOW;
    CHECK(!mini_waf_waf_rule_get_enabled(rule, &enabled));
    CHECK(!mini_waf_waf_rule_get_priority(rule, &priority));
    CHECK(mini_waf_waf_rule_get_reason(rule, NULL) == NULL);

    mini_waf_waf_rule_enabled(rule, false);
    mini_waf_waf_rule_priority(rule, 7);
    mini_waf_waf_rule_min_level(rule, PROTECTION_LEVEL_HIGH);
    mini_waf_waf_rule_reason(rule, TEXT("TRACE is disabled"));
    CHECK(mini_waf_waf_rule_get_enabled(rule, &enabled) && !enabled);
    CHECK(mini_waf_waf_rule_get_priority(rule, &priority) && priority == 7);
    CHECK(mini_waf_waf_rule_get_min_level(rule, &level) &&
          level == PROTECTION_LEVEL_HIGH);
    CHECK_STR(mini_waf_waf_rule_get_reason(rule, NULL), "TRACE is disabled");
    CHECK(mini_waf_waf_rule_get_when(rule) != NULL);

    WafRule *copy = mini_waf_waf_rule_clone(rule);
    mini_waf_waf_rule_free(rule);
    CHECK_STR(mini_waf_waf_rule_get_id(copy, NULL), "no-trace");
    mini_waf_waf_rule_free(copy);

    CHECK(mini_waf_waf_rule_new(TEXT("x"), when, 99) == NULL);
    mini_waf_waf_condition_free(when);
    mini_waf_field_condition_free(condition);
    mini_waf_waf_field_free(method);
}

static void test_parse_rules_from_json_and_list_rules(void) {
    const char json[] = "[{\"id\":\"block-admin\",\"action\":\"block\","
                        "\"when\":{\"field\":\"path\",\"equals\":\"/admin\"}}]";
    size_t count = 0;
    WafRule **rules =
        mini_waf_parse_rules_from_json(json, strlen(json), &count, NULL);
    CHECK(count == 1);
    CHECK_STR(mini_waf_waf_rule_get_id(rules[0], NULL), "block-admin");

    WafConfig *config = mini_waf_waf_config_new();
    mini_waf_waf_config_rules(config, (const WafRule *const *)rules, count);
    mini_waf_waf_rule_array_free(rules, count);
    MiniWafInstance *waf = mini_waf_create_mini_waf(config);
    mini_waf_waf_config_free(config);

    const WafRule *const *active =
        mini_waf_mini_waf_instance_rules(waf, &count);
    CHECK(count == 1);
    CHECK_STR(mini_waf_waf_rule_get_id(active[0], NULL), "block-admin");
    mini_waf_mini_waf_instance_free(waf);

    char *error = NULL;
    CHECK(mini_waf_parse_rules_from_json(TEXT("[{\"id\":1}]"), &count,
                                         &error) == NULL);
    CHECK(count == 0);
    CHECK(error != NULL);
    mini_waf_string_free(error);
}

static void test_config_filters_by_id(void) {
    WafConfig *config = mini_waf_waf_config_new();
    WafPresetName presets[] = {WAF_PRESET_NAME_SQLI};
    MiniWafStr enabled[] = {STR("preset-sqli-classic-query")};
    mini_waf_waf_config_presets(config, presets, 1);
    mini_waf_waf_config_enabled_rule_ids(config, enabled, 1);
    mini_waf_waf_config_block_status_code(config, 406);
    mini_waf_waf_config_block_body(config, TEXT("nope"));
    size_t max = 16;
    bool on = true;
    DecisionCacheConfig cache = {&max, NULL};
    DecodeConfig decode = {&on, NULL, NULL};
    mini_waf_waf_config_decision_cache(config, cache);
    mini_waf_waf_config_decode(config, decode);
    mini_waf_waf_config_max_field_length(config, 4096);
    mini_waf_waf_config_max_rate_limit_keys(config, 100);
    mini_waf_waf_config_logging(config, false);

    MiniWafInstance *waf = mini_waf_create_mini_waf(config);
    mini_waf_waf_config_free(config);
    size_t count = 0;
    mini_waf_mini_waf_instance_rules(waf, &count);
    CHECK(count == 1);

    CustomAdapter *adapter = toy_adapter();
    Request request = get("/search?q=1'%20UNION%20SELECT%20password");
    Response response = {200, "", ""};
    WafEvaluationResult *result =
        mini_waf_mini_waf_instance_protect(waf, adapter, &request, &response);
    CHECK(response.status == 406);
    CHECK_STR(response.body, "nope");
    mini_waf_waf_evaluation_result_free(result);
    mini_waf_custom_adapter_free(adapter);
    mini_waf_mini_waf_instance_free(waf);
}

static void test_ip_helpers(void) {
    char *ip =
        mini_waf_pick_client_ip_from_xff(TEXT("::ffff:1.2.3.4, 10.0.0.1"));
    CHECK_STR(ip, "1.2.3.4");
    mini_waf_string_free(ip);
    CHECK(mini_waf_is_host_ip_literal(TEXT("127.0.0.1:8080")));
    CHECK(!mini_waf_is_host_ip_literal(TEXT("example.com")));
}

static void test_tolerates_null_handles(void) {
    size_t count = 42;
    CHECK(mini_waf_mini_waf_instance_protect(NULL, NULL, NULL, NULL) == NULL);
    mini_waf_mini_waf_instance_rules(NULL, &count);
    CHECK(count == 0);
    CHECK(mini_waf_waf_rule_get_id(NULL, NULL) == NULL);
    mini_waf_waf_rule_reason(NULL, TEXT("x"));
    mini_waf_mini_waf_instance_free(NULL);
    mini_waf_waf_evaluation_result_free(NULL);
    mini_waf_string_free(NULL);
}

int main(void) {
    test_version();
    test_protect_blocks_attacks();
    test_protect_allows_and_reports_logged_rules();
    test_protect_rate_limits_with_headers();
    test_create_adapter_reports_missing_handlers();
    test_handle_evaluates_a_context();
    test_match_patterns();
    test_fields();
    test_rule_fields();
    test_parse_rules_from_json_and_list_rules();
    test_config_filters_by_id();
    test_ip_helpers();
    test_tolerates_null_handles();
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("all C API tests passed");
    return 0;
}
