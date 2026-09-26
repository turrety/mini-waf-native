/*
 * Protect a (pretend) server's requests with the universal adapter.
 *
 *     cmake -S bindings/c -B target/c && cmake --build target/c
 *     target/c/protect
 */

#include <stdio.h>
#include <string.h>

#include "mini_waf.h"

/* Your server's request and response types. */
typedef struct Request {
    const char *method;
    const char *target;
    const char *peer;
    const char *user_agent;
} Request;

typedef struct Response {
    int status;
} Response;

static void set_text(MiniWafString *out, const char *text) {
    mini_waf_string_set(out, text, strlen(text));
}

static void get_method(const void *req, MiniWafString *out) {
    set_text(out, ((const Request *)req)->method);
}

static void get_url(const void *req, MiniWafString *out) {
    set_text(out, ((const Request *)req)->target);
}

static void get_ip(const void *req, MiniWafString *out) {
    set_text(out, ((const Request *)req)->peer);
}

static void get_headers(const void *req, HeaderMap *out) {
    const char *user_agent = ((const Request *)req)->user_agent;
    MiniWafStr value = {user_agent, strlen(user_agent)};
    mini_waf_header_map_insert(out, "user-agent", 10, &value, 1);
}

static void get_raw_body(const void *req, RawBody *out) {
    (void)req, (void)out; /* no body: RawBody::Empty */
}

static void set_response_header(void *res, const char *name, size_t name_len,
                                const char *value, size_t value_len) {
    (void)res;
    printf("  header %.*s: %.*s\n", (int)name_len, name, (int)value_len, value);
}

static void drop(const void *req, void *res, uint16_t status_code,
                 const char *body, size_t body_len) {
    (void)req, (void)body, (void)body_len;
    ((Response *)res)->status = status_code;
}

int main(void) {
    /* 1. Build the WAF once, at startup. */
    WafConfig *config = mini_waf_waf_config_new();
    WafPresetName presets[] = {WAF_PRESET_NAME_DEFAULT};
    mini_waf_waf_config_presets(config, presets, 1);
    mini_waf_waf_config_level(config, PROTECTION_LEVEL_BALANCED);
    MiniWafInstance *waf = mini_waf_create_mini_waf(config);
    mini_waf_waf_config_free(config);

    /* 2. Describe your server's request / response types once. */
    CustomAdapterHandlers *handlers =
        mini_waf_custom_adapter_handlers_new("example", 7);
    mini_waf_custom_adapter_handlers_get_method(handlers, get_method);
    mini_waf_custom_adapter_handlers_get_url(handlers, get_url);
    mini_waf_custom_adapter_handlers_get_ip(handlers, get_ip);
    mini_waf_custom_adapter_handlers_get_headers(handlers, get_headers);
    mini_waf_custom_adapter_handlers_get_raw_body(handlers, get_raw_body);
    mini_waf_custom_adapter_handlers_set_response_header(handlers,
                                                         set_response_header);
    mini_waf_custom_adapter_handlers_drop(handlers, drop);
    CustomAdapter *adapter = mini_waf_create_adapter(handlers, NULL);
    mini_waf_custom_adapter_handlers_free(handlers);

    /* 3. Evaluate every request. */
    Request requests[] = {
        {"GET", "/search?q=hello", "198.51.100.4", "Mozilla/5.0"},
        {"GET", "/search?q=1'%20UNION%20SELECT%20password%20FROM%20users",
         "198.51.100.4", "Mozilla/5.0"},
        {"GET", "/", "198.51.100.4", "sqlmap/1.7"},
    };
    for (size_t index = 0; index < 3; index++) {
        Response response = {200};
        WafEvaluationResult *result = mini_waf_mini_waf_instance_protect(
            waf, adapter, &requests[index], &response);
        const WafRule *rule =
            mini_waf_waf_evaluation_result_get_matched_rule(result);
        printf("%s -> %d %s\n", requests[index].target, response.status,
               rule ? mini_waf_waf_rule_get_id(rule, NULL) : "");
        mini_waf_waf_evaluation_result_free(result);
    }

    mini_waf_custom_adapter_free(adapter);
    mini_waf_mini_waf_instance_free(waf);
    return 0;
}
