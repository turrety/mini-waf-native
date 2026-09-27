/*
 * Engine micro-benchmarks through the C binding, mirroring the A0-A6 cases
 * of `examples/bench.rs`. Each request goes through a custom adapter, so the
 * numbers include the callbacks.
 *
 *     cmake -S c -B target/c -DCMAKE_BUILD_TYPE=Release
 *     cmake --build target/c
 *     target/c/bench            # 20 000 iterations
 *     target/c/bench 100000     # custom iteration count
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "mini_waf.h"

typedef struct Request {
    const char *url;
    const char *ip;
    const char *body;
} Request;

typedef struct Response {
    int blocked;
} Response;

static void set_text(MiniWafString *out, const char *text) {
    mini_waf_string_set(out, text, strlen(text));
}

static void get_method(const void *req, MiniWafString *out) {
    set_text(out, *((const Request *)req)->body ? "POST" : "GET");
}

static void get_url(const void *req, MiniWafString *out) {
    set_text(out, ((const Request *)req)->url);
}

static void get_ip(const void *req, MiniWafString *out) {
    set_text(out, ((const Request *)req)->ip);
}

static void insert(HeaderMap *out, const char *name, const char *value) {
    MiniWafStr text = {value, strlen(value)};
    mini_waf_header_map_insert(out, name, strlen(name), &text, 1);
}

static void get_headers(const void *req, HeaderMap *out) {
    (void)req;
    insert(out, "user-agent", "Mozilla/5.0 (compatible; BenchBot/1.0)");
    insert(out, "accept", "application/json");
    insert(out, "host", "localhost");
}

static void get_raw_body(const void *req, RawBody *out) {
    const char *body = ((const Request *)req)->body;
    if (*body) {
        mini_waf_raw_body_text(out, body, strlen(body));
    }
}

static void set_response_header(void *res, const char *name, size_t name_len,
                                const char *value, size_t value_len) {
    (void)res, (void)name, (void)name_len, (void)value, (void)value_len;
}

static void drop(const void *req, void *res, uint16_t status_code,
                 const char *body, size_t body_len) {
    (void)req, (void)status_code, (void)body, (void)body_len;
    ((Response *)res)->blocked = 1;
}

static MiniWafInstance *create(const ProtectionLevel *level, int cache) {
    WafConfig *config = mini_waf_waf_config_new();
    if (level) {
        WafPresetName presets[] = {WAF_PRESET_NAME_DEFAULT};
        MiniWafStr disabled = {"preset-dos-rate-limit", 21};
        mini_waf_waf_config_presets(config, presets, 1);
        mini_waf_waf_config_level(config, *level);
        mini_waf_waf_config_disabled_rule_ids(config, &disabled, 1);
    }
    if (cache) {
        DecisionCacheConfig defaults = {NULL, NULL};
        mini_waf_waf_config_decision_cache(config, defaults);
    }
    MiniWafInstance *waf = mini_waf_create_mini_waf(config);
    mini_waf_waf_config_free(config);
    return waf;
}

/* Microseconds since the first call. TIME_UTC marks a C library with the
 * C11 wall clock; counting from a base keeps sub-microsecond precision in
 * a double. Without it (the msvcrt of classic MinGW), the C89 processor
 * clock is portable but coarser. */
static double now_us(void) {
#ifdef TIME_UTC
    static time_t base = 0;
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    if (base == 0) {
        base = ts.tv_sec;
    }
    return (double)(ts.tv_sec - base) * 1e6 + ts.tv_nsec / 1e3;
#else
    return (double)clock() * 1e6 / CLOCKS_PER_SEC;
#endif
}

static int compare(const void *left, const void *right) {
    double a = *(const double *)left, b = *(const double *)right;
    return (a > b) - (a < b);
}

static double percentile(const double *sorted, size_t count, double p) {
    size_t index = (size_t)(count * p);
    return sorted[index < count ? index : count - 1];
}

static WafDecision evaluate(const MiniWafInstance *waf,
                            const CustomAdapter *adapter,
                            const Request *request) {
    Response response = {0};
    WafEvaluationResult *result =
        mini_waf_mini_waf_instance_protect(waf, adapter, request, &response);
    WafDecision decision = mini_waf_waf_evaluation_result_get_decision(result);
    mini_waf_waf_evaluation_result_free(result);
    return decision;
}

static void run(const char *id, const char *name, MiniWafInstance *waf,
                const CustomAdapter *adapter, const Request *request,
                size_t iterations) {
    for (int warmup = 0; warmup < 10000; warmup++) {
        evaluate(waf, adapter, request);
    }
    double *samples = malloc(iterations * sizeof *samples);
    WafDecision decision = WAF_DECISION_ALLOW;
    double started = now_us();
    for (size_t index = 0; index < iterations; index++) {
        double begin = now_us();
        decision = evaluate(waf, adapter, request);
        samples[index] = now_us() - begin;
    }
    double wall = (now_us() - started) / 1e6;
    qsort(samples, iterations, sizeof *samples, compare);
    size_t rules = 0;
    mini_waf_mini_waf_instance_rules(waf, &rules);
    printf("| %-12s | %-38s | %5zu | %10.2fk/s | %8.2f us | %8.2f us "
           "| %8.2f us | %s |\n",
           id, name, rules, iterations / wall / 1000.0,
           percentile(samples, iterations, 0.50),
           percentile(samples, iterations, 0.95),
           percentile(samples, iterations, 0.99),
           decision == WAF_DECISION_BLOCK ? "Block" : "Allow");
    free(samples);
    mini_waf_mini_waf_instance_free(waf);
}

int main(int argc, char **argv) {
    size_t iterations = argc > 1 ? strtoul(argv[1], NULL, 10) : 20000;

    CustomAdapterHandlers *handlers =
        mini_waf_custom_adapter_handlers_new("bench", 5);
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

    static char large[8192];
    size_t pad = sizeof large - 40;
    strcpy(large, "{\"note\":\"pad\",\"data\":\"");
    size_t prefix = strlen(large);
    memset(large + prefix, 'A', pad);
    strcpy(large + prefix + pad, "\"}");

    Request clean = {"/api/items?page=1", "10.0.0.1", ""};
    Request bare = {"/", "10.0.0.9", ""};
    Request big = {"/echo", "10.0.0.3", large};
    Request small = {"/echo", "10.0.0.3", "{\"ok\":true,\"q\":\"hello\"}"};
    Request sqli = {"/search?q=1'%20OR%201=1%20--", "10.0.0.2", ""};
    ProtectionLevel balanced = PROTECTION_LEVEL_BALANCED;

    printf("iterations: %zu (+10000 warmup); "
           "preset-dos-rate-limit disabled on A1-A6\n\n",
           iterations);
    printf("| ID | Case | Rules | ops/s | p50 | p95 | p99 | Decision |\n");
    printf("|---|---|---:|---:|---:|---:|---:|---|\n");
    run("A0", "0 rules (baseline protect)", create(NULL, 0), adapter, &bare,
        iterations);
    run("A1", "balanced, clean allow", create(&balanced, 0), adapter, &clean,
        iterations);
    run("A2", "A1 + decision cache (same fingerprint)", create(&balanced, 1),
        adapter, &clean, iterations);
    run("A3", "A1 + 8KB JSON body", create(&balanced, 0), adapter, &big,
        iterations);
    run("A4", "A1 + small (~24B) body", create(&balanced, 0), adapter, &small,
        iterations);
    run("A5", "A1 SQLi - block path", create(&balanced, 0), adapter, &sqli,
        iterations);
    const char *names[] = {"low", "balanced", "high", "paranoid"};
    for (int level = PROTECTION_LEVEL_LOW; level <= PROTECTION_LEVEL_PARANOID;
         level++) {
        char id[16], name[40];
        snprintf(id, sizeof id, "A6-%s", names[level]);
        snprintf(name, sizeof name, "%s, clean allow", names[level]);
        ProtectionLevel current = (ProtectionLevel)level;
        run(id, name, create(&current, 0), adapter, &clean, iterations);
    }

    mini_waf_custom_adapter_free(adapter);
    return 0;
}
