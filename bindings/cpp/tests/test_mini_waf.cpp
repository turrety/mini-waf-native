// Tests of the C++ binding; run them with CMake (`ctest`), see ../README.md.

#include <atomic>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "mini_waf.hpp"

using namespace mini_waf;

namespace {

int failures = 0;

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK("             \
                      << #condition << ") failed\n";                           \
            failures++;                                                        \
        }                                                                      \
    } while (0)

template <class E, class F>
bool throws(F&& body) {
    try {
        body();
    } catch (const E&) {
        return true;
    }
    return false;
}

// A toy server's request and response.
struct Request {
    std::string method = "GET";
    std::string target;
    std::string peer = "203.0.113.7";
    std::map<std::string, std::string> headers{{"user-agent", "Mozilla/5.0"}};
    std::string body;
    std::vector<std::string> uploads;
};

struct Response {
    int status = 200;
    std::string body;
    std::map<std::string, std::string> headers;
};

Request get(std::string target) {
    Request request;
    request.target = std::move(target);
    return request;
}

CustomAdapterHandlers<Request, Response> toy_handlers() {
    return CustomAdapterHandlers<Request, Response>("toy-server")
        .get_method([](const Request& req) { return req.method; })
        .get_url([](const Request& req) { return req.target; })
        .get_ip([](const Request& req) { return req.peer; })
        .get_headers([](const Request& req) {
            HeaderMap headers;
            for (const auto& [name, value] : req.headers) {
                headers.emplace_back(name, value);
            }
            return headers;
        })
        .get_raw_body([](const Request& req) { return RawBody(req.body); })
        .get_files([](const Request& req) {
            std::vector<UploadedFile> files;
            for (const auto& name : req.uploads) {
                files.push_back(UploadedFile::named(name));
            }
            return FilesBag(files);
        })
        .set_response_header(
            [](Response& res, std::string_view name, std::string_view value) {
                res.headers[std::string(name)] = std::string(value);
            })
        .drop([](const Request&, Response& res, std::uint16_t status,
                 std::string_view body) {
            res.status = status;
            res.body = std::string(body);
        });
}

MiniWafInstance toy_waf() {
    return create_mini_waf(
        WafConfig()
            .presets({WafPresetName::Default})
            .level(ProtectionLevel::Balanced)
            .rules({
                WafRule("audit-admin",
                        FieldCondition(WafField::Path()).equals("/admin"),
                        WafAction::Log),
                WafRule("login-rate-limit",
                        WafCondition::all(
                            FieldCondition(WafField::Path()).equals("/login"),
                            FieldCondition(WafField::Ip())
                                .rate_limit(RateLimitSpec(1, 60000))),
                        WafAction::Block)
                    .reason("Too many login attempts"),
            }));
}

void test_protect_blocks_attacks() {
    auto waf = toy_waf();
    auto adapter = create_adapter(toy_handlers());

    Request sqli =
        get("/search?q=1'%20UNION%20SELECT%20password%20FROM%20users");
    Response response;
    auto result = waf.protect(adapter, sqli, response);
    CHECK(result.decision == WafDecision::Block);
    CHECK(result.matched_rule->id() == "preset-sqli-classic-query");
    CHECK(result.reason.has_value());
    CHECK(response.status == 403);
    CHECK(response.body == "Forbidden");

    Request scanner = get("/");
    scanner.headers["user-agent"] = "sqlmap/1.7";
    Request xss = get("/comments");
    xss.method = "POST";
    xss.body = R"({"q":"<script>alert(1)</script>"})";
    Request upload = get("/upload");
    upload.uploads = {"shell.php"};
    for (const Request* request : {&scanner, &xss, &upload}) {
        Response blocked;
        waf.protect(adapter, *request, blocked);
        CHECK(blocked.status == 403);
    }
}

void test_protect_allows_and_reports_logged_rules() {
    auto waf = toy_waf();
    auto adapter = create_adapter(toy_handlers());
    Request request = get("/admin");
    Response response;

    auto result = waf.protect(adapter, request, response);
    CHECK(result.decision == WafDecision::Allow);
    CHECK(!result.matched_rule);
    CHECK(result.logged_rules.size() == 1);
    CHECK(result.logged_rules[0].id() == "audit-admin");
    CHECK(result.logged_rules[0].action() == WafAction::Log);
    CHECK(response.status == 200);
}

void test_protect_rate_limits_with_headers() {
    auto waf = toy_waf();
    auto adapter = create_adapter(toy_handlers());
    Request request = get("/login");

    Response first;
    waf.protect(adapter, request, first);
    CHECK(first.status == 200);
    CHECK(first.headers["X-RateLimit-Limit"] == "1");

    Response second;
    auto result = waf.protect(adapter, request, second);
    CHECK(second.status == 403);
    CHECK(result.matched_rule->id() == "login-rate-limit");
    CHECK(result.reason ==
          std::optional<std::string>("Too many login attempts"));
}

void test_create_adapter_reports_missing_handlers() {
    CHECK(throws<AdapterBuildError>([] {
        create_adapter(
            CustomAdapterHandlers<Request, Response>("incomplete")
                .get_method([](const Request& req) { return req.method; }));
    }));
}

void test_handler_exceptions_propagate() {
    auto waf = toy_waf();
    auto adapter =
        create_adapter(toy_handlers().get_ip([](const Request&) -> std::string {
            throw std::logic_error("no peer");
        }));
    Request request = get("/login");
    Response response;
    CHECK(throws<std::logic_error>(
        [&] { waf.protect(adapter, request, response); }));
}

void test_shares_one_instance_across_threads() {
    auto waf = create_mini_waf(WafConfig().presets({WafPresetName::Default}));
    auto adapter = create_adapter(toy_handlers());
    std::atomic<int> blocked{0};
    std::vector<std::thread> threads;
    for (int worker = 0; worker < 8; worker++) {
        threads.emplace_back([&, worker] {
            for (int index = 0; index < 200; index++) {
                Request request =
                    get(index % 2 ? "/files?name=../../etc/passwd" : "/home");
                // One address per request: the default preset rate-limits
                // each IP.
                request.peer = "10.0." + std::to_string(worker) + "." +
                               std::to_string(index);
                Response response;
                waf.protect(adapter, request, response);
                blocked += response.status == 403;
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    CHECK(blocked == 8 * 100);
}

// A WafHttpContext over a fixed POST request.
class FixedContext : public WafHttpContext {
public:
    std::optional<std::uint16_t> status;
    bool blocked = false;

    std::string framework() const override { return "fixed"; }
    std::string get_method() const override { return "POST"; }
    std::string get_url() const override { return "/api?debug=1"; }
    std::string get_path() const override { return "/api"; }
    std::string get_ip() const override { return "198.51.100.4"; }
    std::string get_protocol() const override { return "https"; }
    std::uint16_t get_local_port() const override { return 443; }
    std::optional<std::string>
    get_header(std::string_view name) const override {
        if (name == "user-agent") {
            return "curl/8.0";
        }
        return std::nullopt;
    }
    HeaderMap get_headers() const override {
        return {{"user-agent", std::string("curl/8.0")}};
    }
    QueryMap get_query() const override {
        return {{"filter", QueryValue{QueryMap{
                               {"$ne", QueryValue{std::string("null")}}}}}};
    }
    CookieMap get_cookies() const override { return {{"session", "abc"}}; }
    std::string get_raw_body() const override { return "name=Ada"; }
    std::vector<UploadedFile> get_files() const override { return {}; }
    void set_response_header(std::string_view, std::string_view) override {}
    void remove_response_header(std::string_view) override {}
    bool is_blocked() const override { return blocked; }
    void drop(std::optional<std::uint16_t> status_code,
              std::optional<std::string_view>) override {
        blocked = true;
        status = status_code;
    }
};

void test_handle_evaluates_a_context() {
    auto waf = create_mini_waf(WafConfig()
                                   .presets({WafPresetName::Default})
                                   .level(ProtectionLevel::High));
    FixedContext ctx;
    auto result = waf.handle(ctx);
    CHECK(result.decision == WafDecision::Block);
    CHECK(ctx.blocked);
    CHECK(ctx.status == std::optional<std::uint16_t>(403));
}

void test_match_patterns_and_fields() {
    CHECK(throws<RegexError>([] { MatchPattern::regex("(unclosed"); }));
    auto regex = MatchPattern::regex_with_flags("union\\s+select", "i");
    CHECK(regex.is_match("1 UNION  SELECT 2"));
    CHECK(!regex.is_match("union"));
    CHECK(MatchPattern::one_of({"TRACE", "TRACK"}).is_match("TRACK"));
    CHECK(MatchPattern::exact("a").is_match("a"));

    std::atomic<int> calls{0};
    auto even = MatchPattern::predicate([&](std::string_view value) {
        calls++;
        return value.size() % 2 == 0;
    });
    CHECK(even.is_match("ab"));
    CHECK(!even.is_match("abc"));
    CHECK(calls == 2);
    auto throwing = MatchPattern::predicate(
        [](std::string_view) -> bool { throw std::runtime_error("boom"); });
    CHECK(!throwing.is_match("x"));

    CHECK(throws<InvalidField>([] { WafField::from_str("header.host"); }));
    CHECK(WafField::header("user-agent").to_string() == "headers.user-agent");
    CHECK(WafField::from_str("query.id").to_string() == "query.id");
}

void test_requires_any_gates_the_pattern() {
    // `bad-bot` matches the pattern but holds no literal, so it is not tried.
    auto waf = create_mini_waf(WafConfig().rules({
        WafRule("bad-bot",
                FieldCondition(WafField::header("user-agent"))
                    .matches(MatchPattern::regex("bad-?bot"))
                    .requires_any({"BADBOT"}),
                WafAction::Block),
    }));
    auto adapter = create_adapter(toy_handlers());
    Request gated = get("/");
    gated.headers["user-agent"] = "bad-bot";
    Request caught = get("/");
    caught.headers["user-agent"] = "badbot/2.0";

    Response allowed;
    CHECK(waf.protect(adapter, gated, allowed).decision == WafDecision::Allow);
    Response blocked;
    CHECK(waf.protect(adapter, caught, blocked).decision == WafDecision::Block);
}

void test_rule_accessors_and_copies() {
    WafRule rule("no-trace", FieldCondition(WafField::Method()).equals("TRACE"),
                 WafAction::Block);
    CHECK(!rule.enabled());
    CHECK(!rule.reason());
    rule.enabled(false).priority(7).min_level(ProtectionLevel::High);
    rule.reason("TRACE is disabled");
    CHECK(rule.enabled() == std::optional<bool>(false));
    CHECK(rule.priority() == std::optional<std::int64_t>(7));
    CHECK(rule.min_level() == std::optional(ProtectionLevel::High));

    WafRule copy = rule;
    copy.reason("changed");
    CHECK(rule.reason() == std::optional<std::string>("TRACE is disabled"));
    CHECK(copy.reason() == std::optional<std::string>("changed"));
}

void test_parse_rules_and_config() {
    auto rules = parse_rules_from_json(R"([{
        "id": "block-admin",
        "action": "block",
        "when": { "field": "path", "equals": "/admin" }
    }])");
    CHECK(rules.size() == 1);
    CHECK(
        throws<RuleParseError>([] { parse_rules_from_json("[{\"id\":1}]"); }));

    auto waf =
        create_mini_waf(WafConfig()
                            .rules(rules)
                            .presets({WafPresetName::Sqli})
                            .disabled_rule_ids({"preset-sqli-blind"})
                            .block_status_code(406)
                            .block_body("nope")
                            .decision_cache(DecisionCacheConfig{16, {}})
                            .decode(DecodeConfig{true, {}, {}})
                            .logging(WafLoggingOptions{WafLogLevel::Error})
                            .logging(false));
    bool found = false;
    for (const auto& rule : waf.rules()) {
        found |= rule.id() == "block-admin";
        CHECK(rule.id() != "preset-sqli-blind");
    }
    CHECK(found);

    auto adapter = create_adapter(toy_handlers());
    Request request = get("/admin");
    Response response;
    waf.protect(adapter, request, response);
    CHECK(response.status == 406);
    CHECK(response.body == "nope");
}

void test_ip_helpers() {
    CHECK(pick_client_ip_from_xff("::ffff:1.2.3.4, 10.0.0.1") == "1.2.3.4");
    CHECK(normalize_client_ip("::ffff:10.0.0.1") == "10.0.0.1");
    CHECK(is_host_ip_literal("127.0.0.1:8080"));
}

}  // namespace

int main() {
    test_protect_blocks_attacks();
    test_protect_allows_and_reports_logged_rules();
    test_protect_rate_limits_with_headers();
    test_create_adapter_reports_missing_handlers();
    test_handler_exceptions_propagate();
    test_shares_one_instance_across_threads();
    test_handle_evaluates_a_context();
    test_match_patterns_and_fields();
    test_requires_any_gates_the_pattern();
    test_rule_accessors_and_copies();
    test_parse_rules_and_config();
    test_ip_helpers();
    if (failures) {
        std::cerr << failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "all C++ binding tests passed\n";
    return 0;
}
