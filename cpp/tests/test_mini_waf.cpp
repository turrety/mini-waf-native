// Tests of the C++ binding, written as Catch2 BDD scenarios; run them with
// CMake (`ctest`), see ../README.md.

#include <atomic>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "mini_waf.hpp"

using namespace mini_waf;

namespace {

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

WafConfig toy_config() {
    return WafConfig()
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
        });
}

MiniWafInstance toy_waf(const WafEngineOptions& options = {}) {
    return create_mini_waf(toy_config(), options);
}

// A WafLogger that writes down what it sees.
class RecordingLogger : public WafLogger {
public:
    std::vector<std::string> events;
    std::string line;
    HeaderMap headers;
    QueryMap query;
    CookieMap cookies;
    std::vector<UploadedFile> files;
    std::string body;
    std::uint16_t port = 0;
    bool throws = false;

    void blocked(const WafHttpContext& ctx, const WafRule& rule) override {
        record("blocked " + rule.id(), ctx);
    }
    void audit(const WafHttpContext& ctx, const WafRule& rule) override {
        record("audit " + rule.id(), ctx);
    }
    void connection(const WafHttpContext& ctx) override {
        events.push_back("connection " +
                         ctx.get_header("user-agent").value_or("-"));
    }

private:
    void record(std::string event, const WafHttpContext& ctx) {
        if (throws) {
            throw std::runtime_error("logger failed");
        }
        events.push_back(std::move(event));
        line = ctx.framework() + " " + ctx.get_protocol() + " " +
               ctx.get_method() + " " + ctx.get_url() + " " + ctx.get_ip();
        headers = ctx.get_headers();
        query = ctx.get_query();
        cookies = ctx.get_cookies();
        files = ctx.get_files();
        body = ctx.get_raw_body();
        port = ctx.get_local_port();
    }
};

WafEngineOptions logged_by(std::shared_ptr<RecordingLogger> logger) {
    WafEngineOptions options;
    options.logger = std::move(logger);
    return options;
}

MiniWafInstance debug_waf(const WafEngineOptions& options) {
    return create_mini_waf(
        toy_config().logging(WafLoggingOptions{WafLogLevel::Debug}), options);
}

int login_status(const MiniWafInstance& waf) {
    auto adapter = create_adapter(toy_handlers());
    Request request = get("/login");
    Response response;
    waf.protect(adapter, request, response);
    return response.status;
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

}  // namespace

SCENARIO("protect blocks attacks through an adapter", "[protect]") {
    GIVEN("a balanced WAF and the toy server's adapter") {
        auto waf = toy_waf();
        auto adapter = create_adapter(toy_handlers());

        WHEN("a query carries a SQL injection") {
            Request sqli =
                get("/search?q=1'%20UNION%20SELECT%20password%20FROM%20users");
            Response response;
            auto result = waf.protect(adapter, sqli, response);

            THEN("the SQLi preset blocks it with the default response") {
                CHECK(result.decision == WafDecision::Block);
                REQUIRE(result.matched_rule);
                CHECK(result.matched_rule->id() == "preset-sqli-classic-query");
                CHECK(result.reason.has_value());
                CHECK(response.status == 403);
                CHECK(response.body == "Forbidden");
            }
        }

        WHEN("a scanner, a stored XSS or a PHP upload comes in") {
            Request scanner = get("/");
            scanner.headers["user-agent"] = "sqlmap/1.7";
            Request xss = get("/comments");
            xss.method = "POST";
            xss.body = R"({"q":"<script>alert(1)</script>"})";
            Request upload = get("/upload");
            upload.uploads = {"shell.php"};

            THEN("each one is dropped with 403") {
                for (const Request* request : {&scanner, &xss, &upload}) {
                    Response blocked;
                    waf.protect(adapter, *request, blocked);
                    CHECK(blocked.status == 403);
                }
            }
        }
    }
}

SCENARIO("protect allows a request and reports its logged rules", "[protect]") {
    GIVEN("a WAF that logs requests to /admin") {
        auto waf = toy_waf();
        auto adapter = create_adapter(toy_handlers());

        WHEN("/admin is requested") {
            Request request = get("/admin");
            Response response;
            auto result = waf.protect(adapter, request, response);

            THEN("it is allowed and the log rule is reported") {
                CHECK(result.decision == WafDecision::Allow);
                CHECK(!result.matched_rule);
                REQUIRE(result.logged_rules.size() == 1);
                CHECK(result.logged_rules[0].id() == "audit-admin");
                CHECK(result.logged_rules[0].action() == WafAction::Log);
                CHECK(response.status == 200);
            }
        }
    }
}

SCENARIO("protect rate-limits a route and sets the rate-limit headers",
         "[protect][rate-limit]") {
    GIVEN("a WAF that allows one login per minute and address") {
        auto waf = toy_waf();
        auto adapter = create_adapter(toy_handlers());
        Request request = get("/login");

        WHEN("the first login arrives") {
            Response first;
            waf.protect(adapter, request, first);

            THEN("it passes and announces the limit") {
                CHECK(first.status == 200);
                CHECK(first.headers["X-RateLimit-Limit"] == "1");
            }

            AND_WHEN("a second login arrives from the same address") {
                Response second;
                auto result = waf.protect(adapter, request, second);

                THEN("the rate-limit rule blocks it") {
                    CHECK(second.status == 403);
                    REQUIRE(result.matched_rule);
                    CHECK(result.matched_rule->id() == "login-rate-limit");
                    CHECK(result.reason == std::optional<std::string>(
                                               "Too many login attempts"));
                }
            }
        }
    }
}

SCENARIO("create_adapter checks the handlers", "[adapter]") {
    GIVEN("handlers with only get_method set") {
        auto handlers =
            CustomAdapterHandlers<Request, Response>("incomplete")
                .get_method([](const Request& req) { return req.method; });

        WHEN("the adapter is built") {
            THEN("it reports the missing handlers") {
                CHECK_THROWS_AS(create_adapter(std::move(handlers)),
                                AdapterBuildError);
            }
        }
    }
}

SCENARIO("a handler's exception reaches the caller", "[adapter]") {
    GIVEN("an adapter whose get_ip throws") {
        auto waf = toy_waf();
        auto adapter = create_adapter(
            toy_handlers().get_ip([](const Request&) -> std::string {
                throw std::logic_error("no peer");
            }));
        Request request = get("/login");
        Response response;

        WHEN("a request is protected") {
            THEN("protect rethrows the handler's exception") {
                CHECK_THROWS_AS(waf.protect(adapter, request, response),
                                std::logic_error);
            }
        }
    }
}

SCENARIO("one instance is shared across threads", "[threads]") {
    GIVEN("a default WAF and an adapter") {
        auto waf =
            create_mini_waf(WafConfig().presets({WafPresetName::Default}));
        auto adapter = create_adapter(toy_handlers());

        WHEN("8 threads send 200 requests each, half of them traversals") {
            std::atomic<int> blocked{0};
            std::vector<std::thread> threads;
            for (int worker = 0; worker < 8; worker++) {
                threads.emplace_back([&, worker] {
                    for (int index = 0; index < 200; index++) {
                        Request request =
                            get(index % 2 ? "/files?name=../../etc/passwd"
                                          : "/home");
                        // One address per request: the default preset
                        // rate-limits each IP.
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

            THEN("exactly the traversals are blocked") {
                CHECK(blocked == 8 * 100);
            }
        }
    }
}

SCENARIO("handle evaluates a WafHttpContext", "[handle]") {
    GIVEN("a high WAF and a context with a NoSQL operator in the query") {
        auto waf = create_mini_waf(WafConfig()
                                       .presets({WafPresetName::Default})
                                       .level(ProtectionLevel::High));
        FixedContext ctx;

        WHEN("the context is handled") {
            auto result = waf.handle(ctx);

            THEN("it is blocked and dropped with 403") {
                CHECK(result.decision == WafDecision::Block);
                CHECK(ctx.blocked);
                CHECK(ctx.status == std::optional<std::uint16_t>(403));
            }
        }
    }
}

SCENARIO("a logger receives the requests it logs", "[logger]") {
    GIVEN("a WAF logging at debug level into a recording logger") {
        auto logger = std::make_shared<RecordingLogger>();
        auto waf = debug_waf(logged_by(logger));

        WHEN("an adapter request matches a log rule") {
            auto adapter = create_adapter(toy_handlers());
            Request request = get("/admin?page=2");
            request.uploads = {"avatar.png"};
            Response response;
            auto result = waf.protect(adapter, request, response);

            THEN("the logger sees the audit, then the connection") {
                CHECK(logger->events ==
                      std::vector<std::string>{"audit audit-admin",
                                               "connection Mozilla/5.0"});
                CHECK(logger->line ==
                      "toy-server http GET /admin?page=2 203.0.113.7");
                CHECK(logger->headers ==
                      HeaderMap{{"user-agent", std::string("Mozilla/5.0")}});
                REQUIRE(logger->query.size() == 1);
                CHECK(std::get<std::string>(logger->query[0].second.value) ==
                      "2");
                REQUIRE(logger->files.size() == 1);
                CHECK(logger->files[0].name == "avatar.png");
                CHECK(result.logged_rules.at(0).id() == "audit-admin");
            }
        }

        WHEN("a context request is blocked") {
            FixedContext ctx;
            auto result = waf.handle(ctx);

            THEN("the logger sees the block and the whole request") {
                REQUIRE(result.matched_rule);
                CHECK(logger->events.back() ==
                      "blocked " + result.matched_rule->id());
                CHECK(logger->line ==
                      "fixed https POST /api?debug=1 198.51.100.4");
                REQUIRE(logger->query.size() == 1);
                const auto& filter =
                    std::get<QueryMap>(logger->query[0].second.value);
                CHECK(filter.at(0).first == "$ne");
                CHECK(std::get<std::string>(filter.at(0).second.value) ==
                      "null");
                CHECK(logger->cookies == CookieMap{{"session", "abc"}});
                CHECK(logger->body == "name=Ada");
                CHECK(logger->port == 443);
            }
        }
    }
}

SCENARIO("a logger's request is read-only and its errors surface", "[logger]") {
    GIVEN("a logger that tries to change the request") {
        class Meddler : public WafLogger {
        public:
            void blocked(const WafHttpContext& ctx, const WafRule&) override {
                const_cast<WafHttpContext&>(ctx).drop(500, "changed");
            }
            void audit(const WafHttpContext&, const WafRule&) override {}
            void connection(const WafHttpContext&) override {}
        };
        WafEngineOptions options;
        options.logger = std::make_shared<Meddler>();
        auto waf = debug_waf(options);

        WHEN("it logs a block") {
            FixedContext ctx;
            THEN("handle throws its logic_error") {
                CHECK_THROWS_AS(waf.handle(ctx), std::logic_error);
            }
        }
    }

    GIVEN("a logger that throws") {
        auto logger = std::make_shared<RecordingLogger>();
        logger->throws = true;
        auto waf = debug_waf(logged_by(logger));

        WHEN("it logs an adapter request") {
            auto adapter = create_adapter(toy_handlers());
            Request request = get("/admin");
            Response response;
            THEN("protect rethrows the exception") {
                CHECK_THROWS_AS(waf.protect(adapter, request, response),
                                std::runtime_error);
            }
        }
    }
}

SCENARIO("instances share a rate-limit store", "[store]") {
    GIVEN("a store shared through the engine options") {
        WafEngineOptions options;
        options.rate_limit_store = RateLimitStore();
        auto old_waf = toy_waf(options);
        CHECK(login_status(old_waf) == 200);

        WHEN("the WAF is rebuilt with the same store") {
            auto new_waf = toy_waf(options);

            THEN("the new instance keeps counting") {
                CHECK(login_status(new_waf) == 403);
            }
        }

        WHEN("an instance is built on a running instance's store") {
            WafEngineOptions taken;
            taken.rate_limit_store = old_waf.rate_limit_store();
            auto successor = toy_waf(taken);

            THEN("it keeps counting too") {
                CHECK(login_status(successor) == 403);
            }
        }

        WHEN("an instance gets no store") {
            auto fresh = toy_waf();

            THEN("it starts from zero") { CHECK(login_status(fresh) == 200); }
        }
    }
}

SCENARIO("match patterns and fields", "[rules]") {
    GIVEN("a case-insensitive regex") {
        auto regex = MatchPattern::regex_with_flags("union\\s+select", "i");

        THEN("it matches whatever the case and spacing") {
            CHECK(regex.is_match("1 UNION  SELECT 2"));
            CHECK(!regex.is_match("union"));
        }
    }

    GIVEN("an invalid regex") {
        THEN("compiling it throws RegexError") {
            CHECK_THROWS_AS(MatchPattern::regex("(unclosed"), RegexError);
        }
    }

    GIVEN("one_of and exact patterns") {
        THEN("they match their literals") {
            CHECK(MatchPattern::one_of({"TRACE", "TRACK"}).is_match("TRACK"));
            CHECK(MatchPattern::exact("a").is_match("a"));
        }
    }

    GIVEN("a predicate that counts its calls") {
        std::atomic<int> calls{0};
        auto even = MatchPattern::predicate([&](std::string_view value) {
            calls++;
            return value.size() % 2 == 0;
        });

        WHEN("it is tried on two values") {
            bool two = even.is_match("ab");
            bool three = even.is_match("abc");

            THEN("it decides each one and runs once per value") {
                CHECK(two);
                CHECK(!three);
                CHECK(calls == 2);
            }
        }
    }

    GIVEN("a predicate that throws") {
        auto throwing = MatchPattern::predicate(
            [](std::string_view) -> bool { throw std::runtime_error("boom"); });

        THEN("is_match reports no match") { CHECK(!throwing.is_match("x")); }
    }

    GIVEN("field names") {
        THEN("invalid ones throw and valid ones round-trip") {
            CHECK_THROWS_AS(WafField::from_str("header.host"), InvalidField);
            CHECK(WafField::header("user-agent").to_string() ==
                  "headers.user-agent");
            CHECK(WafField::from_str("query.id").to_string() == "query.id");
        }
    }
}

SCENARIO("requires_any gates the pattern", "[rules]") {
    GIVEN("a bad-bot rule gated on the literal BADBOT") {
        auto waf = create_mini_waf(WafConfig().rules({
            WafRule("bad-bot",
                    FieldCondition(WafField::header("user-agent"))
                        .matches(MatchPattern::regex("bad-?bot"))
                        .requires_any({"BADBOT"}),
                    WafAction::Block),
        }));
        auto adapter = create_adapter(toy_handlers());

        WHEN("the user agent matches the pattern but holds no literal") {
            Request gated = get("/");
            gated.headers["user-agent"] = "bad-bot";
            Response response;

            THEN("the pattern is never tried and the request passes") {
                CHECK(waf.protect(adapter, gated, response).decision ==
                      WafDecision::Allow);
            }
        }

        WHEN("the user agent holds the literal") {
            Request caught = get("/");
            caught.headers["user-agent"] = "badbot/2.0";
            Response response;

            THEN("the rule blocks it") {
                CHECK(waf.protect(adapter, caught, response).decision ==
                      WafDecision::Block);
            }
        }
    }
}

SCENARIO("rule accessors and copies", "[rules]") {
    GIVEN("a rule with no optional member set") {
        WafRule rule("no-trace",
                     FieldCondition(WafField::Method()).equals("TRACE"),
                     WafAction::Block);

        THEN("its optional members are empty") {
            CHECK(!rule.enabled());
            CHECK(!rule.reason());
        }

        WHEN("its members are set") {
            rule.enabled(false).priority(7).min_level(ProtectionLevel::High);
            rule.reason("TRACE is disabled");

            THEN("the accessors return them") {
                CHECK(rule.enabled() == std::optional<bool>(false));
                CHECK(rule.priority() == std::optional<std::int64_t>(7));
                CHECK(rule.min_level() == std::optional(ProtectionLevel::High));
            }

            AND_WHEN("a copy is changed") {
                WafRule copy = rule;
                copy.reason("changed");

                THEN("the original keeps its value") {
                    CHECK(rule.reason() ==
                          std::optional<std::string>("TRACE is disabled"));
                    CHECK(copy.reason() ==
                          std::optional<std::string>("changed"));
                }
            }
        }
    }
}

SCENARIO("rules parsed from JSON and a full configuration", "[config]") {
    GIVEN("a JSON rules document") {
        auto rules = parse_rules_from_json(R"([{
            "id": "block-admin",
            "action": "block",
            "when": { "field": "path", "equals": "/admin" }
        }])");

        THEN("it yields one rule") { CHECK(rules.size() == 1); }

        WHEN("they build a WAF with every configuration option") {
            auto waf = create_mini_waf(
                WafConfig()
                    .rules(rules)
                    .presets({WafPresetName::Sqli})
                    .disabled_rule_ids({"preset-sqli-blind"})
                    .block_status_code(406)
                    .block_body("nope")
                    .decision_cache(DecisionCacheConfig{16, {}})
                    .decode(DecodeConfig{true, {}, {}})
                    .logging(WafLoggingOptions{WafLogLevel::Error})
                    .logging(false));

            THEN("the parsed rule is active and the disabled one is not") {
                bool found = false;
                for (const auto& rule : waf.rules()) {
                    found |= rule.id() == "block-admin";
                    CHECK(rule.id() != "preset-sqli-blind");
                }
                CHECK(found);
            }

            AND_WHEN("/admin is requested") {
                auto adapter = create_adapter(toy_handlers());
                Request request = get("/admin");
                Response response;
                waf.protect(adapter, request, response);

                THEN("the custom block response is sent") {
                    CHECK(response.status == 406);
                    CHECK(response.body == "nope");
                }
            }
        }
    }

    GIVEN("an invalid rules document") {
        THEN("parsing throws RuleParseError") {
            CHECK_THROWS_AS(parse_rules_from_json("[{\"id\":1}]"),
                            RuleParseError);
        }
    }
}

SCENARIO("client IP helpers", "[ip]") {
    GIVEN("forwarded, mapped and host addresses") {
        THEN("they are picked and normalized") {
            CHECK(pick_client_ip_from_xff("::ffff:1.2.3.4, 10.0.0.1") ==
                  "1.2.3.4");
            CHECK(normalize_client_ip("::ffff:10.0.0.1") == "10.0.0.1");
            CHECK(is_host_ip_literal("127.0.0.1:8080"));
        }
    }
}
