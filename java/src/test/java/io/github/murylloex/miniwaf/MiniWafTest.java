package io.github.murylloex.miniwaf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class MiniWafTest {

    /** A toy server's request. */
    static final class Request {

        String method = "GET";
        String target;
        String peer = "203.0.113.7";
        Map<String, String> headers = new LinkedHashMap<>(
            Map.of("user-agent", "Mozilla/5.0")
        );
        String body = "";
        List<String> uploads = List.of();

        Request(String target) {
            this.target = target;
        }
    }

    /** A toy server's response. */
    static final class Response {

        int status = 200;
        String body = "";
        Map<String, String> headers = new LinkedHashMap<>();
    }

    static CustomAdapterHandlers<Request, Response> toyHandlers() {
        return new CustomAdapterHandlers<Request, Response>("toy-server")
            .getMethod(req -> req.method)
            .getUrl(req -> req.target)
            .getIp(req -> req.peer)
            .getHeaders(req -> {
                HeaderMap headers = new HeaderMap();
                req.headers.forEach(headers::insert);
                return headers;
            })
            .getRawBody(req ->
                RawBody.from(req.body.getBytes(StandardCharsets.UTF_8))
            )
            .getFiles(req ->
                FilesBag.from(
                    req.uploads.stream().map(UploadedFile::named).toList()
                )
            )
            .setResponseHeader((res, name, value) ->
                res.headers.put(name, value)
            )
            .drop((req, res, status, body) -> {
                res.status = status;
                res.body = body;
            });
    }

    static MiniWafInstance toyWaf() {
        return MiniWaf.createMiniWaf(
            new WafConfig()
                .presets(WafPresetName.DEFAULT)
                .level(ProtectionLevel.BALANCED)
                .rules(
                    new WafRule(
                        "audit-admin",
                        new FieldCondition(WafField.PATH).equals("/admin"),
                        WafAction.LOG
                    ),
                    new WafRule(
                        "login-rate-limit",
                        WafCondition.all(
                            new FieldCondition(WafField.PATH)
                                .equals("/login")
                                .into(),
                            new FieldCondition(WafField.IP)
                                .rateLimit(new RateLimitSpec(1, 60_000))
                                .into()
                        ),
                        WafAction.BLOCK
                    ).reason("Too many login attempts")
                )
        );
    }

    @Test
    void protectBlocksAttacks() {
        MiniWafInstance waf = toyWaf();
        CustomAdapter<Request, Response> adapter = MiniWaf.createAdapter(
            toyHandlers()
        );

        Response response = new Response();
        WafEvaluationResult result = waf.protect(
            adapter,
            new Request(
                "/search?q=1'%20UNION%20SELECT%20password%20FROM%20users"
            ),
            response
        );
        assertEquals(WafDecision.BLOCK, result.decision());
        assertEquals(
            "preset-sqli-classic-query",
            result.matchedRule().orElseThrow().id()
        );
        assertTrue(result.reason().isPresent());
        assertEquals(403, response.status);
        assertEquals("Forbidden", response.body);

        Request scanner = new Request("/");
        scanner.headers.put("user-agent", "sqlmap/1.7");
        Request xss = new Request("/comments");
        xss.method = "POST";
        xss.body = "{\"q\":\"<script>alert(1)</script>\"}";
        Request upload = new Request("/upload");
        upload.uploads = List.of("shell.php");
        for (Request request : List.of(scanner, xss, upload)) {
            Response blocked = new Response();
            waf.protect(adapter, request, blocked);
            assertEquals(403, blocked.status, request.target);
        }
    }

    @Test
    void protectAllowsAndReportsLoggedRules() {
        MiniWafInstance waf = toyWaf();
        CustomAdapter<Request, Response> adapter = MiniWaf.createAdapter(
            toyHandlers()
        );
        Response response = new Response();

        WafEvaluationResult result = waf.protect(
            adapter,
            new Request("/admin"),
            response
        );
        assertEquals(WafDecision.ALLOW, result.decision());
        assertTrue(result.matchedRule().isEmpty());
        assertEquals(1, result.loggedRules().size());
        assertEquals("audit-admin", result.loggedRules().get(0).id());
        assertEquals(WafAction.LOG, result.loggedRules().get(0).action());
        assertEquals(200, response.status);
    }

    @Test
    void protectRateLimitsWithHeaders() {
        MiniWafInstance waf = toyWaf();
        CustomAdapter<Request, Response> adapter = MiniWaf.createAdapter(
            toyHandlers()
        );

        Response first = new Response();
        waf.protect(adapter, new Request("/login"), first);
        assertEquals(200, first.status);
        assertEquals("1", first.headers.get("X-RateLimit-Limit"));

        Response second = new Response();
        WafEvaluationResult result = waf.protect(
            adapter,
            new Request("/login"),
            second
        );
        assertEquals(403, second.status);
        assertEquals(
            "login-rate-limit",
            result.matchedRule().orElseThrow().id()
        );
        assertEquals(Optional.of("Too many login attempts"), result.reason());
    }

    @Test
    void createAdapterReportsMissingHandlers() {
        AdapterBuildError error = assertThrows(AdapterBuildError.class, () ->
            MiniWaf.createAdapter(
                new CustomAdapterHandlers<Request, Response>(
                    "incomplete"
                ).getMethod(req -> req.method)
            )
        );
        assertEquals(
            List.of(
                "get_url",
                "get_ip",
                "get_headers",
                "get_raw_body",
                "set_response_header",
                "drop"
            ),
            error.missing()
        );
    }

    @Test
    void handlerExceptionsPropagate() {
        MiniWafInstance waf = toyWaf();
        CustomAdapter<Request, Response> adapter = MiniWaf.createAdapter(
            toyHandlers().getIp(req -> {
                throw new IllegalArgumentException("no peer");
            })
        );
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> waf.protect(adapter, new Request("/login"), new Response())
        );
        assertEquals("no peer", error.getMessage());
    }

    @Test
    void sharesOneInstanceAcrossThreads() throws Exception {
        MiniWafInstance waf = MiniWaf.createMiniWaf(
            new WafConfig().presets(WafPresetName.DEFAULT)
        );
        CustomAdapter<Request, Response> adapter = MiniWaf.createAdapter(
            toyHandlers()
        );
        AtomicInteger blocked = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<?>> workers = new ArrayList<>();
            for (int worker = 0; worker < 8; worker++) {
                int id = worker;
                workers.add(
                    pool.submit(() -> {
                        for (int index = 0; index < 200; index++) {
                            Request request = new Request(
                                index % 2 == 1
                                    ? "/files?name=../../etc/passwd"
                                    : "/home"
                            );
                            // One address per request: the default preset
                            // rate-limits each IP.
                            request.peer = "10.0." + id + "." + index;
                            Response response = new Response();
                            waf.protect(adapter, request, response);
                            if (response.status == 403) {
                                blocked.incrementAndGet();
                            }
                        }
                    })
                );
            }
            for (Future<?> future : workers) {
                future.get();
            }
        } finally {
            pool.shutdown();
        }
        assertEquals(8 * 100, blocked.get());
    }

    /** A WafHttpContext over a fixed POST request. */
    static final class FixedContext implements WafHttpContext {

        OptionalInt status = OptionalInt.empty();
        boolean blocked;

        @Override
        public String framework() {
            return "fixed";
        }

        @Override
        public String getMethod() {
            return "POST";
        }

        @Override
        public String getUrl() {
            return "/api?debug=1";
        }

        @Override
        public String getPath() {
            return "/api";
        }

        @Override
        public String getIp() {
            return "198.51.100.4";
        }

        @Override
        public String getProtocol() {
            return "https";
        }

        @Override
        public int getLocalPort() {
            return 443;
        }

        @Override
        public Optional<String> getHeader(String name) {
            return name.equals("user-agent")
                ? Optional.of("curl/8.0")
                : Optional.empty();
        }

        @Override
        public HeaderMap getHeaders() {
            return new HeaderMap().insert("user-agent", "curl/8.0");
        }

        @Override
        public QueryMap getQuery() {
            QueryMap filter = new QueryMap().insert("$ne", "null");
            QueryMap query = new QueryMap();
            query.put("filter", new QueryValue.Object(filter));
            query.put(
                "page",
                new QueryValue.Array(List.of(new QueryValue.Number(1)))
            );
            return query;
        }

        @Override
        public CookieMap getCookies() {
            CookieMap cookies = new CookieMap();
            cookies.put("session", "abc");
            return cookies;
        }

        @Override
        public String getRawBody() {
            return "name=Ada";
        }

        @Override
        public List<UploadedFile> getFiles() {
            return List.of();
        }

        @Override
        public void setResponseHeader(String name, String value) {}

        @Override
        public void removeResponseHeader(String name) {}

        @Override
        public boolean isBlocked() {
            return blocked;
        }

        @Override
        public void drop(OptionalInt statusCode, Optional<String> body) {
            blocked = true;
            status = statusCode;
        }
    }

    @Test
    void handleEvaluatesAContext() {
        MiniWafInstance waf = MiniWaf.createMiniWaf(
            new WafConfig()
                .presets(WafPresetName.DEFAULT)
                .level(ProtectionLevel.HIGH)
        );
        FixedContext ctx = new FixedContext();
        WafEvaluationResult result = waf.handle(ctx);
        assertEquals(WafDecision.BLOCK, result.decision());
        assertTrue(ctx.blocked);
        assertEquals(OptionalInt.of(403), ctx.status);
    }

    @Test
    void matchPatternsAndFields() {
        assertThrows(RegexError.class, () -> MatchPattern.regex("(unclosed"));
        MatchPattern regex = MatchPattern.regexWithFlags(
            "union\\s+select",
            "i"
        );
        assertTrue(regex.isMatch("1 UNION  SELECT 2"));
        assertFalse(regex.isMatch("union"));
        assertTrue(MatchPattern.oneOf("TRACE", "TRACK").isMatch("TRACK"));
        assertTrue(MatchPattern.exact("a").isMatch("a"));

        AtomicInteger calls = new AtomicInteger();
        MatchPattern even = MatchPattern.predicate(value -> {
            calls.incrementAndGet();
            return value.length() % 2 == 0;
        });
        assertTrue(even.isMatch("ab"));
        assertFalse(even.isMatch("abc"));
        assertEquals(2, calls.get());

        MatchPattern throwing = MatchPattern.predicate(value -> {
            throw new IllegalStateException("boom");
        });
        assertThrows(IllegalStateException.class, () -> throwing.isMatch("x"));

        InvalidField error = assertThrows(InvalidField.class, () ->
            WafField.fromStr("header.host")
        );
        assertEquals("unsupported field \"header.host\"", error.getMessage());
        assertEquals(
            "headers.user-agent",
            WafField.header("user-agent").toString()
        );
        assertEquals(WafField.query("id"), WafField.fromStr("query.id"));
        assertEquals(WafField.IP, WafField.fromStr("ip"));
    }

    @Test
    void ruleAccessorsAndViews() {
        WafRule rule = new WafRule(
            "no-trace",
            new FieldCondition(WafField.METHOD).equals("TRACE"),
            WafAction.BLOCK
        );
        assertTrue(rule.enabled().isEmpty());
        assertTrue(rule.reason().isEmpty());
        rule.enabled(false)
            .priority(7)
            .minLevel(ProtectionLevel.HIGH)
            .reason("TRACE is disabled");
        assertEquals(Optional.of(false), rule.enabled());
        assertEquals(OptionalLong.of(7), rule.priority());
        assertEquals(Optional.of(ProtectionLevel.HIGH), rule.minLevel());
        assertEquals(Optional.of("TRACE is disabled"), rule.reason());

        MiniWafInstance waf = MiniWaf.createMiniWaf(
            new WafConfig()
                .level(ProtectionLevel.HIGH)
                .rules(rule.enabled(true))
        );
        WafRule view = waf.rules().get(0);
        view.reason("changed");
        assertEquals(Optional.of("changed"), view.reason());
        assertEquals(
            Optional.of("TRACE is disabled"),
            waf.rules().get(0).reason()
        );

        WafCondition when = waf.rules().get(0).when();
        MiniWafInstance rebuilt = MiniWaf.createMiniWaf(
            new WafConfig().rules(new WafRule("again", when, WafAction.BLOCK))
        );
        assertEquals("again", rebuilt.rules().get(0).id());

        waf.close();
        assertThrows(IllegalStateException.class, () -> waf.rules());
    }

    @Test
    void parseRulesAndConfig() {
        List<WafRule> rules = MiniWaf.parseRulesFromJson(
            """
            [{
              "id": "block-admin",
              "action": "block",
              "when": { "field": "path", "equals": "/admin" }
            }]"""
        );
        assertEquals(1, rules.size());
        assertThrows(RuleParseError.class, () ->
            MiniWaf.parseRulesFromJson("[{\"id\":1}]")
        );

        MiniWafInstance waf = MiniWaf.createMiniWaf(
            new WafConfig()
                .rules(rules)
                .presets(WafPresetName.SQLI)
                .disabledRuleIds("preset-sqli-blind")
                .blockStatusCode(406)
                .blockBody("nope")
                .decisionCache(new DecisionCacheConfig(16L, null))
                .decode(new DecodeConfig(true, null, null))
                .maxFieldLength(4096)
                .maxRateLimitKeys(100)
                .logging(new WafLoggingOptions(WafLogLevel.ERROR))
                .logging(false)
        );
        List<String> ids = waf.rules().stream().map(WafRule::id).toList();
        assertTrue(ids.contains("block-admin"));
        assertFalse(ids.contains("preset-sqli-blind"));

        CustomAdapter<Request, Response> adapter = MiniWaf.createAdapter(
            toyHandlers()
        );
        Response response = new Response();
        waf.protect(adapter, new Request("/admin"), response);
        assertEquals(406, response.status);
        assertEquals("nope", response.body);
    }

    @Test
    void ipHelpers() {
        assertEquals(
            "1.2.3.4",
            MiniWaf.pickClientIpFromXff("::ffff:1.2.3.4, 10.0.0.1")
        );
        assertEquals("10.0.0.1", MiniWaf.normalizeClientIp("::ffff:10.0.0.1"));
        assertTrue(MiniWaf.isHostIpLiteral("127.0.0.1:8080"));
        assertFalse(MiniWaf.isHostIpLiteral("example.com"));
    }
}
