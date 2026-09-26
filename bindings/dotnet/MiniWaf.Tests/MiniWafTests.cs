using System.Runtime.CompilerServices;
using System.Text;
using Xunit;

namespace MurylloEx.MiniWaf.Tests;

internal static class LibraryPath
{
    /// <summary>
    /// Point the binding at the workspace build (<c>target/release</c>)
    /// unless <c>MINI_WAF_LIBRARY_PATH</c> is already set.
    /// </summary>
    [ModuleInitializer]
    internal static void Initialize()
    {
        if (
            Environment.GetEnvironmentVariable("MINI_WAF_LIBRARY_PATH") is
            { Length: > 0 }
        )
        {
            return;
        }
        for (
            DirectoryInfo? directory = new(AppContext.BaseDirectory);
            directory is not null;
            directory = directory.Parent
        )
        {
            string release = Path.Combine(
                directory.FullName,
                "target",
                "release"
            );
            if (Directory.Exists(release))
            {
                Environment.SetEnvironmentVariable(
                    "MINI_WAF_LIBRARY_PATH",
                    release
                );
                return;
            }
        }
    }
}

public class MiniWafTests
{
    /// <summary>A toy server's request.</summary>
    private sealed class Request(string target)
    {
        public string Method = "GET";
        public string Target = target;
        public string Peer = "203.0.113.7";
        public Dictionary<string, string> Headers = new()
        {
            ["user-agent"] = "Mozilla/5.0",
        };
        public string Body = "";
        public List<string> Uploads = [];
    }

    /// <summary>A toy server's response.</summary>
    private sealed class Response
    {
        public int Status = 200;
        public string Body = "";
        public Dictionary<string, string> Headers = [];
    }

    private static CustomAdapterHandlers<Request, Response> ToyHandlers() =>
        new CustomAdapterHandlers<Request, Response>("toy-server")
            .GetMethod(req => req.Method)
            .GetUrl(req => req.Target)
            .GetIp(req => req.Peer)
            .GetHeaders(req =>
            {
                HeaderMap headers = new();
                foreach ((string name, string value) in req.Headers)
                {
                    headers.Insert(name, value);
                }
                return headers;
            })
            .GetRawBody(req => Encoding.UTF8.GetBytes(req.Body))
            .GetFiles(req => req.Uploads.Select(UploadedFile.Named).ToArray())
            .SetResponseHeader((res, name, value) => res.Headers[name] = value)
            .Drop(
                (req, res, status, body) =>
                {
                    res.Status = status;
                    res.Body = body;
                }
            );

    private static MiniWafInstance ToyWaf() =>
        MiniWaf.CreateMiniWaf(
            new WafConfig()
                .Presets(WafPresetName.Default)
                .Level(ProtectionLevel.Balanced)
                .Rules(
                    new WafRule(
                        "audit-admin",
                        new FieldCondition(WafField.Path).Equals("/admin"),
                        WafAction.Log
                    ),
                    new WafRule(
                        "login-rate-limit",
                        WafCondition.All(
                            new FieldCondition(WafField.Path).Equals("/login"),
                            new FieldCondition(WafField.Ip).RateLimit(
                                new RateLimitSpec(1, 60_000)
                            )
                        ),
                        WafAction.Block
                    ).Reason("Too many login attempts")
                )
        );

    [Fact]
    public void ProtectBlocksAttacks()
    {
        using MiniWafInstance waf = ToyWaf();
        using var adapter = MiniWaf.CreateAdapter(ToyHandlers());

        Response response = new();
        WafEvaluationResult result = waf.Protect(
            adapter,
            new Request(
                "/search?q=1'%20UNION%20SELECT%20password%20FROM%20users"
            ),
            response
        );
        Assert.Equal(WafDecision.Block, result.Decision);
        Assert.Equal("preset-sqli-classic-query", result.MatchedRule?.Id());
        Assert.NotNull(result.Reason);
        Assert.Equal(403, response.Status);
        Assert.Equal("Forbidden", response.Body);

        Request scanner = new("/");
        scanner.Headers["user-agent"] = "sqlmap/1.7";
        Request xss = new("/comments")
        {
            Method = "POST",
            Body = "{\"q\":\"<script>alert(1)</script>\"}",
        };
        Request upload = new("/upload") { Uploads = ["shell.php"] };
        foreach (Request request in new[] { scanner, xss, upload })
        {
            Response blocked = new();
            waf.Protect(adapter, request, blocked);
            Assert.Equal(403, blocked.Status);
        }
    }

    [Fact]
    public void ProtectAllowsAndReportsLoggedRules()
    {
        using MiniWafInstance waf = ToyWaf();
        using var adapter = MiniWaf.CreateAdapter(ToyHandlers());
        Response response = new();

        WafEvaluationResult result = waf.Protect(
            adapter,
            new Request("/admin"),
            response
        );
        Assert.Equal(WafDecision.Allow, result.Decision);
        Assert.Null(result.MatchedRule);
        WafRule logged = Assert.Single(result.LoggedRules);
        Assert.Equal("audit-admin", logged.Id());
        Assert.Equal(WafAction.Log, logged.Action());
        Assert.Equal(200, response.Status);
    }

    [Fact]
    public void ProtectRateLimitsWithHeaders()
    {
        using MiniWafInstance waf = ToyWaf();
        using var adapter = MiniWaf.CreateAdapter(ToyHandlers());

        Response first = new();
        waf.Protect(adapter, new Request("/login"), first);
        Assert.Equal(200, first.Status);
        Assert.Equal("1", first.Headers["X-RateLimit-Limit"]);

        Response second = new();
        WafEvaluationResult result = waf.Protect(
            adapter,
            new Request("/login"),
            second
        );
        Assert.Equal(403, second.Status);
        Assert.Equal("login-rate-limit", result.MatchedRule?.Id());
        Assert.Equal("Too many login attempts", result.Reason);
    }

    [Fact]
    public void CreateAdapterReportsMissingHandlers()
    {
        AdapterBuildError error = Assert.Throws<AdapterBuildError>(() =>
            MiniWaf.CreateAdapter(
                new CustomAdapterHandlers<Request, Response>(
                    "incomplete"
                ).GetMethod(req => req.Method)
            )
        );
        string[] missing =
        [
            "get_url",
            "get_ip",
            "get_headers",
            "get_raw_body",
            "set_response_header",
            "drop",
        ];
        Assert.Equal(missing, error.Missing);
    }

    [Fact]
    public void HandlerExceptionsPropagate()
    {
        using MiniWafInstance waf = ToyWaf();
        using var adapter = MiniWaf.CreateAdapter(
            ToyHandlers().GetIp(_ => throw new ArgumentException("no peer"))
        );
        ArgumentException error = Assert.Throws<ArgumentException>(() =>
            waf.Protect(adapter, new Request("/login"), new Response())
        );
        Assert.Equal("no peer", error.Message);
    }

    [Fact]
    public async Task SharesOneInstanceAcrossThreads()
    {
        using MiniWafInstance waf = MiniWaf.CreateMiniWaf(
            new WafConfig().Presets(WafPresetName.Default)
        );
        using var adapter = MiniWaf.CreateAdapter(ToyHandlers());
        int blocked = 0;
        Task[] workers =
        [
            .. Enumerable
                .Range(0, 8)
                .Select(worker =>
                    Task.Run(() =>
                    {
                        for (int index = 0; index < 200; index++)
                        {
                            Request request = new(
                                index % 2 == 1
                                    ? "/files?name=../../etc/passwd"
                                    : "/home"
                            )
                            {
                                // One address per request: the default preset
                                // rate-limits each IP.
                                Peer = $"10.0.{worker}.{index}",
                            };
                            Response response = new();
                            waf.Protect(adapter, request, response);
                            if (response.Status == 403)
                            {
                                Interlocked.Increment(ref blocked);
                            }
                        }
                    })
                ),
        ];
        await Task.WhenAll(workers);
        Assert.Equal(8 * 100, blocked);
    }

    /// <summary>A WafHttpContext over a fixed POST request.</summary>
    private sealed class FixedContext : WafHttpContext
    {
        public ushort? Status;
        public bool Blocked;

        public string Framework() => "fixed";

        public string GetMethod() => "POST";

        public string GetUrl() => "/api?debug=1";

        public string GetPath() => "/api";

        public string GetIp() => "198.51.100.4";

        public string GetProtocol() => "https";

        public ushort GetLocalPort() => 443;

        public string? GetHeader(string name) =>
            name == "user-agent" ? "curl/8.0" : null;

        public HeaderMap GetHeaders() => new() { { "user-agent", "curl/8.0" } };

        public QueryMap GetQuery() =>
            new()
            {
                {
                    "filter",
                    new QueryValue.Object(new QueryMap { { "$ne", "null" } })
                },
                { "page", new QueryValue.Array([new QueryValue.Number(1)]) },
            };

        public CookieMap GetCookies() => new() { { "session", "abc" } };

        public string GetRawBody() => "name=Ada";

        public IReadOnlyList<UploadedFile> GetFiles() => [];

        public void SetResponseHeader(string name, string value) { }

        public void RemoveResponseHeader(string name) { }

        public bool IsBlocked() => Blocked;

        public void Drop(ushort? statusCode, string? body)
        {
            Blocked = true;
            Status = statusCode;
        }
    }

    [Fact]
    public void HandleEvaluatesAContext()
    {
        using MiniWafInstance waf = MiniWaf.CreateMiniWaf(
            new WafConfig()
                .Presets(WafPresetName.Default)
                .Level(ProtectionLevel.High)
        );
        FixedContext ctx = new();
        WafEvaluationResult result = waf.Handle(ctx);
        Assert.Equal(WafDecision.Block, result.Decision);
        Assert.True(ctx.Blocked);
        Assert.Equal((ushort)403, ctx.Status);
    }

    [Fact]
    public void MatchPatternsAndFields()
    {
        Assert.Throws<RegexError>(() => MatchPattern.Regex("(unclosed"));
        using MatchPattern regex = MatchPattern.RegexWithFlags(
            @"union\s+select",
            "i"
        );
        Assert.True(regex.IsMatch("1 UNION  SELECT 2"));
        Assert.False(regex.IsMatch("union"));
        Assert.True(MatchPattern.OneOf("TRACE", "TRACK").IsMatch("TRACK"));
        Assert.True(MatchPattern.Exact("a").IsMatch("a"));

        int calls = 0;
        using MatchPattern even = MatchPattern.Predicate(value =>
        {
            calls++;
            return value.Length % 2 == 0;
        });
        Assert.True(even.IsMatch("ab"));
        Assert.False(even.IsMatch("abc"));
        Assert.Equal(2, calls);

        using MatchPattern throwing = MatchPattern.Predicate(_ =>
            throw new InvalidOperationException("boom")
        );
        Assert.Throws<InvalidOperationException>(() => throwing.IsMatch("x"));

        InvalidField error = Assert.Throws<InvalidField>(() =>
            WafField.FromStr("header.host")
        );
        Assert.Equal("unsupported field \"header.host\"", error.Message);
        Assert.Equal(
            "headers.user-agent",
            WafField.Header("user-agent").ToString()
        );
        Assert.Equal(WafField.QueryParam("id"), WafField.FromStr("query.id"));
        Assert.Equal(WafField.Ip, WafField.FromStr("ip"));
    }

    [Fact]
    public void RuleAccessorsAndViews()
    {
        WafRule rule = new(
            "no-trace",
            new FieldCondition(WafField.Method).Equals("TRACE"),
            WafAction.Block
        );
        Assert.Null(rule.Enabled());
        Assert.Null(rule.Reason());
        rule.Enabled(false)
            .Priority(7)
            .MinLevel(ProtectionLevel.High)
            .Reason("TRACE is disabled");
        Assert.False(rule.Enabled());
        Assert.Equal(7, rule.Priority());
        Assert.Equal(ProtectionLevel.High, rule.MinLevel());
        Assert.Equal("TRACE is disabled", rule.Reason());

        MiniWafInstance waf = MiniWaf.CreateMiniWaf(
            new WafConfig()
                .Level(ProtectionLevel.High)
                .Rules(rule.Enabled(true))
        );
        WafRule view = waf.Rules()[0];
        view.Reason("changed");
        Assert.Equal("changed", view.Reason());
        Assert.Equal("TRACE is disabled", waf.Rules()[0].Reason());

        WafCondition when = waf.Rules()[0].When();
        using MiniWafInstance rebuilt = MiniWaf.CreateMiniWaf(
            new WafConfig().Rules(new WafRule("again", when, WafAction.Block))
        );
        Assert.Equal("again", rebuilt.Rules()[0].Id());

        WafRule stale = waf.Rules()[0];
        waf.Dispose();
        Assert.Throws<ObjectDisposedException>(() => waf.Rules());
        Assert.Throws<ObjectDisposedException>(() => stale.Id());
    }

    [Fact]
    public void ParseRulesAndConfig()
    {
        IReadOnlyList<WafRule> rules = MiniWaf.ParseRulesFromJson(
            """
            [{
              "id": "block-admin",
              "action": "block",
              "when": { "field": "path", "equals": "/admin" }
            }]
            """
        );
        Assert.Single(rules);
        Assert.Throws<RuleParseError>(() =>
            MiniWaf.ParseRulesFromJson("""[{"id":1}]""")
        );

        using MiniWafInstance waf = MiniWaf.CreateMiniWaf(
            new WafConfig()
                .Rules(rules)
                .Presets(WafPresetName.Sqli)
                .DisabledRuleIds("preset-sqli-blind")
                .BlockStatusCode(406)
                .BlockBody("nope")
                .DecisionCache(new DecisionCacheConfig(Max: 16))
                .Decode(new DecodeConfig(Base64: true))
                .MaxFieldLength(4096)
                .MaxRateLimitKeys(100)
                .Logging(new WafLoggingOptions(WafLogLevel.Error))
                .Logging(false)
        );
        List<string> ids = [.. waf.Rules().Select(rule => rule.Id())];
        Assert.Contains("block-admin", ids);
        Assert.DoesNotContain("preset-sqli-blind", ids);

        using var adapter = MiniWaf.CreateAdapter(ToyHandlers());
        Response response = new();
        waf.Protect(adapter, new Request("/admin"), response);
        Assert.Equal(406, response.Status);
        Assert.Equal("nope", response.Body);
    }

    [Fact]
    public void IpHelpers()
    {
        Assert.Equal(
            "1.2.3.4",
            MiniWaf.PickClientIpFromXff("::ffff:1.2.3.4, 10.0.0.1")
        );
        Assert.Equal("10.0.0.1", MiniWaf.NormalizeClientIp("::ffff:10.0.0.1"));
        Assert.True(MiniWaf.IsHostIpLiteral("127.0.0.1:8080"));
        Assert.False(MiniWaf.IsHostIpLiteral("example.com"));
    }
}
