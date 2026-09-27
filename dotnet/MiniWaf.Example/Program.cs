// Protect a (pretend) server's requests with the universal adapter.
//
//     MINI_WAF_LIBRARY_PATH=$PWD/../target/release \
//         dotnet run --project MiniWaf.Example

using MurylloEx.MiniWaf;

// 1. Build the WAF once, at startup.
using MiniWafInstance waf = MiniWaf.CreateMiniWaf(
    new WafConfig()
        .Presets(WafPresetName.Default)
        .Level(ProtectionLevel.Balanced)
        .Rules(
            new WafRule(
                "allow-health",
                new FieldCondition(WafField.Path).Equals("/health"),
                WafAction.Allow
            ).Priority(1)
        )
);

// 2. Describe your server's request / response types once.
using var adapter = MiniWaf.CreateAdapter(
    new CustomAdapterHandlers<Request, Response>("example")
        .GetMethod(req => req.Method)
        .GetUrl(req => req.Target)
        .GetIp(req => req.Peer)
        .GetHeaders(req => new HeaderMap { { "user-agent", req.UserAgent } })
        .GetRawBody(_ => new RawBody.Empty())
        .SetResponseHeader((_, _, _) => { })
        .Drop((_, res, status, _) => res.Status = status)
);

// 3. Evaluate every request.
Request[] requests =
[
    new("GET", "/health", "198.51.100.4", "curl/8.0"),
    new(
        "GET",
        "/search?q=1'%20UNION%20SELECT%201",
        "198.51.100.4",
        "Mozilla/5.0"
    ),
    new("GET", "/", "198.51.100.4", "sqlmap/1.7"),
];
foreach (Request request in requests)
{
    Response response = new();
    WafEvaluationResult result = waf.Protect(adapter, request, response);
    Console.WriteLine(
        $"{request.Target} -> {response.Status} {result.MatchedRule?.Id()}"
    );
}

/// <summary>Your server's request type.</summary>
internal sealed record Request(
    string Method,
    string Target,
    string Peer,
    string UserAgent
);

/// <summary>Your server's response type.</summary>
internal sealed class Response
{
    public int Status { get; set; } = 200;
}
