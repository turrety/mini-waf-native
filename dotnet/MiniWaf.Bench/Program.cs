// Engine micro-benchmarks through the .NET binding, mirroring the A0-A6
// cases of `examples/bench.rs`. Each request goes through a custom adapter,
// so the numbers include the callbacks.
//
//     MINI_WAF_LIBRARY_PATH=$PWD/../target/release \
//         dotnet run -c Release --project MiniWaf.Bench            # 20 000
//     MINI_WAF_LIBRARY_PATH=$PWD/../target/release \
//         dotnet run -c Release --project MiniWaf.Bench -- 100000

using System.Diagnostics;
using System.Globalization;
using MurylloEx.MiniWaf;

int iterations = args.Length > 0 ? int.Parse(args[0]) : 20_000;

using var adapter = MiniWaf.CreateAdapter(
    new CustomAdapterHandlers<Request, Response>("bench")
        .GetMethod(req => req.Body.Length == 0 ? "GET" : "POST")
        .GetUrl(req => req.Url)
        .GetIp(req => req.Ip)
        .GetHeaders(_ => new HeaderMap
        {
            { "user-agent", "Mozilla/5.0 (compatible; BenchBot/1.0)" },
            { "accept", "application/json" },
            { "host", "localhost" },
        })
        .GetRawBody(req =>
            req.Body.Length == 0
                ? new RawBody.Empty()
                : new RawBody.Text(req.Body)
        )
        .SetResponseHeader((_, _, _) => { })
        .Drop((_, res, _, _) => res.Blocked = true)
);

string large =
    "{\"note\":\"pad\",\"data\":\"" + new string('A', 8192 - 40) + "\"}";
Request clean = new("/api/items?page=1", "10.0.0.1", "");

Console.WriteLine(
    $"iterations: {iterations} (+10000 warmup); "
        + "preset-dos-rate-limit disabled on A1-A6\n"
);
Console.WriteLine(
    "| ID | Case | Rules | ops/s | p50 | p95 | p99 | Decision |\n"
        + "|---|---|---:|---:|---:|---:|---:|---|"
);

using (MiniWafInstance empty = MiniWaf.CreateMiniWaf(new WafConfig()))
{
    Run("A0", "0 rules (baseline protect)", empty, new("/", "10.0.0.9", ""));
}
using MiniWafInstance balanced = MiniWaf.CreateMiniWaf(
    Config(ProtectionLevel.Balanced)
);
Run("A1", "balanced, clean allow", balanced, clean);
using (
    MiniWafInstance cached = MiniWaf.CreateMiniWaf(
        Config(ProtectionLevel.Balanced).DecisionCache(new())
    )
)
{
    Run("A2", "A1 + decision cache (same fingerprint)", cached, clean);
}
Run("A3", "A1 + 8KB JSON body", balanced, new("/echo", "10.0.0.3", large));
Run(
    "A4",
    "A1 + small (~24B) body",
    balanced,
    new("/echo", "10.0.0.3", "{\"ok\":true,\"q\":\"hello\"}")
);
Run(
    "A5",
    "A1 SQLi - block path",
    balanced,
    new("/search?q=1'%20OR%201=1%20--", "10.0.0.2", "")
);
foreach (ProtectionLevel level in Enum.GetValues<ProtectionLevel>())
{
    string name = level.ToString().ToLowerInvariant();
    using MiniWafInstance waf = MiniWaf.CreateMiniWaf(Config(level));
    Run($"A6-{name}", $"{name}, clean allow", waf, clean);
}

static WafConfig Config(ProtectionLevel level) =>
    new WafConfig()
        .Presets(WafPresetName.Default)
        .Level(level)
        .DisabledRuleIds("preset-dos-rate-limit");

static double Percentile(double[] sorted, double p) =>
    sorted[Math.Min((int)(sorted.Length * p), sorted.Length - 1)];

void Run(string id, string name, MiniWafInstance waf, Request request)
{
    for (int warmup = 0; warmup < 10000; warmup++)
    {
        waf.Protect(adapter, request, new Response());
    }
    double[] samples = new double[iterations];
    WafDecision decision = WafDecision.Allow;
    long started = Stopwatch.GetTimestamp();
    for (int index = 0; index < iterations; index++)
    {
        Response response = new();
        long begin = Stopwatch.GetTimestamp();
        decision = waf.Protect(adapter, request, response).Decision;
        samples[index] = Stopwatch.GetElapsedTime(begin).TotalMicroseconds;
    }
    double wall = Stopwatch.GetElapsedTime(started).TotalSeconds;
    Array.Sort(samples);
    Console.WriteLine(
        string.Format(
            CultureInfo.InvariantCulture,
            "| {0,-12} | {1,-38} | {2,5} | {3,10:F2}k/s | {4,8:F2} us "
                + "| {5,8:F2} us | {6,8:F2} us | {7} |",
            id,
            name,
            waf.Rules().Count,
            iterations / wall / 1000.0,
            Percentile(samples, 0.50),
            Percentile(samples, 0.95),
            Percentile(samples, 0.99),
            decision
        )
    );
}

/// <summary>A pre-built request.</summary>
internal sealed record Request(string Url, string Ip, string Body);

/// <summary>What the adapter's <c>Drop</c> handler writes to.</summary>
internal sealed class Response
{
    public bool Blocked { get; set; }
}
