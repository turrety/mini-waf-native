// Engine micro-benchmarks through the Java binding, mirroring the A0-A6
// cases of `examples/bench.rs`. Each request goes through a custom adapter,
// so the numbers include the upcalls.
//
//     mvn -B -q compile
//     java --enable-native-access=ALL-UNNAMED -cp target/classes \
//         -Dmini_waf.library.path=../target/release examples/Bench.java
//     # append an iteration count to override the default 20 000

import io.github.murylloex.miniwaf.CustomAdapter;
import io.github.murylloex.miniwaf.CustomAdapterHandlers;
import io.github.murylloex.miniwaf.DecisionCacheConfig;
import io.github.murylloex.miniwaf.HeaderMap;
import io.github.murylloex.miniwaf.MiniWaf;
import io.github.murylloex.miniwaf.MiniWafInstance;
import io.github.murylloex.miniwaf.ProtectionLevel;
import io.github.murylloex.miniwaf.RawBody;
import io.github.murylloex.miniwaf.WafConfig;
import io.github.murylloex.miniwaf.WafDecision;
import io.github.murylloex.miniwaf.WafPresetName;
import java.util.Arrays;
import java.util.Locale;

public class Bench {

    record Request(String url, String ip, String body) {}

    static final class Response {

        boolean blocked;
    }

    static final CustomAdapter<Request, Response> ADAPTER =
        MiniWaf.createAdapter(
            new CustomAdapterHandlers<Request, Response>("bench")
                .getMethod(req -> req.body().isEmpty() ? "GET" : "POST")
                .getUrl(Request::url)
                .getIp(Request::ip)
                .getHeaders(req ->
                    new HeaderMap()
                        .insert(
                            "user-agent",
                            "Mozilla/5.0 (compatible; BenchBot/1.0)"
                        )
                        .insert("accept", "application/json")
                        .insert("host", "localhost")
                )
                .getRawBody(req ->
                    req.body().isEmpty()
                        ? new RawBody.Empty()
                        : new RawBody.Text(req.body())
                )
                .setResponseHeader((res, name, value) -> {})
                .drop((req, res, status, body) -> res.blocked = true)
        );

    static WafConfig config(ProtectionLevel level) {
        return new WafConfig()
            .presets(WafPresetName.DEFAULT)
            .level(level)
            .disabledRuleIds("preset-dos-rate-limit");
    }

    static double percentile(double[] sorted, double p) {
        int index = (int) (sorted.length * p);
        return sorted[Math.min(index, sorted.length - 1)];
    }

    static void run(
        String id,
        String name,
        MiniWafInstance waf,
        Request request,
        int iterations
    ) {
        for (int warmup = 0; warmup < 10000; warmup++) {
            waf.protect(ADAPTER, request, new Response());
        }
        double[] samples = new double[iterations];
        WafDecision decision = WafDecision.ALLOW;
        long started = System.nanoTime();
        for (int index = 0; index < iterations; index++) {
            Response response = new Response();
            long begin = System.nanoTime();
            decision = waf.protect(ADAPTER, request, response).decision();
            samples[index] = (System.nanoTime() - begin) / 1e3;
        }
        double wall = (System.nanoTime() - started) / 1e9;
        Arrays.sort(samples);
        System.out.println(
            String.format(
                Locale.ROOT,
                "| %-12s | %-38s | %5d | %10.2fk/s | %8.2f us | %8.2f us " +
                    "| %8.2f us | %s |",
                id,
                name,
                waf.rules().size(),
                iterations / wall / 1000.0,
                percentile(samples, 0.50),
                percentile(samples, 0.95),
                percentile(samples, 0.99),
                decision == WafDecision.BLOCK ? "Block" : "Allow"
            )
        );
    }

    public static void main(String[] args) {
        int iterations = args.length > 0 ? Integer.parseInt(args[0]) : 20000;
        String large =
            "{\"note\":\"pad\",\"data\":\"" + "A".repeat(8192 - 40) + "\"}";
        Request clean = new Request("/api/items?page=1", "10.0.0.1", "");

        System.out.println(
            "iterations: " +
                iterations +
                " (+10000 warmup); preset-dos-rate-limit disabled on A1-A6\n"
        );
        System.out.println(
            "| ID | Case | Rules | ops/s | p50 | p95 | p99 | Decision |\n" +
                "|---|---|---:|---:|---:|---:|---:|---|"
        );

        run(
            "A0",
            "0 rules (baseline protect)",
            MiniWaf.createMiniWaf(new WafConfig()),
            new Request("/", "10.0.0.9", ""),
            iterations
        );
        MiniWafInstance balanced = MiniWaf.createMiniWaf(
            config(ProtectionLevel.BALANCED)
        );
        run("A1", "balanced, clean allow", balanced, clean, iterations);
        run(
            "A2",
            "A1 + decision cache (same fingerprint)",
            MiniWaf.createMiniWaf(
                config(ProtectionLevel.BALANCED).decisionCache(
                    new DecisionCacheConfig()
                )
            ),
            clean,
            iterations
        );
        run(
            "A3",
            "A1 + 8KB JSON body",
            balanced,
            new Request("/echo", "10.0.0.3", large),
            iterations
        );
        run(
            "A4",
            "A1 + small (~24B) body",
            balanced,
            new Request("/echo", "10.0.0.3", "{\"ok\":true,\"q\":\"hello\"}"),
            iterations
        );
        run(
            "A5",
            "A1 SQLi - block path",
            balanced,
            new Request("/search?q=1'%20OR%201=1%20--", "10.0.0.2", ""),
            iterations
        );
        for (ProtectionLevel level : ProtectionLevel.values()) {
            String name = level.name().toLowerCase(Locale.ROOT);
            run(
                "A6-" + name,
                name + ", clean allow",
                MiniWaf.createMiniWaf(config(level)),
                clean,
                iterations
            );
        }
    }
}
