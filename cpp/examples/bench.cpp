// Engine micro-benchmarks through the C++ binding, mirroring the A0-A6
// cases of `examples/bench.rs`. Each request goes through a custom adapter,
// so the numbers include the callbacks.
//
//     cmake -S cpp -B target/cpp -DCMAKE_BUILD_TYPE=Release
//     cmake --build target/cpp
//     target/cpp/bench            # 20 000 iterations
//     target/cpp/bench 100000     # custom iteration count

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include "mini_waf.hpp"

using namespace mini_waf;

namespace {

struct Request {
    std::string url;
    std::string ip;
    std::string body;
};

struct Response {
    bool blocked = false;
};

using Clock = std::chrono::steady_clock;
using Adapter = CustomAdapter<Request, Response>;

WafConfig config(ProtectionLevel level) {
    return WafConfig()
        .presets({WafPresetName::Default})
        .level(level)
        .disabled_rule_ids({"preset-dos-rate-limit"});
}

double percentile(const std::vector<double>& sorted, double p) {
    auto index = static_cast<std::size_t>(sorted.size() * p);
    return sorted[std::min(index, sorted.size() - 1)];
}

double micros(Clock::duration elapsed) {
    return std::chrono::duration<double, std::micro>(elapsed).count();
}

void run(const std::string& id, const std::string& name,
         const MiniWafInstance& waf, const Adapter& adapter,
         const Request& request, std::size_t iterations) {
    for (int warmup = 0; warmup < 10000; warmup++) {
        Response response;
        waf.protect(adapter, request, response);
    }
    std::vector<double> samples;
    samples.reserve(iterations);
    WafDecision decision = WafDecision::Allow;
    auto started = Clock::now();
    for (std::size_t index = 0; index < iterations; index++) {
        Response response;
        auto begin = Clock::now();
        decision = waf.protect(adapter, request, response).decision;
        samples.push_back(micros(Clock::now() - begin));
    }
    double wall = micros(Clock::now() - started) / 1e6;
    std::sort(samples.begin(), samples.end());
    std::printf("| %-12s | %-38s | %5zu | %10.2fk/s | %8.2f us | %8.2f us "
                "| %8.2f us | %s |\n",
                id.c_str(), name.c_str(), waf.rules().size(),
                iterations / wall / 1000.0, percentile(samples, 0.50),
                percentile(samples, 0.95), percentile(samples, 0.99),
                decision == WafDecision::Block ? "Block" : "Allow");
}

}  // namespace

int main(int argc, char** argv) {
    std::size_t iterations = argc > 1 ? std::stoul(argv[1]) : 20000;

    auto adapter = create_adapter(
        CustomAdapterHandlers<Request, Response>("bench")
            .get_method([](const Request& req) {
                return std::string(req.body.empty() ? "GET" : "POST");
            })
            .get_url([](const Request& req) { return req.url; })
            .get_ip([](const Request& req) { return req.ip; })
            .get_headers([](const Request&) {
                return HeaderMap{
                    {"user-agent", "Mozilla/5.0 (compatible; BenchBot/1.0)"},
                    {"accept", "application/json"},
                    {"host", "localhost"},
                };
            })
            .get_raw_body([](const Request& req) {
                return req.body.empty() ? RawBody() : RawBody(req.body);
            })
            .set_response_header(
                [](Response&, std::string_view, std::string_view) {})
            .drop([](const Request&, Response& res, std::uint16_t,
                     std::string_view) { res.blocked = true; }));

    std::string large =
        R"({"note":"pad","data":")" + std::string(8192 - 40, 'A') + R"("})";
    Request clean{"/api/items?page=1", "10.0.0.1", ""};

    std::printf("iterations: %zu (+10000 warmup); "
                "preset-dos-rate-limit disabled on A1-A6\n\n",
                iterations);
    std::printf("| ID | Case | Rules | ops/s | p50 | p95 | p99 | Decision |\n"
                "|---|---|---:|---:|---:|---:|---:|---|\n");

    run("A0", "0 rules (baseline protect)", create_mini_waf(WafConfig()),
        adapter, Request{"/", "10.0.0.9", ""}, iterations);
    auto balanced = create_mini_waf(config(ProtectionLevel::Balanced));
    run("A1", "balanced, clean allow", balanced, adapter, clean, iterations);
    run("A2", "A1 + decision cache (same fingerprint)",
        create_mini_waf(config(ProtectionLevel::Balanced)
                            .decision_cache(DecisionCacheConfig{})),
        adapter, clean, iterations);
    run("A3", "A1 + 8KB JSON body", balanced, adapter,
        Request{"/echo", "10.0.0.3", large}, iterations);
    run("A4", "A1 + small (~24B) body", balanced, adapter,
        Request{"/echo", "10.0.0.3", R"({"ok":true,"q":"hello"})"}, iterations);
    run("A5", "A1 SQLi - block path", balanced, adapter,
        Request{"/search?q=1'%20OR%201=1%20--", "10.0.0.2", ""}, iterations);
    const std::pair<ProtectionLevel, const char*> levels[] = {
        {ProtectionLevel::Low, "low"},
        {ProtectionLevel::Balanced, "balanced"},
        {ProtectionLevel::High, "high"},
        {ProtectionLevel::Paranoid, "paranoid"},
    };
    for (const auto& [level, name] : levels) {
        run(std::string("A6-") + name, std::string(name) + ", clean allow",
            create_mini_waf(config(level)), adapter, clean, iterations);
    }
}
