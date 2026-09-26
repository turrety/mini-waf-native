//! Engine micro-benchmarks, mirroring the `A0`–`A6` cases of the TypeScript
//! implementation so the two can be compared on the same machine.
//!
//! ```sh
//! cargo run --release --example bench            # 20 000 iterations
//! cargo run --release --example bench -- 100000  # custom iteration count
//! ```

use std::hint::black_box;
use std::time::Instant;

use mini_waf::{
    CookieMap,
    DecisionCacheConfig,
    HeaderMap,
    HeaderValue,
    MiniWafInstance,
    ProtectionLevel,
    QueryMap,
    QueryValue,
    UploadedFile,
    WafConfig,
    WafHttpContext,
    WafPresetName,
    create_mini_waf,
};

/// A pre-built request, so only the engine is measured.
#[derive(Clone)]
struct BenchRequest {
    path: String,
    ip: String,
    headers: HeaderMap,
    query: QueryMap,
    cookies: CookieMap,
    body: String,
    blocked: bool,
}

impl BenchRequest {
    fn new(path: &str, ip: &str, query: &[(&str, &str)], body: &str) -> Self {
        let headers: HeaderMap = [
            (
                "user-agent",
                HeaderValue::from("Mozilla/5.0 (compatible; BenchBot/1.0)"),
            ),
            ("accept", HeaderValue::from("application/json")),
            ("host", HeaderValue::from("localhost")),
        ]
        .into();
        Self {
            path: path.into(),
            ip: ip.into(),
            headers,
            query: query
                .iter()
                .map(|(k, v)| (*k, QueryValue::from(*v)))
                .collect(),
            cookies: CookieMap::new(),
            body: body.into(),
            blocked: false,
        }
    }
}

impl WafHttpContext for BenchRequest {
    fn framework(&self) -> &str {
        "bench"
    }
    fn get_method(&self) -> &str {
        if self.body.is_empty() { "GET" } else { "POST" }
    }
    fn get_url(&self) -> &str {
        &self.path
    }
    fn get_path(&self) -> &str {
        &self.path
    }
    fn get_ip(&self) -> &str {
        &self.ip
    }
    fn get_protocol(&self) -> &str {
        "http"
    }
    fn get_local_port(&self) -> u16 {
        3000
    }
    fn get_header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(HeaderValue::first)
            .map(str::to_owned)
    }
    fn get_headers(&self) -> &HeaderMap {
        &self.headers
    }
    fn get_query(&self) -> &QueryMap {
        &self.query
    }
    fn get_cookies(&self) -> &CookieMap {
        &self.cookies
    }
    fn get_raw_body(&self) -> &str {
        &self.body
    }
    fn get_files(&self) -> &[UploadedFile] {
        &[]
    }
    fn set_response_header(&mut self, _name: &str, _value: &str) {}
    fn remove_response_header(&mut self, _name: &str) {}
    fn is_blocked(&self) -> bool {
        self.blocked
    }
    fn drop(&mut self, _status_code: Option<u16>, _body: Option<&str>) {
        self.blocked = true;
    }
}

fn config(level: ProtectionLevel) -> WafConfig {
    WafConfig::default()
        .presets([WafPresetName::Default])
        .level(level)
        .disabled_rule_ids(["preset-dos-rate-limit"])
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    sorted[((sorted.len() as f64 * p) as usize).min(sorted.len() - 1)]
}

fn run(
    id: &str,
    name: &str,
    waf: &MiniWafInstance,
    template: &BenchRequest,
    iterations: usize,
) {
    for _ in 0..1_000 {
        black_box(waf.handle(&mut template.clone()).decision);
    }
    let mut samples = Vec::with_capacity(iterations);
    let mut decision = None;
    let started = Instant::now();
    for _ in 0..iterations {
        let mut request = template.clone();
        let begin = Instant::now();
        decision = Some(black_box(waf.handle(&mut request).decision));
        samples.push(begin.elapsed().as_secs_f64() * 1e6);
    }
    let wall = started.elapsed().as_secs_f64();
    samples.sort_by(f64::total_cmp);
    println!(
        concat!(
            "| {id:<12} | {name:<38} | {:>5} | {:>10.2}k/s ",
            "| {:>8.2} µs | {:>8.2} µs | {:>8.2} µs | {:?} |",
        ),
        waf.rules().len(),
        iterations as f64 / wall / 1_000.0,
        percentile(&samples, 0.50),
        percentile(&samples, 0.95),
        percentile(&samples, 0.99),
        decision.expect("at least one iteration"),
        id = id,
        name = name,
    );
}

fn main() {
    let iterations: usize = std::env::args()
        .nth(1)
        .and_then(|arg| arg.parse().ok())
        .unwrap_or(20_000);
    let clean =
        BenchRequest::new("/api/items", "10.0.0.1", &[("page", "1")], "");
    let large_body =
        format!(r#"{{"note":"pad","data":"{}"}}"#, "A".repeat(8_192 - 40));

    println!(
        concat!(
            "iterations: {iterations} (+1000 warmup); ",
            "preset-dos-rate-limit disabled on A1–A6\n",
        ),
        iterations = iterations
    );
    println!(concat!(
        "| ID           | Case                                   ",
        "| Rules | ops/s        | p50         | p95         ",
        "| p99         | Decision |",
    ));
    println!(concat!(
        "|--------------|----------------------------------------",
        "|------:|-------------:|------------:|------------:",
        "|------------:|----------|",
    ));

    run(
        "A0",
        "0 rules (baseline handle)",
        &create_mini_waf(WafConfig::default(), None),
        &BenchRequest::new("/", "10.0.0.9", &[], ""),
        iterations,
    );
    let balanced = create_mini_waf(config(ProtectionLevel::Balanced), None);
    run("A1", "balanced, clean allow", &balanced, &clean, iterations);
    let cached = create_mini_waf(
        config(ProtectionLevel::Balanced)
            .decision_cache(DecisionCacheConfig::default()),
        None,
    );
    run(
        "A2",
        "A1 + decision cache (same fingerprint)",
        &cached,
        &clean,
        iterations,
    );
    run(
        "A3",
        "A1 + 8KB JSON body",
        &balanced,
        &BenchRequest::new("/echo", "10.0.0.3", &[], &large_body),
        iterations,
    );
    let small = BenchRequest::new(
        "/echo",
        "10.0.0.3",
        &[],
        r#"{"ok":true,"q":"hello"}"#,
    );
    run(
        "A4",
        "A1 + small (~24B) body",
        &balanced,
        &small,
        iterations,
    );
    let sqli =
        BenchRequest::new("/search", "10.0.0.2", &[("q", "1' OR 1=1 --")], "");
    run("A5", "A1 SQLi — block path", &balanced, &sqli, iterations);
    for level in [
        ProtectionLevel::Low,
        ProtectionLevel::Balanced,
        ProtectionLevel::High,
        ProtectionLevel::Paranoid,
    ] {
        run(
            &format!("A6-{level}"),
            &format!("{level}, clean allow"),
            &create_mini_waf(config(level), None),
            &clean,
            iterations,
        );
    }
}
