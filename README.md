# mini-waf (Rust)

A minimalistic, framework-agnostic **Web Application Firewall engine** for Rust.

- **Declarative rules**: field conditions (`matches`, `equals`, `includes`, `rate_limit`) composed with `all`, `any_of` and `not`.
- **94 preset rules** derived from OWASP CRS categories (SQLi, NoSQLi, XSS, RCE, SSTI, SSRF, RFI/LFI, path traversal, protocol abuse, scanners), gated by four protection levels.
- **One universal adapter**: describe how to read your server's request and write its response once, then call `waf.protect(...)` per request. Works with axum, actix-web, hyper, Rocket, a hand-written server — anything.
- **Linear-time matching**: patterns run on the [`regex`](https://docs.rs/regex) crate, so no payload can push a rule into catastrophic backtracking.
- **Transport decoding**: Base64, percent-encoding, JSON `\u` escapes and `space2comment` SQL-comment obfuscation are unwrapped and scanned at `High`+, including inside the fields of a raw JSON, form or multipart body.
- **Shared, thread-safe state**: the engine is `Send + Sync`; rate-limit buckets and the optional decision cache are shared across threads.
- **One dependency** (`regex`). JSON, Base64, percent-decoding, cookies, IP normalization and the LRU are implemented in-crate.

This is a Rust rewrite of the TypeScript [mini-waf](https://github.com/MurylloEx/Mini-WAF) with **the same API**: the same functions, types, rule structure, rule ids, levels and decisions. See [Coming from TypeScript](#coming-from-typescript) for how names map, and [Differences from the TypeScript version](#differences-from-the-typescript-version).

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [The universal adapter](#the-universal-adapter)
- [Integrating a framework (axum)](#integrating-a-framework-axum)
- [Writing rules](#writing-rules)
- [Presets and protection levels](#presets-and-protection-levels)
- [Tuning](#tuning)
- [Rules as JSON](#rules-as-json)
- [Logging](#logging)
- [Behind a proxy](#behind-a-proxy)
- [Performance](#performance)
- [Differences from the TypeScript version](#differences-from-the-typescript-version)
- [Coming from TypeScript](#coming-from-typescript)
- [C, C++, Java and .NET](#c-c-java-and-net)
- [Development](#development)

## Installation

```toml
[dependencies]
mini-waf = { git = "https://github.com/turrety/mini-waf-native" }
```

Requires Rust 1.85+ (edition 2024).

## Quick start

```rust
use mini_waf::{
    CustomAdapterHandlers,
    FieldCondition,
    HeaderMap,
    ProtectionLevel,
    RateLimitSpec,
    WafAction,
    WafCondition,
    WafConfig,
    WafDecision,
    WafField,
    WafPresetName,
    WafRule,
    create_adapter,
    create_mini_waf,
};

// 1. Build the WAF once, at startup. Presets and rules are resolved,
//    level-filtered and sorted here — never per request.
let waf = create_mini_waf(
    WafConfig::default()
        .presets([WafPresetName::Default])
        .level(ProtectionLevel::Balanced)
        .rules([
            WafRule::new(
                "allow-health",
                FieldCondition::new(WafField::Path).equals("/health"),
                WafAction::Allow,
            )
            .priority(1),
            WafRule::new(
                "login-rate-limit",
                WafCondition::all([
                    FieldCondition::new(WafField::Path).equals("/login").into(),
                    FieldCondition::new(WafField::Ip)
                        .rate_limit(RateLimitSpec::new(5, 60_000))
                        .into(),
                ]),
                WafAction::Block,
            )
            .reason("Too many login attempts"),
        ]),
    None,
);

// 2. Describe your server's request / response types once.
struct Req {
    method: String,
    url: String,
    peer: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
#[derive(Default)]
struct Res {
    status: u16,
    body: String,
    headers: Vec<(String, String)>,
}

let adapter = create_adapter(
    CustomAdapterHandlers::<Req, Res>::new("my-server")
        .get_method(|r| r.method.clone())
        .get_url(|r| r.url.clone()) // path + query string, as received
        .get_ip(|r| r.peer.clone())
        .get_headers(|r| {
            r.headers
                .iter()
                .map(|(k, v)| (k.to_lowercase(), v.as_str().into()))
                .collect::<HeaderMap>()
        })
        .get_raw_body(|r| r.body.clone())
        .set_response_header(|res, name, value| {
            res.headers.push((name.into(), value.into()))
        })
        .drop(|_req, res, status, body| {
            res.status = status;
            res.body = body.into();
        }),
)
.expect("every required handler is set");

// 3. Evaluate every request.
let request = Req {
    method: "GET".into(),
    url: "/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users".into(),
    peer: "198.51.100.4".into(),
    headers: vec![("User-Agent".into(), "Mozilla/5.0".into())],
    body: Vec::new(),
};
let mut response = Res::default();
let result = waf.protect(&adapter, &request, &mut response);

assert_eq!(result.decision, WafDecision::Block);
assert_eq!(
    result.matched_rule.map(|rule| rule.id.as_str()),
    Some("preset-sqli-classic-query")
);
assert_eq!(response.status, 403);
```

`result` is a `WafEvaluationResult`: `decision`, `matched_rule`, `reason` and `logged_rules` (rules with action `Log` that matched). A dependency-free runnable server lives in [`examples/std_server.rs`](examples/std_server.rs):

```sh
cargo run --example std_server
curl -i "http://127.0.0.1:8080/search?q=1'%20UNION%20SELECT%201"   # 403
```

## The universal adapter

`create_adapter(CustomAdapterHandlers)` maps any request / response pair onto the engine's `WafHttpContext` and returns a `WafAdapter`. Build it once and reuse it; `waf.protect(&adapter, &request, &mut response)` creates a short-lived context per request.

| Handler | Required | Default | Notes |
|---|---|---|---|
| `get_method` | yes | | |
| `get_url` | yes | | Path **and** query string, as received (`/a?b=1`). |
| `get_ip` | yes | | Normalized for you (IPv4-mapped IPv6, brackets, zones). |
| `get_headers` | yes | | Lowercase the names. |
| `get_raw_body` | yes | | `String`, `Vec<u8>`, `&[u8]`, `JsonValue`, an `Option` of those, or `RawBody`. Buffer the body first. |
| `set_response_header` | yes | | Used for `X-RateLimit-*`. |
| `drop` | yes | | End the request with the block status and body. |
| `get_path` | no | `get_url` up to `?` | Must stay **percent-encoded**: traversal rules look for `%2e%2e%2f`. |
| `get_query` | no | parsed from the URL | Supply it when your framework already parses (nested) query strings. |
| `get_cookies` | no | parsed from the `cookie` header | |
| `get_header` | no | lookup in `get_headers` | |
| `get_files` | no | none | A `Vec<UploadedFile>` or a `FilesBag`; only names are inspected. |
| `get_protocol` | no | `"http"` | |
| `get_local_port` | no | `0` | |
| `remove_response_header` | no | no-op | |

`create_adapter` returns `Err(AdapterBuildError { missing })` listing every required handler you forgot. The URL, path and body are read once per request; every other value is read on first use and cached, so a rule set that never looks at cookies never parses them.

If you already own a request type, you can instead implement the `WafHttpContext` trait directly and call `waf.handle(&mut ctx)`, or implement `WafAdapter` yourself.

## Integrating a framework (axum)

There are no framework plugins: the adapter is the integration. This complete axum 0.8 middleware is compiled and exercised against the crate:

```rust,ignore
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::{
    Body,
    Bytes,
    to_bytes,
};
use axum::extract::{
    ConnectInfo,
    Request,
    State,
};
use axum::http::request::Parts;
use axum::http::{
    HeaderName,
    StatusCode,
};
use axum::middleware::{
    self,
    Next,
};
use axum::response::{
    IntoResponse,
    Response,
};
use axum::routing::get;
use mini_waf::{
    CustomAdapter,
    CustomAdapterHandlers,
    HeaderMap,
    HeaderValue,
    MiniWafInstance,
    WafConfig,
    WafDecision,
    WafPresetName,
    create_adapter,
    create_mini_waf,
};

/// Everything the WAF reads, captured before the request moves on.
struct Incoming {
    parts: Parts,
    body: Bytes,
    peer: SocketAddr,
}

/// What the WAF asks the response to do.
#[derive(Default)]
struct Verdict {
    status: Option<u16>,
    body: String,
    headers: Vec<(String, String)>,
}

fn axum_adapter() -> CustomAdapter<Incoming, Verdict> {
    create_adapter(
        CustomAdapterHandlers::new("axum")
            .get_method(|req: &Incoming| req.parts.method.to_string())
            .get_url(|req: &Incoming| req.parts.uri.to_string())
            .get_ip(|req: &Incoming| req.peer.ip().to_string())
            .get_headers(|req: &Incoming| {
                req.parts
                    .headers
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.as_str(),
                            HeaderValue::from(
                                String::from_utf8_lossy(value.as_bytes())
                                    .into_owned(),
                            ),
                        )
                    })
                    .collect::<HeaderMap>()
            })
            .get_raw_body(|req: &Incoming| req.body.to_vec())
            .set_response_header(|verdict: &mut Verdict, name, value| {
                verdict.headers.push((name.into(), value.into()))
            })
            .drop(|_req: &Incoming, verdict: &mut Verdict, status, body| {
                verdict.status = Some(status);
                verdict.body = body.into();
            }),
    )
    .expect("every required handler is set")
}

struct Guard {
    waf: MiniWafInstance,
    adapter: CustomAdapter<Incoming, Verdict>,
}

async fn firewall(
    State(guard): State<Arc<Guard>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let Ok(body) = to_bytes(body, 1024 * 1024).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let incoming = Incoming { parts, body, peer };
    let mut verdict = Verdict::default();
    let blocked = guard
        .waf
        .protect(&guard.adapter, &incoming, &mut verdict)
        .decision
        == WafDecision::Block;

    let mut response = if blocked {
        let status = verdict
            .status
            .and_then(|s| StatusCode::from_u16(s).ok())
            .unwrap_or(StatusCode::FORBIDDEN);
        (status, std::mem::take(&mut verdict.body)).into_response()
    } else {
        next.run(Request::from_parts(
            incoming.parts,
            Body::from(incoming.body),
        ))
        .await
    };
    for (name, value) in verdict.headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::try_from(name),
            axum::http::HeaderValue::try_from(value),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

#[tokio::main]
async fn main() {
    let guard = Arc::new(Guard {
        waf: create_mini_waf(
            WafConfig::default().presets([WafPresetName::Default]),
            None,
        ),
        adapter: axum_adapter(),
    });
    let app = Router::new()
        .route("/", get(|| async { "hello" }))
        .layer(middleware::from_fn_with_state(guard, firewall));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
```

The same shape works elsewhere: snapshot what the WAF needs into a struct (`Incoming`), let the adapter write into a small `Verdict`, then either answer with the verdict or forward the rebuilt request. `waf.protect` is synchronous and CPU-only, so it is safe to call from async code; on very large bodies with `max_field_length: Some(0)` consider `spawn_blocking`.

## Writing rules

A `WafRule` has the same shape as in TypeScript: `id`, `when` (a `WafCondition`), `action`, and the optional `reason`, `enabled`, `priority` and `min_level`. Build one with `WafRule::new` and the chainable setters, or as a struct literal.

```rust
use mini_waf::{
    FieldCondition,
    MatchPattern,
    ProtectionLevel,
    RateLimitSpec,
    WafAction,
    WafCondition,
    WafField,
    WafRule,
};

// Block SQL keywords in one query parameter, case-insensitively.
let sqli = WafRule::new(
    "block-union",
    FieldCondition::new(WafField::query("id"))
        .matches(
            MatchPattern::regex_with_flags(r"union\s+select", "i").unwrap(),
        )
        .requires(["union"]), // cheap literal gate, see below
    WafAction::Block,
)
.reason("Possible SQL injection")
.priority(10)
.min_level(ProtectionLevel::Low);

// Only admins' network may reach /admin.
let admin = WafRule::new(
    "admin-from-vpn-only",
    WafCondition::all([
        FieldCondition::new(WafField::Path)
            .matches(MatchPattern::regex("^/admin").unwrap())
            .into(),
        WafCondition::not(
            FieldCondition::new(WafField::Ip)
                .matches(MatchPattern::predicate(|ip| ip.starts_with("10."))),
        ),
    ]),
    WafAction::Block,
);

// Audit, without blocking, every request from curl — as a struct literal.
let audit = WafRule {
    id: "audit-curl".into(),
    when: FieldCondition::new(WafField::header("user-agent"))
        .includes("curl")
        .into(),
    action: WafAction::Log,
    reason: None,
    enabled: None,
    priority: None,
    min_level: None,
};

// 100 requests per minute per IP.
let flood = WafRule::new(
    "flood",
    FieldCondition::new(WafField::Ip)
        .rate_limit(RateLimitSpec::new(100, 60_000)),
    WafAction::Block,
);
# let _ = (sqli, admin, audit, flood);
```

**Fields**

| Field | JSON path | Values |
|---|---|---|
| `WafField::Ip` | `ip` | normalized client IP |
| `WafField::Method` | `method` | |
| `WafField::Path` | `path` | as received, still encoded |
| `WafField::Url` | `url` | path + query string |
| `WafField::Body` | `body` | raw body text |
| `WafField::Files` | `files` | every upload's name |
| `WafField::Query` | `query` | every parameter value (nested objects flattened to `key=value&…`) |
| `WafField::Headers` | `headers` | every header value |
| `WafField::Cookies` | `cookies` | every cookie value |
| `WafField::query("id")` | `query.id` | one parameter (`""` when absent) |
| `WafField::header("user-agent")` | `headers.user-agent` | one header, looked up lowercased (`""` when absent) |
| `WafField::cookie("sid")` | `cookies.sid` | one cookie (`""` when absent) |

A condition on a multi-value field matches when **any** value matches.

**Conditions.** `WafCondition` is `Field(FieldCondition)`, `All(AllCondition { all })`, `AnyOf(AnyOfCondition { any_of })` or `Not(NotCondition { not })`; `WafCondition::all`, `any_of` and `not` build them, and `is_field_condition` / `is_all_condition` / `is_any_of_condition` / `is_not_condition` test them. An empty `all` never matches.

**Matchers** (a `FieldCondition` may combine several; any one matching is enough)

- `matches(MatchPattern)` — `Exact(String)`, `OneOf(Vec<String>)`, `Regex` or `Predicate(MatchPredicate)`.
- `equals(s)` — case-sensitive equality.
- `includes(s)` — case-insensitive substring.
- `rate_limit(RateLimitSpec)` — sliding window per value of the field (`key_prefix` names the bucket). With a pattern too, the pattern gates the counter.
- `requires([...])` — a literal prefilter checked **before** the pattern: a value is only tested when it contains one of the literals (case-insensitive). It is what makes large bodies cheap, and a footgun: an incomplete list silently narrows the rule. Only list literals that **every** match must contain.

**Regex dialect.** `MatchPattern::regex(_with_flags)` (or `compile_regex`) compiles with the `regex` crate over the value's UTF-8 bytes with Unicode mode **off**, matching JavaScript's defaults: `\w`, `\d`, `\b` and case folding are ASCII, `.` stops at `\n` and `\r`, and `\s` also matches the Unicode spaces JavaScript's does (NBSP, `U+2000`–`U+200A`, `U+3000`, `U+FEFF`, …) — the value is matched with those mapped to ASCII, so `UNION\u{A0}SELECT` cannot slip past `union\s+select`. Flags: `i`, `m`, `s`, `u`/`v` (Unicode on); `g`, `y`, `d` are accepted and ignored. Look-around and backreferences are **not** supported — that is the price of linear-time matching; use a `Predicate` or two conditions instead.

**Actions and order.** Rules run by ascending `priority` (default 100; ties keep declaration order). A matching `Allow` stops evaluation immediately. The first matching `Block` decides the request, but later rules still run when they are `Log` or carry a rate limit, so counters keep advancing. `Log` matches are collected without stopping.

## Presets and protection levels

| Preset | Rules | Covers |
|---|---:|---|
| `Sqli` | 22 | UNION/boolean/tautology/blind SQLi, DBMS primitives, versioned comments, MongoDB operators and `$where` DoS, T-SQL `DECLARE` |
| `Xss` | 14 | script/handler injection, encoded tags, `data:` URIs, attribute vectors, JS primitives, sink breakouts, SSI |
| `Scanners` | 12 | scanner user agents, LDAP injection, null bytes, prototype pollution, hex floods, GraphQL introspection, DoS rate limit |
| `PathTraversal` | 5 | `../` in every encoding, OS files, UNC paths, `.git` / `.env` / secrets |
| `Rfi` | 7 | stream wrappers, remote script inclusion, PHP sinks, XXE, dangerous uploads |
| `Rce` | 19 | Unix/Windows command injection, LOLBins, reverse shells, JNDI, SSTI, FreeMarker, deserialization, SSRF |
| `Protocol` | 15 | response splitting, CRLF (encoded / double-encoded), smuggling, mail/IMAP injection, Host IP, session ids in URLs |
| `Default` | 94 | all of the above |

| Level | `Default` rules | Adds |
|---|---:|---|
| `Low` | 19 | high-signal, near-zero false positives |
| `Balanced` (default) | 51 | common XSS, uploads, protocol checks, DoS rate limit (120 req/min per IP) |
| `High` | 81 | aggressive heuristics and the transport decoders |
| `Paranoid` | 94 | rules with known false positives (broad user agents, generic tags, `eval(`) |

The enum is `WafPresetName`; each pack is also available as a list (`default_rules()`, `sqli_rules()`, `xss_rules()`, `scanner_rules()`, `path_traversal_rules()`, `rfi_rules()`, `rce_rules()`, `protocol_rules()`), and `resolve_presets` merges several without duplicates. `waf.rules()` lists the active rules in evaluation order. Rule ids are stable public API.

## Tuning

`WafConfig` has the TypeScript fields, all optional. Set them with the chainable setters of the same names, or with struct-update syntax (`WafConfig { level: Some(ProtectionLevel::High), ..WafConfig::default() }`).

```rust
use mini_waf::{
    DecisionCacheConfig,
    DecodeConfig,
    ProtectionLevel,
    WafConfig,
    WafPresetName,
};

let config = WafConfig::default()
    .presets([WafPresetName::Default])
    .level(ProtectionLevel::High)
    // Silence a false positive by id (applied after the level filter).
    .disabled_rule_ids(["preset-xss-js-primitives"])
    // Or keep only an allowlist of ids.
    // .enabled_rule_ids(["preset-sqli-classic-query"])
    .block_status_code(403)
    .block_body("Request blocked")
    // Characters scanned per value (default 8192; 0 = unlimited).
    .max_field_length(16_384)
    // Cap on distinct rate-limit keys, evicted LRU-style (default 10 000).
    .max_rate_limit_keys(50_000)
    // Force a decoder on/off regardless of level (default: on at High+).
    .decode(DecodeConfig {
        base64: Some(false),
        ..DecodeConfig::default()
    })
    // Cache decisions for identical requests (auto-disabled with rate limits).
    .decision_cache(DecisionCacheConfig {
        max: Some(1_024),
        ttl_ms: Some(1_000),
    });
# let _ = config;
```

To share rate-limit buckets between several engines, pass one store in the `WafEngineOptions`:

```rust
use std::sync::Arc;

use mini_waf::{
    RateLimitStore,
    WafConfig,
    WafEngineOptions,
    create_mini_waf,
};

let store = Arc::new(RateLimitStore::default());
let options = WafEngineOptions {
    rate_limit_store: Some(store.clone()),
    ..WafEngineOptions::default()
};
let public_api = create_mini_waf(WafConfig::default(), Some(options.clone()));
let admin_api = create_mini_waf(WafConfig::default(), Some(options));
# let _ = (public_api, admin_api);
```

## Rules as JSON

Keep custom rules in a file and load them at boot:

```json
{
  "rules": [
    {
      "id": "block-union",
      "action": "block",
      "reason": "Possible SQL injection",
      "minLevel": "low",
      "when": {
        "field": "query.id",
        "matches": { "pattern": "union\\s+select", "flags": "i" },
        "requires": ["union"]
      }
    },
    {
      "id": "allow-health",
      "action": "allow",
      "priority": 1,
      "when": { "anyOf": [
        { "field": "path", "equals": "/health" },
        { "field": "path", "equals": "/ready" }
      ] }
    },
    {
      "id": "login-flood",
      "action": "block",
      "when": { "all": [
        { "field": "path", "equals": "/login" },
        { "field": "ip", "rateLimit": { "max": 5, "windowMs": 60000 } }
      ] }
    }
  ]
}
```

```rust,ignore
let rules = mini_waf::parse_rules_from_json(include_str!("../rules.json"))?;
let waf = mini_waf::create_mini_waf(
    mini_waf::WafConfig::default().rules(rules),
    None,
);
```

`matches` is a string (exact), a string array (any of) or `{ "pattern", "flags"? }`. `load_rules` takes an already-parsed `JsonValue` instead. To produce such documents from code, build `JsonWafRule` / `JsonWafCondition` / `JsonFieldCondition` values and convert them with `JsonValue::from(...)`, then `.to_json_string()`. Malformed documents fail with a `RuleParseError` whose `path` points at the offending key, e.g. `rules[2].when.rateLimit.max: must be >= 1`.

## Logging

Logging is **off by default** (no formatting, no I/O).

```rust
use std::sync::Arc;

use mini_waf::{
    WafConfig,
    WafHttpContext,
    WafLogLevel,
    WafLogger,
    WafLoggingOptions,
    WafRule,
};

struct Tracing;
impl WafLogger for Tracing {
    fn blocked(&self, ctx: &dyn WafHttpContext, rule: &WafRule) {
        eprintln!("blocked {} {} ({})", ctx.get_ip(), ctx.get_path(), rule.id);
    }
    fn audit(&self, ctx: &dyn WafHttpContext, rule: &WafRule) {
        eprintln!("audit {} {}", ctx.get_ip(), rule.id);
    }
    fn connection(&self, _ctx: &dyn WafHttpContext) {}
}

let console = WafConfig::default().logging(true); // stdout, level Info
let custom = WafConfig::default().logging(WafLoggingOptions {
    level: Some(WafLogLevel::Error),
    sink: Some(Arc::new(Tracing)),
});
# let _ = (console, custom);
```

`Error` logs blocks, `Info` adds `Log`-rule audits, `Debug` adds every allowed request. `create_console_logger` and `silent_logger` return the built-in sinks, and `WafEngineOptions::logger` overrides the sink for one engine.

## Behind a proxy

The adapter's `get_ip` handler decides which address the rules and rate limits see. Behind a trusted reverse proxy, take the first `X-Forwarded-For` hop:

```rust
use mini_waf::pick_client_ip_from_xff;

assert_eq!(
    pick_client_ip_from_xff("  ::ffff:203.0.113.9 , 10.0.0.1"),
    "203.0.113.9"
);
```

Only do this when the proxy overwrites the header; otherwise clients can spoof it.

## Performance

Same machine and the same cases as the TypeScript benchmarks (AMD Ryzen 7 5700X3D, 20 000 iterations, `cargo run --release --example bench`):

| Case | Rules | Rust p50 | TypeScript p50 |
|---|---:|---:|---:|
| `Balanced`, clean request | 50 | **7.0 µs** | 13.7 µs |
| + 8 KB JSON body | 50 | **63 µs** | 131.7 µs |
| SQLi, block path | 50 | **5.1 µs** | 8.6 µs |
| `Low` / `High` / `Paranoid`, clean | 19 / 80 / 93 | **3.6 / 12.4 / 13.0 µs** | 6.9 / 28.1 / 31.0 µs |
| decision-cache hit | 50 | **0.69 µs** | 2.0 µs |

Rust figures are the median of four runs; run-to-run variance is up to ±10%. Details and methodology in [BENCHMARKS.md](BENCHMARKS.md).

## Coming from TypeScript

Every public name of the TypeScript package exists here — except the framework plugins and `scanRulesAsync` (see below) — spelled the Rust way:

- functions, methods, fields and handler names go from `camelCase` to `snake_case`: `createMiniWaf` → `create_mini_waf`, `ctx.getRawBody()` → `ctx.get_raw_body()`, `disabledRuleIds` → `disabled_rule_ids`, `rateLimit.windowMs` → `rate_limit.window_ms`;
- type names are unchanged: `WafConfig`, `WafRule`, `WafCondition`, `FieldCondition`, `AllCondition`, `WafHttpContext`, `WafAdapter`, `CustomAdapterHandlers`, `RateLimitStore`, `WafEvaluationResult`, …;
- string unions are enums: `'block'` → `WafAction::Block`, `'balanced'` → `ProtectionLevel::Balanced`, `'path-traversal'` → `WafPresetName::PathTraversal`, `'query.id'` → `WafField::query("id")`;
- optional properties and parameters are `Option`s (`WafConfig`, `WafRule::priority`, `createMiniWaf(config, options?)` → `create_mini_waf(config, None)`, `now = Date.now()` → `now: Option<i64>`);
- exported values become functions of the same name: `defaultRules` → `default_rules()`, `silentLogger` → `silent_logger()`;
- JSON keys stay camelCase (`"windowMs"`, `"anyOf"`, `"minLevel"`), so the same rules file loads in both.

```ts
// TypeScript
const waf = createMiniWaf({
  presets: ['default'],
  level: 'high',
  disabledRuleIds: ['preset-xss-js-primitives'],
});
const result = await waf.protect(adapter, req, res);
```

```rust,ignore
// Rust
let waf = create_mini_waf(
    WafConfig::default()
        .presets([WafPresetName::Default])
        .level(ProtectionLevel::High)
        .disabled_rule_ids(["preset-xss-js-primitives"]),
    None,
);
let result = waf.protect(&adapter, &req, &mut res);
```

## Differences from the TypeScript version

The engine is the same design — configuration resolved once, `build_rule_list`, needles pre-lowercased, a priority-ordered scan with the same allow / block / log / rate-limit semantics. The differences are the ones the language imposes:

- **No framework plugins.** `expressWaf`, `fastifyWaf`, `MiniWafModule` and the Express/Fastify/Nest adapters are not ported; `create_adapter` is the integration point. Its handlers `get_header`, `get_query` and `get_cookies` are optional here (derived from the URL and headers), since Rust servers rarely pre-parse them.
- **Synchronous.** `handle` / `protect` return the result directly instead of a `Promise`, and the body must be buffered before `protect` (no async `getRawBody`). There is no event loop to yield to, so `ruleYieldEvery` and `scanRulesAsync` do not exist. Adapters take no `next` argument.
- **Thread-safe.** The engine is `Send + Sync`; its rate-limit store and decision cache are shared behind mutexes.
- **Compiled rules.** Rules are compiled once so each field is resolved into a per-request slot (the TypeScript engine memoizes by field name). The standalone `evaluate_condition` and `scan_rules` compile on every call, and `FieldResolveOptions` has no memo maps.
- **Results borrow the rules.** `WafEvaluationResult` and `ScanState` hold `&WafRule` references into the engine.
- **Regex dialect.** Rust's `regex` has no look-around or backreferences. The two places that used look-ahead (the XXE `about:legacy-compat` exception and the versioned-comment guard of the SQL-comment decoder) are implemented in code with identical results, and JSON rules that use look-around fail at load with a `RuleParseError`. Bounded repetitions such as `[^>]{0,200}` count UTF-8 bytes rather than UTF-16 units, and `i` folds ASCII letters only (as JavaScript does for ASCII).
- **Priorities are integers** (`i64`); JSON priorities must be whole numbers.
- **One preset change:** `preset-rce-deserialization` gained a complete `requires` prefilter. Detection is unchanged; without it the combined case-insensitive pattern defeated the regex engine's literal optimizations and cost ~135 µs on a clean 8 KB body.

## C, C++, Java and .NET

[`bindings/`](bindings) exposes the crate to C, C++ (header-only), Java 22+
(FFM API) and .NET 8+ through one C ABI library, `libmini_waf`, built by
`cargo build --release -p mini-waf-ffi`. Every binding keeps the Rust names,
recased for the language (`create_mini_waf` is `MiniWaf.createMiniWaf` in
Java and `MiniWaf.CreateMiniWaf` in C#), so this README applies to all of
them. See [`bindings/README.md`](bindings/README.md) for building, the name
map and what is not exposed.

## Development

```sh
cargo test --workspace                      # unit, integration and doc tests
cargo clippy --workspace --all-targets -- -D warnings
cargo +nightly fmt --check                  # rustfmt.toml uses nightly-only options
cargo run --release --example bench         # engine benchmarks
cargo run --example std_server              # demo server on :8080
```

`tests/presets.rs` holds the attack corpus (asserting **which** rule id fires) and a benign corpus that must stay allowed at `High` / `Paranoid`. A new or changed preset that blocks any benign entry is a false positive — the failure mode that gets a WAF turned off.

## License

[MIT](LICENSE)
