//! The universal adapter against a fake HTTP stack, plus JSON-loaded rules.

use std::collections::HashMap;

use mini_waf::{
    CustomAdapter,
    CustomAdapterHandlers,
    FieldCondition,
    HeaderMap,
    HeaderValue,
    ProtectionLevel,
    QueryMap,
    QueryValue,
    RateLimitSpec,
    UploadedFile,
    WafAction,
    WafAdapter,
    WafConfig,
    WafDecision,
    WafEvaluationResult,
    WafField,
    WafPresetName,
    WafRule,
    create_adapter,
    create_mini_waf,
    create_waf_engine,
    parse_rules_from_json,
    pick_client_ip_from_xff,
    run_with_adapter,
    scalar_to_string,
};

struct FakeRequest {
    method: &'static str,
    url: &'static str,
    peer: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    body: &'static [u8],
    uploads: Vec<&'static str>,
}

impl Default for FakeRequest {
    fn default() -> Self {
        Self {
            method: "GET",
            url: "/",
            peer: "203.0.113.10",
            headers: vec![("User-Agent", "Mozilla/5.0")],
            body: b"",
            uploads: Vec::new(),
        }
    }
}

#[derive(Default)]
struct FakeResponse {
    status: u16,
    body: String,
    headers: HashMap<String, String>,
}

fn adapter() -> CustomAdapter<FakeRequest, FakeResponse> {
    create_adapter(
        CustomAdapterHandlers::new("fake")
            .get_method(|req: &FakeRequest| req.method.to_owned())
            .get_url(|req: &FakeRequest| req.url.to_owned())
            .get_ip(|req: &FakeRequest| {
                req.headers
                    .iter()
                    .find(|(name, _)| {
                        name.eq_ignore_ascii_case("x-forwarded-for")
                    })
                    .map_or_else(
                        || req.peer.to_owned(),
                        |(_, value)| pick_client_ip_from_xff(value),
                    )
            })
            .get_headers(|req: &FakeRequest| {
                req.headers
                    .iter()
                    .map(|(name, value)| {
                        (name.to_lowercase(), HeaderValue::from(*value))
                    })
                    .collect::<HeaderMap>()
            })
            .get_raw_body(|req: &FakeRequest| req.body)
            .get_files(|req: &FakeRequest| {
                req.uploads
                    .iter()
                    .map(|name| UploadedFile::named(*name))
                    .collect::<Vec<_>>()
            })
            .set_response_header(|res: &mut FakeResponse, name, value| {
                res.headers.insert(name.to_owned(), value.to_owned());
            })
            .remove_response_header(|res: &mut FakeResponse, name| {
                res.headers.remove(name);
            })
            .drop(
                |_req: &FakeRequest, res: &mut FakeResponse, status, body| {
                    res.status = status;
                    res.body = body.to_owned();
                },
            ),
    )
    .expect("complete adapter")
}

fn matched_id<'a>(result: &'a WafEvaluationResult<'_>) -> Option<&'a str> {
    result.matched_rule.map(|rule| rule.id.as_str())
}

#[test]
fn maps_a_custom_stack_onto_the_engine() {
    let rule = WafRule::new(
        "block-path",
        FieldCondition::new(WafField::Path).includes("admin"),
        WafAction::Block,
    );
    let waf = create_mini_waf(WafConfig::default().rules([rule]), None);
    let request = FakeRequest {
        url: "/admin/users?x=1",
        ..FakeRequest::default()
    };
    let mut response = FakeResponse::default();
    let result = waf.protect(&adapter(), &request, &mut response);
    assert_eq!(result.decision, WafDecision::Block);
    assert_eq!(
        (response.status, response.body.as_str()),
        (403, "Forbidden")
    );
}

#[test]
fn derives_path_query_and_cookies_from_the_request() {
    let adapter = adapter();
    assert_eq!(adapter.name(), "fake");
    let request = FakeRequest {
        url: "/search?q=hello+world&tag=a&tag=b",
        headers: vec![
            ("Cookie", "sid=abc%20def; theme=dark"),
            ("User-Agent", "Mozilla/5.0"),
        ],
        ..FakeRequest::default()
    };
    let mut response = FakeResponse::default();
    let ctx = adapter.create_context(&request, &mut response);
    assert_eq!(ctx.framework(), "fake");
    assert_eq!(ctx.get_path(), "/search");
    assert_eq!(
        ctx.get_query().get("q"),
        Some(&QueryValue::from("hello world"))
    );
    assert_eq!(scalar_to_string(&ctx.get_query().get("tag")), "a,b");
    assert_eq!(
        ctx.get_cookies().get("sid").map(String::as_str),
        Some("abc def")
    );
    assert_eq!(ctx.get_header("user-agent").as_deref(), Some("Mozilla/5.0"));
    assert_eq!(ctx.get_protocol(), "http");
    assert_eq!(ctx.get_ip(), "203.0.113.10");
    assert!(!ctx.is_blocked());
}

#[test]
fn normalizes_forwarded_client_ips() {
    let adapter = adapter();
    let request = FakeRequest {
        headers: vec![
            ("X-Forwarded-For", "  ::ffff:203.0.113.9 , 10.0.0.1"),
            ("User-Agent", "Mozilla/5.0"),
        ],
        ..FakeRequest::default()
    };
    let mut response = FakeResponse::default();
    assert_eq!(
        adapter.create_context(&request, &mut response).get_ip(),
        "203.0.113.9"
    );
}

#[test]
fn inspects_bodies_query_strings_and_uploads_through_presets() {
    let config = WafConfig::default()
        .presets([WafPresetName::Default])
        .level(ProtectionLevel::Balanced);
    let waf = create_mini_waf(config, None);
    let adapter = adapter();
    let attacks = [
        FakeRequest {
            url: "/items?id=1%27%20UNION%20SELECT%201",
            ..FakeRequest::default()
        },
        FakeRequest {
            method: "POST",
            body: b"{\"bio\":\"<script>alert(1)</script>\"}",
            ..FakeRequest::default()
        },
        FakeRequest {
            method: "POST",
            uploads: vec!["shell.php"],
            ..FakeRequest::default()
        },
        FakeRequest {
            url: "/files/..%2f..%2fetc/passwd",
            ..FakeRequest::default()
        },
    ];
    for request in attacks {
        let mut response = FakeResponse::default();
        assert_eq!(
            waf.protect(&adapter, &request, &mut response).decision,
            WafDecision::Block,
            "{}",
            request.url
        );
        assert_eq!(response.status, 403);
    }
    let mut response = FakeResponse::default();
    let clean = FakeRequest {
        url: "/items?page=2&sort=name",
        ..FakeRequest::default()
    };
    assert_eq!(
        waf.protect(&adapter, &clean, &mut response).decision,
        WafDecision::Allow
    );
    assert_eq!(response.status, 0);
}

#[test]
fn writes_rate_limit_headers_through_the_adapter() {
    let rule = WafRule::new(
        "rate",
        FieldCondition::new(WafField::Ip)
            .rate_limit(RateLimitSpec::new(1, 60_000)),
        WafAction::Block,
    );
    let waf = create_mini_waf(WafConfig::default().rules([rule]), None);
    let adapter = adapter();
    let request = FakeRequest {
        peer: "198.51.100.77",
        ..FakeRequest::default()
    };
    let mut first = FakeResponse::default();
    let mut second = FakeResponse::default();
    assert_eq!(
        waf.protect(&adapter, &request, &mut first).decision,
        WafDecision::Allow
    );
    assert_eq!(
        waf.protect(&adapter, &request, &mut second).decision,
        WafDecision::Block
    );
    assert_eq!(
        first.headers.get("X-RateLimit-Limit").map(String::as_str),
        Some("1")
    );
    assert_eq!(
        second
            .headers
            .get("X-RateLimit-Remaining")
            .map(String::as_str),
        Some("0")
    );
}

#[test]
fn prefers_framework_parsed_query_maps() {
    let adapter = create_adapter(
        CustomAdapterHandlers::<FakeRequest, FakeResponse>::new("parsed-query")
            .get_method(|req| req.method.to_owned())
            .get_url(|req| req.url.to_owned())
            .get_ip(|req| req.peer.to_owned())
            .get_headers(|_| HeaderMap::new())
            .get_query(|_| {
                QueryMap::from([(
                    "user",
                    QueryValue::Object(
                        [("$ne", QueryValue::from("null"))].into(),
                    ),
                )])
            })
            .get_raw_body(|_| None::<String>)
            .set_response_header(|_, _, _| {})
            .drop(|_, res, status, _| res.status = status),
    )
    .unwrap();
    let waf = create_mini_waf(
        WafConfig::default().presets([WafPresetName::Sqli]),
        None,
    );
    let mut response = FakeResponse::default();
    let result = waf.protect(&adapter, &FakeRequest::default(), &mut response);
    assert_eq!(matched_id(&result), Some("preset-sqli-nosql-operator"));
}

#[test]
fn run_with_adapter_returns_the_result_and_the_context() {
    let rule = WafRule::new(
        "block-path",
        FieldCondition::new(WafField::Path).equals("/x"),
        WafAction::Block,
    );
    let engine = create_waf_engine(WafConfig::default().rules([rule]), None);
    let adapter = adapter();
    let request = FakeRequest {
        url: "/x",
        ..FakeRequest::default()
    };
    let mut response = FakeResponse::default();
    let run = run_with_adapter(&engine, &adapter, &request, &mut response);
    assert_eq!(run.result.decision, WafDecision::Block);
    assert!(run.ctx.is_blocked());
    drop(run);
    assert_eq!(response.status, 403);
}

#[test]
fn runs_rules_loaded_from_json() {
    let rules = parse_rules_from_json(
        r#"{ "rules": [
      {
        "id": "json-block-sqli",
        "action": "block",
        "reason": "Possible SQL injection",
        "when": {
          "field": "query.id",
          "matches": { "pattern": "union\\s+select", "flags": "i" }
        }
      },
      {
        "id": "json-allow-health",
        "action": "allow",
        "priority": 1,
        "when": { "field": "path", "equals": "/health" }
      }
    ] }"#,
    )
    .unwrap();
    let waf = create_mini_waf(WafConfig::default().rules(rules), None);
    let adapter = adapter();

    let mut response = FakeResponse::default();
    let attack = FakeRequest {
        url: "/items?id=1+UNION+SELECT+1",
        ..FakeRequest::default()
    };
    assert_eq!(
        matched_id(&waf.protect(&adapter, &attack, &mut response)),
        Some("json-block-sqli")
    );

    let mut response = FakeResponse::default();
    let health = FakeRequest {
        url: "/health?id=1+UNION+SELECT+1",
        ..FakeRequest::default()
    };
    let result = waf.protect(&adapter, &health, &mut response);
    assert_eq!(
        (result.decision, matched_id(&result)),
        (WafDecision::Allow, Some("json-allow-health"))
    );
}
