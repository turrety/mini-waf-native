mod common;

use std::sync::{
    Arc,
    Mutex,
};

use common::MockRequest;
use mini_waf::{
    DecisionCacheConfig,
    EvaluateOptions,
    FieldCondition,
    FieldResolveOptions,
    MatchPattern,
    ProtectionLevel,
    RateLimitSpec,
    RateLimitStore,
    ScanOptions,
    WafAction,
    WafCondition,
    WafConfig,
    WafDecision,
    WafEngineOptions,
    WafEvaluationResult,
    WafField,
    WafHttpContext,
    WafLogLevel,
    WafLogger,
    WafLoggingOptions,
    WafPresetName,
    WafRule,
    build_rule_list,
    create_mini_waf,
    create_waf_engine,
    evaluate_condition,
    filter_rules_by_disabled_ids,
    filter_rules_by_enabled_ids,
    filter_rules_by_level,
    matches_pattern,
    resolve_field_joined,
    resolve_field_values,
    resolve_field_values_lower,
    scan_rules,
};

fn block_sql() -> WafRule {
    WafRule::new(
        "block-sqli",
        FieldCondition::new(WafField::query("id")).matches(
            MatchPattern::regex_with_flags(r"('|OR\s+1=1)", "i").unwrap(),
        ),
        WafAction::Block,
    )
    .reason("Possible SQL injection")
}

fn allow_local() -> WafRule {
    WafRule::new(
        "allow-local",
        FieldCondition::new(WafField::Ip).equals("127.0.0.1"),
        WafAction::Allow,
    )
    .priority(1)
}

fn log_ua() -> WafRule {
    WafRule::new(
        "log-ua",
        FieldCondition::new(WafField::header("user-agent")).includes("curl"),
        WafAction::Log,
    )
    .priority(10)
}

fn rate_limited(max: u64) -> WafRule {
    WafRule::new(
        "rate-limit",
        FieldCondition::new(WafField::Ip)
            .rate_limit(RateLimitSpec::new(max, 60_000)),
        WafAction::Block,
    )
    .reason("Too many requests")
}

fn path_rule(id: &str, path: &str) -> WafRule {
    WafRule::new(
        id,
        FieldCondition::new(WafField::Path).equals(path),
        WafAction::Block,
    )
}

fn matched_id<'a>(result: &'a WafEvaluationResult<'_>) -> Option<&'a str> {
    result.matched_rule.map(|rule| rule.id.as_str())
}

mod block_and_allow {
    use super::*;

    #[test]
    fn blocks_a_matching_malicious_query() {
        let waf =
            create_mini_waf(WafConfig::default().rules([block_sql()]), None);
        let mut req =
            MockRequest::new().ip("10.1.1.1").query("id", "1' OR 1=1");
        let result = waf.handle(&mut req);
        assert_eq!(result.decision, WafDecision::Block);
        assert_eq!(matched_id(&result), Some("block-sqli"));
        assert_eq!(result.reason.as_deref(), Some("Possible SQL injection"));
        assert_eq!(req.blocked, Some((403, "Forbidden".into())));
    }

    #[test]
    fn allows_when_nothing_matches() {
        let waf =
            create_mini_waf(WafConfig::default().rules([block_sql()]), None);
        let mut req = MockRequest::new().query("id", "42");
        let result = waf.handle(&mut req);
        assert_eq!(result.decision, WafDecision::Allow);
        assert!(result.matched_rule.is_none());
        assert!(!req.is_blocked());
    }

    #[test]
    fn short_circuits_on_a_higher_priority_allow() {
        let waf = create_mini_waf(
            WafConfig::default().rules([block_sql(), allow_local()]),
            None,
        );
        let mut req =
            MockRequest::new().ip("127.0.0.1").query("id", "1' OR 1=1");
        let result = waf.handle(&mut req);
        assert_eq!(result.decision, WafDecision::Allow);
        assert_eq!(matched_id(&result), Some("allow-local"));
        assert!(!req.is_blocked());
    }

    #[test]
    fn collects_log_rules_without_blocking() {
        let waf = create_mini_waf(WafConfig::default().rules([log_ua()]), None);
        let mut req = MockRequest::new().header("user-agent", "curl/8.0");
        let result = waf.handle(&mut req);
        assert_eq!(result.decision, WafDecision::Allow);
        assert_eq!(
            result
                .logged_rules
                .iter()
                .map(|rule| rule.id.as_str())
                .collect::<Vec<_>>(),
            ["log-ua"]
        );
    }

    #[test]
    fn uses_the_configured_block_response_and_fallback_reason() {
        let config = WafConfig::default()
            .rules([path_rule("no-admin", "/admin")])
            .block_status_code(451)
            .block_body("Nope");
        let waf = create_mini_waf(config, None);
        let mut req = MockRequest::new().path("/admin");
        let result = waf.handle(&mut req);
        assert_eq!(result.reason.as_deref(), Some("Blocked by rule no-admin"));
        assert_eq!(req.blocked, Some((451, "Nope".into())));
    }

    #[test]
    fn an_empty_all_never_matches() {
        let rule =
            WafRule::new("empty", WafCondition::all([]), WafAction::Block);
        let waf = create_mini_waf(WafConfig::default().rules([rule]), None);
        assert_eq!(
            waf.handle(&mut MockRequest::new()).decision,
            WafDecision::Allow
        );
    }

    #[test]
    fn not_inverts_a_condition() {
        let rule = WafRule::new(
            "only-get",
            WafCondition::not(
                FieldCondition::new(WafField::Method).equals("GET"),
            ),
            WafAction::Block,
        );
        let waf = create_mini_waf(WafConfig::default().rules([rule]), None);
        assert_eq!(
            waf.handle(&mut MockRequest::new()).decision,
            WafDecision::Allow
        );
        assert_eq!(
            waf.handle(&mut MockRequest::new().method("POST")).decision,
            WafDecision::Block
        );
    }

    #[test]
    fn config_is_a_plain_struct_with_optional_fields() {
        let config = WafConfig {
            rules: Some(vec![block_sql()]),
            block_status_code: Some(406),
            ..WafConfig::default()
        };
        let waf = create_waf_engine(config, None);
        assert_eq!(waf.config().level, ProtectionLevel::Balanced);
        let mut req = MockRequest::new().query("id", "1' OR 1=1");
        waf.handle(&mut req);
        assert_eq!(req.blocked, Some((406, "Forbidden".into())));
    }
}

mod rate_limits {
    use super::*;

    #[test]
    fn blocks_after_exceeding_max_and_sets_headers() {
        let waf = create_mini_waf(
            WafConfig::default().rules([rate_limited(2)]),
            None,
        );
        let decisions: Vec<WafDecision> = (0..3)
            .map(|_| {
                waf.handle(&mut MockRequest::new().ip("10.0.0.1")).decision
            })
            .collect();
        assert_eq!(
            decisions,
            [WafDecision::Allow, WafDecision::Allow, WafDecision::Block]
        );

        let mut req = MockRequest::new().ip("10.0.0.9");
        waf.handle(&mut req);
        let names: Vec<&str> = req
            .response_headers
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "X-RateLimit-Limit",
                "X-RateLimit-Remaining",
                "X-RateLimit-Reset"
            ]
        );
        assert_eq!(req.response_headers[1].1, "1");
    }

    #[test]
    fn unifies_mapped_ipv6_and_ipv4_buckets() {
        let waf = create_mini_waf(
            WafConfig::default().rules([rate_limited(2)]),
            None,
        );
        let first = waf
            .handle(&mut MockRequest::new().ip("::ffff:10.0.0.1"))
            .decision;
        let second =
            waf.handle(&mut MockRequest::new().ip("10.0.0.1")).decision;
        let third = waf.handle(&mut MockRequest::new().ip("10.0.0.1")).decision;
        assert_eq!(
            [first, second, third],
            [WafDecision::Allow, WafDecision::Allow, WafDecision::Block]
        );
    }

    #[test]
    fn unifies_equivalent_ipv6_forms_for_equals() {
        let rule = WafRule::new(
            "loopback-v6",
            FieldCondition::new(WafField::Ip).equals("::1"),
            WafAction::Block,
        );
        let waf = create_mini_waf(WafConfig::default().rules([rule]), None);
        assert_eq!(
            waf.handle(&mut MockRequest::new().ip("0:0:0:0:0:0:0:1"))
                .decision,
            WafDecision::Block
        );
    }

    #[test]
    fn engines_can_share_a_store() {
        let store = Arc::new(RateLimitStore::default());
        let options = WafEngineOptions {
            rate_limit_store: Some(Arc::clone(&store)),
            ..WafEngineOptions::default()
        };
        let a = create_mini_waf(
            WafConfig::default().rules([rate_limited(1)]),
            Some(options.clone()),
        );
        let b = create_mini_waf(
            WafConfig::default().rules([rate_limited(1)]),
            Some(options),
        );
        assert_eq!(
            a.handle(&mut MockRequest::new().ip("10.9.9.9")).decision,
            WafDecision::Allow
        );
        assert_eq!(
            b.handle(&mut MockRequest::new().ip("10.9.9.9")).decision,
            WafDecision::Block
        );
        assert_eq!(store.size(), 1);
    }

    #[test]
    fn rate_limited_rules_run_after_a_block_is_decided() {
        let path_block = path_rule("block-path", "/x").priority(1);
        let waf = create_mini_waf(
            WafConfig::default().rules([path_block, rate_limited(100)]),
            None,
        );
        waf.handle(&mut MockRequest::new().path("/x").ip("10.2.2.2"));
        assert_eq!(
            waf.rate_limit_store().size(),
            1,
            "the counter still advanced"
        );
    }

    #[test]
    fn is_thread_safe() {
        let waf = Arc::new(create_mini_waf(
            WafConfig::default().rules([rate_limited(50)]),
            None,
        ));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let waf = Arc::clone(&waf);
                std::thread::spawn(move || {
                    (0..25)
                        .filter(|_| {
                            waf.handle(&mut MockRequest::new().ip("10.3.3.3"))
                                .decision
                                == WafDecision::Block
                        })
                        .count()
                })
            })
            .collect();
        let blocked: usize = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .sum();
        assert_eq!(blocked, 200 - 50);
    }
}

mod requires_prefilter {
    use super::*;

    fn rule(requires: Option<&[&str]>) -> WafRule {
        let condition = FieldCondition::new(WafField::query("q"))
            .matches(MatchPattern::regex_with_flags("danger", "i").unwrap());
        let condition = match requires {
            Some(literals) => condition.requires(literals.iter().copied()),
            None => condition,
        };
        WafRule::new("prefiltered", condition, WafAction::Block)
    }

    fn decide(rule: WafRule, q: &str) -> WafDecision {
        create_mini_waf(WafConfig::default().rules([rule]), None)
            .handle(&mut MockRequest::new().query("q", q))
            .decision
    }

    #[test]
    fn blocks_when_a_literal_is_present() {
        assert_eq!(
            decide(rule(Some(&["danger"])), "very DANGERous"),
            WafDecision::Block
        );
    }

    #[test]
    fn matches_the_needle_case_insensitively() {
        assert_eq!(
            decide(rule(Some(&["DANGER"])), "danger zone"),
            WafDecision::Block
        );
    }

    #[test]
    fn any_literal_is_enough() {
        assert_eq!(
            decide(rule(Some(&["nope", "danger"])), "danger"),
            WafDecision::Block
        );
    }

    #[test]
    fn skips_the_pattern_without_a_literal() {
        assert_eq!(
            decide(rule(Some(&["absent-literal"])), "danger"),
            WafDecision::Allow
        );
    }

    #[test]
    fn is_a_no_op_when_omitted() {
        assert_eq!(decide(rule(None), "danger"), WafDecision::Block);
    }
}

mod rule_filters {
    use super::*;

    fn ids(rules: &[WafRule]) -> Vec<&str> {
        rules.iter().map(|rule| rule.id.as_str()).collect()
    }

    fn custom_block() -> WafRule {
        path_rule("custom-block-admin", "/admin")
    }

    fn sqli_low() -> WafConfig {
        WafConfig::default()
            .presets([WafPresetName::Sqli])
            .level(ProtectionLevel::Low)
    }

    #[test]
    fn disables_one_preset_rule() {
        let rules = build_rule_list(
            &sqli_low().disabled_rule_ids(["preset-sqli-classic-query"]),
        );
        assert!(!ids(&rules).contains(&"preset-sqli-classic-query"));
        assert!(ids(&rules).contains(&"preset-sqli-classic-body"));
    }

    #[test]
    fn allowlists_only_listed_ids() {
        let rules = build_rule_list(
            &sqli_low().enabled_rule_ids(["preset-sqli-classic-query"]),
        );
        assert_eq!(ids(&rules), ["preset-sqli-classic-query"]);
    }

    #[test]
    fn allowlist_then_disable() {
        let config = sqli_low()
            .rules([custom_block()])
            .enabled_rule_ids([
                "custom-block-admin",
                "preset-sqli-classic-query",
            ])
            .disabled_rule_ids(["preset-sqli-classic-query"]);
        assert_eq!(ids(&build_rule_list(&config)), ["custom-block-admin"]);
    }

    #[test]
    fn pure_helpers_filter() {
        let input = vec![custom_block(), path_rule("other", "/x")];
        let enabled = filter_rules_by_enabled_ids(
            input.clone(),
            Some(&["custom-block-admin".into()]),
        );
        let disabled = filter_rules_by_disabled_ids(
            input.clone(),
            Some(&["other".into()]),
        );
        assert_eq!(ids(&enabled), ["custom-block-admin"]);
        assert_eq!(ids(&disabled), ["custom-block-admin"]);
        assert_eq!(filter_rules_by_enabled_ids(input.clone(), None).len(), 2);
        assert_eq!(filter_rules_by_disabled_ids(input, Some(&[])).len(), 2);
    }

    #[test]
    fn disabled_preset_rules_no_longer_block() {
        let waf = create_mini_waf(
            sqli_low().disabled_rule_ids([
                "preset-sqli-classic-query",
                "preset-sqli-classic-body",
                "preset-sqli-classic-path",
                "preset-sqli-classic-cookies",
            ]),
            None,
        );
        let result =
            waf.handle(&mut MockRequest::new().query("id", "1 UNION SELECT 1"));
        assert_eq!(result.decision, WafDecision::Allow);
    }

    #[test]
    fn sorts_by_priority_and_drops_disabled_rules() {
        let config = WafConfig::default().rules([
            path_rule("late", "/a").priority(200),
            path_rule("off", "/b").enabled(false),
            path_rule("early", "/c").priority(-5),
        ]);
        assert_eq!(ids(&build_rule_list(&config)), ["early", "late"]);
    }

    #[test]
    fn filters_custom_rules_by_min_level() {
        let rules = vec![
            path_rule("always", "/a"),
            path_rule("only-high", "/b").min_level(ProtectionLevel::High),
        ];
        assert_eq!(
            ids(&filter_rules_by_level(rules.clone(), ProtectionLevel::Low)),
            ["always"]
        );
        assert_eq!(
            ids(&filter_rules_by_level(rules, ProtectionLevel::High)),
            ["always", "only-high"]
        );
    }
}

mod decision_cache {
    use super::*;

    #[test]
    fn replays_a_cached_block() {
        let config = WafConfig::default()
            .rules([block_sql()])
            .decision_cache(DecisionCacheConfig::default());
        let waf = create_mini_waf(config, None);
        for _ in 0..2 {
            let mut req =
                MockRequest::new().ip("10.4.4.4").query("id", "1' OR 1=1");
            let result = waf.handle(&mut req);
            assert_eq!(matched_id(&result), Some("block-sqli"));
            assert!(req.is_blocked());
        }
    }

    #[test]
    fn is_disabled_by_rate_limited_rules() {
        let config = WafConfig::default()
            .rules([rate_limited(1)])
            .decision_cache(DecisionCacheConfig::default());
        let waf = create_mini_waf(config, None);
        let first = waf.handle(&mut MockRequest::new().ip("10.5.5.5")).decision;
        let second =
            waf.handle(&mut MockRequest::new().ip("10.5.5.5")).decision;
        assert_eq!([first, second], [WafDecision::Allow, WafDecision::Block]);
    }
}

mod standalone_helpers {
    use super::*;

    #[test]
    fn evaluate_condition_reports_matches_and_rate_limits() {
        let store = RateLimitStore::default();
        let req = MockRequest::new().query("id", "1' OR 1=1");
        let sqli = block_sql().when;
        assert!(evaluate_condition(&req, &sqli, &store, None).matched);
        // Raw (never normalized) needles still match case-insensitively.
        let raw = FieldCondition::new(WafField::query("id"))
            .includes("OR 1=1")
            .into();
        assert!(evaluate_condition(&req, &raw, &store, None).matched);

        let limited: WafCondition = FieldCondition::new(WafField::Ip)
            .rate_limit(RateLimitSpec::new(1, 60_000))
            .into();
        let first = evaluate_condition(&req, &limited, &store, None);
        let second = evaluate_condition(
            &req,
            &limited,
            &store,
            Some(&EvaluateOptions::default()),
        );
        assert_eq!((first.matched, second.matched), (false, true));
        assert_eq!(second.rate_limit_info.map(|info| info.remaining), Some(0));
    }

    #[test]
    fn scan_rules_returns_the_scan_state() {
        let store = RateLimitStore::default();
        let rules = build_rule_list(&WafConfig::default().rules([
            log_ua(),
            block_sql(),
            path_rule("late-block", "/"),
        ]));
        let req = MockRequest::new()
            .query("id", "1' OR 1=1")
            .header("user-agent", "curl/8");
        let state = scan_rules(&req, &rules, &store, None);
        assert_eq!(
            state.block_candidate.map(|rule| rule.id.as_str()),
            Some("block-sqli")
        );
        assert_eq!(
            state
                .logged_rules
                .iter()
                .map(|rule| rule.id.as_str())
                .collect::<Vec<_>>(),
            ["log-ua"]
        );
        assert!(state.allow_rule.is_none());
        assert!(!req.is_blocked(), "scanning has no side effects");
        let _ = ScanOptions::default();
    }

    #[test]
    fn field_resolvers() {
        let req = MockRequest::new()
            .query("a", "Hello")
            .query("b", "World")
            .header("host", "Example.com");
        let truncate = FieldResolveOptions {
            max_field_length: 3,
            decode: None,
        };
        assert_eq!(
            resolve_field_values(&req, &WafField::Query, None),
            ["Hello", "World"]
        );
        assert_eq!(
            resolve_field_values(&req, &WafField::Query, Some(&truncate)),
            ["Hel", "Wor"]
        );
        assert_eq!(
            resolve_field_values_lower(&req, &WafField::header("Host"), None),
            ["example.com"]
        );
        assert_eq!(
            resolve_field_joined(&req, &WafField::Query, None),
            "Hello|World"
        );
        assert_eq!(req.get_header("HOST").as_deref(), Some("Example.com"));
    }

    #[test]
    fn matches_every_pattern_kind() {
        assert!(matches_pattern("a", &MatchPattern::exact("a")));
        assert!(matches_pattern("b", &MatchPattern::one_of(["a", "b"])));
        assert!(matches_pattern("x1", &MatchPattern::regex(r"\d").unwrap()));
        assert!(matches_pattern(
            "ok",
            &MatchPattern::predicate(|value| value == "ok")
        ));
    }
}

#[derive(Default)]
struct Tracking {
    blocked: Mutex<Vec<String>>,
    audit: Mutex<Vec<String>>,
    connection: Mutex<usize>,
}

impl WafLogger for Tracking {
    fn blocked(&self, _ctx: &dyn WafHttpContext, rule: &WafRule) {
        self.blocked.lock().unwrap().push(rule.id.clone());
    }
    fn audit(&self, _ctx: &dyn WafHttpContext, rule: &WafRule) {
        self.audit.lock().unwrap().push(rule.id.clone());
    }
    fn connection(&self, _ctx: &dyn WafHttpContext) {
        *self.connection.lock().unwrap() += 1;
    }
}

mod logging {
    use super::*;

    fn run(config: WafConfig, logger: &Arc<Tracking>, req: MockRequest) {
        let options = WafEngineOptions {
            logger: Some(logger.clone() as Arc<dyn WafLogger>),
            ..WafEngineOptions::default()
        };
        create_mini_waf(config, Some(options)).handle(&mut req.clone());
    }

    fn with_sink(
        level: WafLogLevel,
        logger: &Arc<Tracking>,
    ) -> WafLoggingOptions {
        WafLoggingOptions {
            level: Some(level),
            sink: Some(logger.clone()),
        }
    }

    #[test]
    fn is_off_by_default() {
        let logger = Arc::new(Tracking::default());
        run(
            WafConfig::default().rules([block_sql()]),
            &logger,
            MockRequest::new().query("id", "1' OR 1=1"),
        );
        assert!(logger.blocked.lock().unwrap().is_empty());
        assert_eq!(*logger.connection.lock().unwrap(), 0);
    }

    #[test]
    fn logs_blocks_when_enabled() {
        let logger = Arc::new(Tracking::default());
        let config = WafConfig::default().rules([block_sql()]).logging(true);
        let waf = create_mini_waf(config.clone(), None);
        assert!(waf.config().logging.enabled);
        assert_eq!(waf.config().logging.level, WafLogLevel::Info);
        run(config, &logger, MockRequest::new().query("id", "1' OR 1=1"));
        assert_eq!(*logger.blocked.lock().unwrap(), ["block-sqli"]);
    }

    #[test]
    fn audits_at_info_through_a_custom_sink() {
        let logger = Arc::new(Tracking::default());
        create_mini_waf(
            WafConfig::default()
                .rules([log_ua()])
                .logging(with_sink(WafLogLevel::Info, &logger)),
            None,
        )
        .handle(&mut MockRequest::new().header("user-agent", "curl/8"));
        assert_eq!(*logger.audit.lock().unwrap(), ["log-ua"]);
        assert_eq!(*logger.connection.lock().unwrap(), 0);
    }

    #[test]
    fn logs_connections_only_at_debug() {
        let logger = Arc::new(Tracking::default());
        create_mini_waf(
            WafConfig::default()
                .rules([block_sql()])
                .logging(with_sink(WafLogLevel::Debug, &logger)),
            None,
        )
        .handle(&mut MockRequest::new().query("id", "42"));
        assert_eq!(*logger.connection.lock().unwrap(), 1);
        assert!(logger.blocked.lock().unwrap().is_empty());
    }

    #[test]
    fn error_level_skips_audit() {
        let logger = Arc::new(Tracking::default());
        let config = WafConfig::default()
            .rules([log_ua(), block_sql()])
            .logging(with_sink(WafLogLevel::Error, &logger));
        create_mini_waf(config, None).handle(
            &mut MockRequest::new()
                .query("id", "1' OR 1=1")
                .header("user-agent", "curl"),
        );
        assert_eq!(logger.blocked.lock().unwrap().len(), 1);
        assert!(logger.audit.lock().unwrap().is_empty());
    }
}
