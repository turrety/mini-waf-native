//! The WAF engine: configuration resolved once, a priority-sorted rule list,
//! and the per-request scan.

use std::fmt;
use std::sync::{
    Arc,
    Mutex,
    PoisonError,
};

use crate::domain::context::{
    DEFAULT_BLOCK_BODY,
    DEFAULT_BLOCK_STATUS_CODE,
    WafHttpContext,
};
use crate::domain::levels::{
    DEFAULT_PROTECTION_LEVEL,
    DEFAULT_RULE_MIN_LEVEL,
    ProtectionLevel,
    is_level_active,
};
use crate::domain::rules::{
    WafAction,
    WafConfig,
    WafDecision,
    WafEvaluationResult,
    WafPresetName,
    WafRule,
};
use crate::engine::decode::DecodeSettings;
use crate::engine::evaluate::{
    CompiledRules,
    EvaluateOptions,
    Evaluator,
    RateLimitInfo,
};
use crate::engine::field_resolver::{
    FieldResolveOptions,
    FieldResolver,
};
use crate::engine::fingerprint::request_fingerprint;
use crate::engine::normalize_condition::normalize_rules;
use crate::engine::rate_limit::{
    DEFAULT_MAX_RATE_LIMIT_KEYS,
    RateLimitPort,
    RateLimitStore,
    RateLimitStoreOptions,
};
use crate::engine::rule_filter::{
    filter_rules_by_disabled_ids,
    filter_rules_by_enabled_ids,
};
use crate::logging::logger::{
    ConsoleLoggerOptions,
    create_console_logger,
};
use crate::logging::port::{
    ResolvedLogging,
    WafLogLevel,
    WafLogger,
    is_log_level_active,
    pick_logger_sink,
    resolve_logging,
    silent_logger,
};
use crate::presets::resolve_presets;
use crate::utils::lru::LruCache;
use crate::utils::time::now_ms;

/// Production-safe default: truncate each scanned field before matchers run.
/// `0` still means unlimited when set explicitly.
pub const DEFAULT_MAX_FIELD_LENGTH: usize = 8_192;
const DEFAULT_RULE_PRIORITY: i64 = 100;
const DEFAULT_DECISION_CACHE_MAX: usize = 256;
const DEFAULT_DECISION_CACHE_TTL_MS: u64 = 1_000;
/// Body characters hashed into a decision-cache fingerprint.
const FINGERPRINT_BODY_MAX: usize = 4_096;

/// Engine-level injectables.
#[derive(Default, Clone)]
pub struct WafEngineOptions {
    /// Inject a shared rate-limit store (tests / multi-instance).
    pub rate_limit_store: Option<Arc<RateLimitStore>>,
    /// Override the logging sink when logging is enabled. Ignored while
    /// `config.logging` is off (the default).
    pub logger: Option<Arc<dyn WafLogger>>,
}

impl fmt::Debug for WafEngineOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WafEngineOptions")
            .field(
                "rate_limit_store",
                &self.rate_limit_store.as_ref().map(|_| "RateLimitStore"),
            )
            .field("logger", &self.logger.as_ref().map(|_| "WafLogger"))
            .finish()
    }
}

/// Decision-cache settings after defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedDecisionCache {
    pub max: usize,
    pub ttl_ms: u64,
}

/// Performance knobs after defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedPerformance {
    pub max_field_length: usize,
    pub max_rate_limit_keys: usize,
    pub decision_cache: Option<ResolvedDecisionCache>,
    pub decode: DecodeSettings,
}

/// The configuration after defaults, as the engine uses it.
#[derive(Debug, Clone)]
pub struct ResolvedWafConfig {
    pub level: ProtectionLevel,
    /// The active rules, in evaluation order.
    pub rules: Vec<WafRule>,
    pub presets: Vec<WafPresetName>,
    pub block_status_code: u16,
    pub block_body: String,
    pub logging: ResolvedLogging,
    pub performance: ResolvedPerformance,
}

/// Keep rules whose `min_level` is satisfied by the configured protection
/// level.
pub fn filter_rules_by_level(
    rules: Vec<WafRule>,
    level: ProtectionLevel,
) -> Vec<WafRule> {
    rules
        .into_iter()
        .filter(|rule| {
            is_level_active(
                level,
                rule.min_level.unwrap_or(DEFAULT_RULE_MIN_LEVEL),
            )
        })
        .collect()
}

/// Drop `enabled: Some(false)` rules and stable-sort the rest by priority.
fn sort_by_priority(rules: Vec<WafRule>) -> Vec<WafRule> {
    let mut active: Vec<WafRule> = rules
        .into_iter()
        .filter(|rule| rule.enabled != Some(false))
        .collect();
    active.sort_by_key(|rule| rule.priority.unwrap_or(DEFAULT_RULE_PRIORITY));
    active
}

fn build_rules(config: &WafConfig, custom: Vec<WafRule>) -> Vec<WafRule> {
    let level = config.level.unwrap_or(DEFAULT_PROTECTION_LEVEL);
    let presets =
        resolve_presets(config.presets.as_deref().unwrap_or_default());
    let merged = presets.into_iter().chain(custom).collect();

    let leveled = filter_rules_by_level(merged, level);
    let allowed = filter_rules_by_enabled_ids(
        leveled,
        config.enabled_rule_ids.as_deref(),
    );
    let kept = filter_rules_by_disabled_ids(
        allowed,
        config.disabled_rule_ids.as_deref(),
    );
    normalize_rules(sort_by_priority(kept))
}

/// Build the final rule list. Order:
/// 1. resolve presets + custom rules
/// 2. filter by protection level (`min_level`)
/// 3. apply the `enabled_rule_ids` allowlist (if set and non-empty)
/// 4. apply `disabled_rule_ids`
/// 5. drop `enabled: Some(false)` and stable-sort by priority
/// 6. pre-lowercase `includes` / `requires` needles
pub fn build_rule_list(config: &WafConfig) -> Vec<WafRule> {
    build_rules(config, config.rules.clone().unwrap_or_default())
}

/// Transport decoders default off at `Low` / `Balanced` and on at `High`+.
fn resolve_decode(
    config: &WafConfig,
    level: ProtectionLevel,
) -> DecodeSettings {
    let auto = level >= ProtectionLevel::High;
    let decode = config.decode.unwrap_or_default();
    DecodeSettings {
        base64: decode.base64.unwrap_or(auto),
        url: decode.url.unwrap_or(auto),
        comments: decode.comments.unwrap_or(auto),
    }
}

fn resolve_performance(
    config: &WafConfig,
    level: ProtectionLevel,
) -> ResolvedPerformance {
    let decision_cache =
        config
            .decision_cache
            .as_ref()
            .map(|cache| ResolvedDecisionCache {
                max: cache.max.unwrap_or(DEFAULT_DECISION_CACHE_MAX),
                ttl_ms: cache.ttl_ms.unwrap_or(DEFAULT_DECISION_CACHE_TTL_MS),
            });
    ResolvedPerformance {
        max_field_length: config
            .max_field_length
            .unwrap_or(DEFAULT_MAX_FIELD_LENGTH),
        max_rate_limit_keys: config
            .max_rate_limit_keys
            .unwrap_or(DEFAULT_MAX_RATE_LIMIT_KEYS),
        decision_cache,
        decode: resolve_decode(config, level),
    }
}

fn resolve_config(
    config: &WafConfig,
    rules: Vec<WafRule>,
) -> ResolvedWafConfig {
    let level = config.level.unwrap_or(DEFAULT_PROTECTION_LEVEL);
    ResolvedWafConfig {
        level,
        rules,
        presets: config.presets.clone().unwrap_or_default(),
        block_status_code: config
            .block_status_code
            .unwrap_or(DEFAULT_BLOCK_STATUS_CODE),
        block_body: config
            .block_body
            .clone()
            .unwrap_or_else(|| DEFAULT_BLOCK_BODY.to_owned()),
        logging: resolve_logging(config.logging.as_ref()),
        performance: resolve_performance(config, level),
    }
}

fn resolve_engine_logger(
    config: &WafConfig,
    logging: ResolvedLogging,
    options_logger: Option<Arc<dyn WafLogger>>,
) -> Arc<dyn WafLogger> {
    if !logging.enabled {
        return silent_logger();
    }
    let console = create_console_logger(ConsoleLoggerOptions::default());
    pick_logger_sink(config.logging.as_ref(), options_logger, console)
}

/// Outcome of scanning a rule list, before any side effect.
#[derive(Debug, Clone, Default)]
pub struct ScanState<'a> {
    pub logged_rules: Vec<&'a WafRule>,
    pub block_candidate: Option<&'a WafRule>,
    pub allow_rule: Option<&'a WafRule>,
    pub last_rate_limit_info: Option<RateLimitInfo>,
}

/// Options of [`scan_rules`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanOptions {
    pub evaluate: EvaluateOptions,
}

impl Default for ScanOptions {
    fn default() -> Self {
        let fields = FieldResolveOptions {
            max_field_length: DEFAULT_MAX_FIELD_LENGTH,
            decode: None,
        };
        Self {
            evaluate: EvaluateOptions { fields },
        }
    }
}

/// [`ScanState`] as rule indices, so the decision cache can store it.
#[derive(Default)]
struct IndexScan {
    logged: Vec<usize>,
    block_candidate: Option<usize>,
    allow_rule: Option<usize>,
    last_rate_limit_info: Option<RateLimitInfo>,
}

impl IndexScan {
    /// Whether rule `index` can be skipped: a block already won, and this
    /// block has no rate-limit counter that must still advance.
    fn skips(
        &self,
        index: usize,
        action: WafAction,
        compiled: &CompiledRules,
    ) -> bool {
        self.block_candidate.is_some()
            && action == WafAction::Block
            && !compiled.rate_limited[index]
    }

    /// Record a matched rule. Returns `true` when the scan must stop.
    fn record_match(&mut self, index: usize, action: WafAction) -> bool {
        match action {
            WafAction::Allow => self.allow_rule = Some(index),
            WafAction::Log => self.logged.push(index),
            WafAction::Block => {
                self.block_candidate.get_or_insert(index);
            }
        }
        action == WafAction::Allow
    }

    fn into_state(self, rules: &[WafRule]) -> ScanState<'_> {
        ScanState {
            logged_rules: self
                .logged
                .iter()
                .map(|&index| &rules[index])
                .collect(),
            block_candidate: self.block_candidate.map(|index| &rules[index]),
            allow_rule: self.allow_rule.map(|index| &rules[index]),
            last_rate_limit_info: self.last_rate_limit_info,
        }
    }
}

/// Walk the rules in priority order. An `allow` match stops the scan; the
/// first `block` match wins, but later rules still run when they are `allow`
/// / `log` or carry a rate-limit side effect.
fn scan_compiled(
    ctx: &dyn WafHttpContext,
    rules: &[WafRule],
    compiled: &CompiledRules,
    rate_limits: &dyn RateLimitPort,
    options: FieldResolveOptions,
) -> IndexScan {
    let fields = FieldResolver::new(ctx, &compiled.fields, options);
    let evaluator = Evaluator {
        fields: &fields,
        rate_limits,
        now: now_ms(),
    };
    let mut scan = IndexScan::default();

    for (index, (rule, program)) in
        rules.iter().zip(&compiled.programs).enumerate()
    {
        if scan.skips(index, rule.action, compiled) {
            continue;
        }
        let evaluation = evaluator.evaluate(program);
        if evaluation.rate_limit_info.is_some() {
            scan.last_rate_limit_info = evaluation.rate_limit_info;
        }
        if evaluation.matched && scan.record_match(index, rule.action) {
            break;
        }
    }
    scan
}

/// Rule scan with no side effects besides rate-limit hits (which go through
/// `rate_limits` immediately). The engine compiles its rules once; this
/// standalone form compiles `rules` on every call.
pub fn scan_rules<'a>(
    ctx: &dyn WafHttpContext,
    rules: &'a [WafRule],
    rate_limits: &dyn RateLimitPort,
    options: Option<&ScanOptions>,
) -> ScanState<'a> {
    let options = options.copied().unwrap_or_default();
    let compiled = CompiledRules::from_rules(rules);
    scan_compiled(ctx, rules, &compiled, rate_limits, options.evaluate.fields)
        .into_state(rules)
}

/// A decision replayed from the cache: rule indices instead of references.
#[derive(Clone)]
struct CachedDecision {
    decision: WafDecision,
    matched: Option<usize>,
    reason: Option<String>,
    logged: Vec<usize>,
}

/// Short-TTL LRU of decisions keyed by request fingerprint, shared across
/// threads.
struct DecisionCache(Mutex<LruCache<CachedDecision>>);

impl DecisionCache {
    fn new(settings: ResolvedDecisionCache) -> Self {
        Self(Mutex::new(LruCache::new(
            settings.max,
            Some(settings.ttl_ms),
        )))
    }

    fn get(&self, key: &str, now: i64) -> Option<CachedDecision> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key, Some(now))
            .cloned()
    }

    fn set(&self, key: &str, decision: CachedDecision, now: i64) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).set(
            key,
            decision,
            Some(now),
        );
    }
}

/// An immutable, priority-sorted rule list plus the shared state (rate-limit
/// buckets, optional decision cache) needed to evaluate requests.
///
/// It is `Send + Sync`: build it once at startup and share it across every
/// request handler.
pub struct WafEngine {
    compiled: CompiledRules,
    config: ResolvedWafConfig,
    rate_limit_store: Arc<RateLimitStore>,
    logger: Arc<dyn WafLogger>,
    decision_cache: Option<DecisionCache>,
}

impl fmt::Debug for WafEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rule_ids: Vec<&str> = self
            .config
            .rules
            .iter()
            .map(|rule| rule.id.as_str())
            .collect();
        f.debug_struct("WafEngine")
            .field("rules", &rule_ids)
            .field("level", &self.config.level)
            .finish_non_exhaustive()
    }
}

/// Build the engine. Presets and rules are resolved, level-filtered, sorted
/// and compiled **once**, here — never per request.
pub fn create_waf_engine(
    mut config: WafConfig,
    options: Option<WafEngineOptions>,
) -> WafEngine {
    let options = options.unwrap_or_default();
    let custom = config.rules.take().unwrap_or_default();
    let resolved = resolve_config(&config, build_rules(&config, custom));
    let compiled = CompiledRules::from_rules(&resolved.rules);

    let rate_limit_store = options.rate_limit_store.unwrap_or_else(|| {
        let max_keys = Some(resolved.performance.max_rate_limit_keys);
        let store_options = RateLimitStoreOptions {
            max_keys,
            ..RateLimitStoreOptions::default()
        };
        Arc::new(RateLimitStore::new(None, store_options))
    });
    let logger =
        resolve_engine_logger(&config, resolved.logging, options.logger);
    // Caching a decision would freeze rate-limit counters, so any rate-limited
    // rule disables the cache.
    let decision_cache = resolved
        .performance
        .decision_cache
        .filter(|_| !compiled.rate_limited.contains(&true))
        .map(DecisionCache::new);

    WafEngine {
        compiled,
        config: resolved,
        rate_limit_store,
        logger,
        decision_cache,
    }
}

impl WafEngine {
    /// The active rules, in evaluation order.
    pub fn rules(&self) -> &[WafRule] {
        &self.config.rules
    }

    pub fn config(&self) -> &ResolvedWafConfig {
        &self.config
    }

    pub fn rate_limit_store(&self) -> &Arc<RateLimitStore> {
        &self.rate_limit_store
    }

    /// Evaluate a request. On block, calls
    /// [`WafHttpContext::drop`] with the configured status and body;
    /// rate-limited rules also set `X-RateLimit-*` response headers.
    pub fn handle(
        &self,
        ctx: &mut dyn WafHttpContext,
    ) -> WafEvaluationResult<'_> {
        let Some(cache) = &self.decision_cache else {
            let scan = self.scan(ctx);
            return self.finish(scan, ctx);
        };

        let key = request_fingerprint(ctx, FINGERPRINT_BODY_MAX);
        let now = now_ms();
        if let Some(cached) = cache.get(&key, now) {
            return self.replay(cached, ctx);
        }

        let scan = self.scan(ctx);
        let matched = scan.allow_rule.or(scan.block_candidate);
        let logged = scan.logged.clone();
        let result = self.finish(scan, ctx);
        let reason = result.reason.clone();
        cache.set(
            &key,
            CachedDecision {
                decision: result.decision,
                matched,
                reason,
                logged,
            },
            now,
        );
        result
    }

    fn scan(&self, ctx: &dyn WafHttpContext) -> IndexScan {
        let performance = &self.config.performance;
        let options = FieldResolveOptions {
            max_field_length: performance.max_field_length,
            decode: Some(performance.decode),
        };
        let rate_limits = self.rate_limit_store.as_ref();
        scan_compiled(
            ctx,
            &self.config.rules,
            &self.compiled,
            rate_limits,
            options,
        )
    }

    /// Apply side effects (headers, drop, logs) and build the result.
    fn finish(
        &self,
        scan: IndexScan,
        ctx: &mut dyn WafHttpContext,
    ) -> WafEvaluationResult<'_> {
        if let Some(info) = scan.last_rate_limit_info {
            write_rate_limit_headers(ctx, info);
        }
        let logged = self.rules_at(&scan.logged);

        if let Some(index) = scan.allow_rule {
            let rule = &self.config.rules[index];
            return self.allow(ctx, Some(rule), rule.reason.clone(), logged);
        }

        self.emit(WafLogLevel::Info, |logger| {
            logged.iter().for_each(|rule| logger.audit(ctx, rule))
        });

        match scan.block_candidate {
            Some(index) => {
                let rule = &self.config.rules[index];
                let reason = rule
                    .reason
                    .clone()
                    .unwrap_or_else(|| format!("Blocked by rule {}", rule.id));
                self.block(ctx, rule, Some(reason), logged)
            }
            None => self.allow(ctx, None, None, logged),
        }
    }

    /// Replay a cached decision: the same verdict and side effects, no scan.
    fn replay(
        &self,
        cached: CachedDecision,
        ctx: &mut dyn WafHttpContext,
    ) -> WafEvaluationResult<'_> {
        let matched = cached
            .matched
            .and_then(|index| self.config.rules.get(index));
        let logged = self.rules_at(&cached.logged);
        match (cached.decision, matched) {
            (WafDecision::Block, Some(rule)) => {
                self.block(ctx, rule, cached.reason, logged)
            }
            _ => self.allow(ctx, matched, cached.reason, logged),
        }
    }

    fn allow<'e>(
        &'e self,
        ctx: &mut dyn WafHttpContext,
        matched_rule: Option<&'e WafRule>,
        reason: Option<String>,
        logged_rules: Vec<&'e WafRule>,
    ) -> WafEvaluationResult<'e> {
        self.emit(WafLogLevel::Debug, |logger| logger.connection(ctx));
        WafEvaluationResult {
            decision: WafDecision::Allow,
            matched_rule,
            reason,
            logged_rules,
        }
    }

    fn block<'e>(
        &'e self,
        ctx: &mut dyn WafHttpContext,
        rule: &'e WafRule,
        reason: Option<String>,
        logged_rules: Vec<&'e WafRule>,
    ) -> WafEvaluationResult<'e> {
        ctx.drop(
            Some(self.config.block_status_code),
            Some(&self.config.block_body),
        );
        self.emit(WafLogLevel::Error, |logger| logger.blocked(ctx, rule));
        WafEvaluationResult {
            decision: WafDecision::Block,
            matched_rule: Some(rule),
            reason,
            logged_rules,
        }
    }

    fn rules_at(&self, indices: &[usize]) -> Vec<&WafRule> {
        indices
            .iter()
            .filter_map(|&index| self.config.rules.get(index))
            .collect()
    }

    fn emit(&self, minimum: WafLogLevel, event: impl FnOnce(&dyn WafLogger)) {
        let logging = self.config.logging;
        if logging.enabled && is_log_level_active(logging.level, minimum) {
            event(self.logger.as_ref());
        }
    }
}

fn write_rate_limit_headers(ctx: &mut dyn WafHttpContext, info: RateLimitInfo) {
    ctx.set_response_header("X-RateLimit-Limit", &info.limit.to_string());
    ctx.set_response_header(
        "X-RateLimit-Remaining",
        &info.remaining.to_string(),
    );
    ctx.set_response_header("X-RateLimit-Reset", &info.reset_at.to_string());
}
