//! The WAF engine and its entry points.

pub(crate) mod condition_utils;
pub(crate) mod decode;
#[allow(clippy::module_inception)]
pub(crate) mod engine;
pub(crate) mod evaluate;
pub(crate) mod field_resolver;
pub(crate) mod fingerprint;
pub(crate) mod load_rules;
pub(crate) mod matcher;
pub(crate) mod normalize_condition;
pub(crate) mod rate_limit;
pub(crate) mod rule_filter;

use std::ops::Deref;

pub use condition_utils::{
    condition_has_rate_limit,
    rules_have_rate_limit,
};
pub use decode::DecodeSettings;
pub use engine::{
    DEFAULT_MAX_FIELD_LENGTH,
    ResolvedDecisionCache,
    ResolvedPerformance,
    ResolvedWafConfig,
    ScanOptions,
    ScanState,
    WafEngine,
    WafEngineOptions,
    build_rule_list,
    create_waf_engine,
    filter_rules_by_level,
    scan_rules,
};
pub use evaluate::{
    ConditionEvaluation,
    EvaluateOptions,
    RateLimitInfo,
    evaluate_condition,
};
pub use field_resolver::{
    FieldResolveOptions,
    resolve_field_joined,
    resolve_field_values,
    resolve_field_values_lower,
};
pub use fingerprint::{
    hash_string,
    request_fingerprint,
};
pub use load_rules::{
    RuleParseError,
    load_rules,
    parse_rules_from_json,
};
pub use matcher::{
    RegexError,
    compile_regex,
    contains_any_lower,
    includes_ignore_case,
    includes_lower,
    matches_pattern,
};
pub use normalize_condition::{
    normalize_condition,
    normalize_rule,
    normalize_rules,
};
pub use rate_limit::{
    DEFAULT_MAX_RATE_LIMIT_KEYS,
    DEFAULT_RATE_LIMIT_IDLE_MS,
    DEFAULT_RATE_LIMIT_PRUNE_EVERY,
    RateLimitHit,
    RateLimitPort,
    RateLimitState,
    RateLimitStore,
    RateLimitStoreOptions,
    RateLimitTransition,
    apply_rate_limit_hit,
    empty_rate_limit_state,
    prune_rate_limit_state,
};
pub use rule_filter::{
    filter_rules_by_disabled_ids,
    filter_rules_by_enabled_ids,
};

use crate::domain::context::{
    WafAdapter,
    WafHttpContext,
};
use crate::domain::rules::{
    WafConfig,
    WafEvaluationResult,
};
pub use crate::utils::lru::{
    LruCache,
    LruEntry,
};

/// A [`WafEngine`] plus [`protect`](MiniWafInstance::protect), which runs it
/// through an adapter. Every `WafEngine` method is available on it.
#[derive(Debug)]
pub struct MiniWafInstance {
    engine: WafEngine,
}

impl Deref for MiniWafInstance {
    type Target = WafEngine;

    fn deref(&self) -> &WafEngine {
        &self.engine
    }
}

impl MiniWafInstance {
    /// Run the engine against any adapter + native request / response.
    pub fn protect<TRequest, TResponse, A>(
        &self,
        adapter: &A,
        request: &TRequest,
        response: &mut TResponse,
    ) -> WafEvaluationResult<'_>
    where
        A: WafAdapter<TRequest, TResponse> + ?Sized,
    {
        let mut ctx = adapter.create_context(request, response);
        self.engine.handle(ctx.as_mut())
    }
}

/// Build a WAF instance: the main entry point.
///
/// Resolves `presets` and `rules` into a single immutable rule list, filters
/// it by `level`, and returns an object that can evaluate requests — through
/// [`WafEngine::handle`] (a [`WafHttpContext`]) or
/// [`MiniWafInstance::protect`] (an adapter).
///
/// `options` carries engine-level injectables, such as a `logger` or a
/// shared `rate_limit_store`.
///
/// ```
/// use mini_waf::{
///     ProtectionLevel,
///     WafConfig,
///     WafPresetName,
///     create_mini_waf,
/// };
///
/// let waf = create_mini_waf(
///     WafConfig::default()
///         .presets([WafPresetName::Default])
///         .level(ProtectionLevel::Balanced),
///     None,
/// );
/// assert!(
///     waf.rules()
///         .iter()
///         .any(|rule| rule.id == "preset-sqli-classic-query")
/// );
/// ```
pub fn create_mini_waf(
    config: WafConfig,
    options: Option<WafEngineOptions>,
) -> MiniWafInstance {
    MiniWafInstance {
        engine: create_waf_engine(config, options),
    }
}

/// What [`run_with_adapter`] returns: the result and the context it built.
pub struct AdapterRun<'e, 'a> {
    pub result: WafEvaluationResult<'e>,
    pub ctx: Box<dyn WafHttpContext + 'a>,
}

/// Build a context through `adapter`, evaluate it, and hand both back —
/// the shared step of framework integrations.
pub fn run_with_adapter<'e, 'a, TRequest, TResponse, A>(
    waf: &'e WafEngine,
    adapter: &'a A,
    request: &'a TRequest,
    response: &'a mut TResponse,
) -> AdapterRun<'e, 'a>
where
    A: WafAdapter<TRequest, TResponse> + ?Sized,
{
    let mut ctx = adapter.create_context(request, response);
    let result = waf.handle(ctx.as_mut());
    AdapterRun { result, ctx }
}
