//! Declarative WAF rule DSL.
//!
//! ```
//! use mini_waf::{
//!     FieldCondition,
//!     MatchPattern,
//!     ProtectionLevel,
//!     WafAction,
//!     WafField,
//!     WafRule,
//! };
//!
//! let rules = vec![
//!     WafRule::new(
//!         "block-sqli",
//!         FieldCondition::new(WafField::query("id")).matches(
//!             MatchPattern::regex_with_flags(r"('|OR\s+1=1)", "i")
//!                 .unwrap(),
//!         ),
//!         WafAction::Block,
//!     )
//!     .reason("Possible SQL injection")
//!     .min_level(ProtectionLevel::Low),
//! ];
//! # let _ = rules;
//! ```

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use regex::bytes::Regex;

use crate::domain::levels::ProtectionLevel;
use crate::engine::matcher::{
    RegexError,
    compile_regex,
    matches_pattern,
};
use crate::logging::port::WafLoggingSetting;

/// Pure predicate for field matching (e.g. "Host header is an IP literal").
#[derive(Clone)]
pub struct MatchPredicate(Arc<dyn Fn(&str) -> bool + Send + Sync>);

impl MatchPredicate {
    pub fn new(test: impl Fn(&str) -> bool + Send + Sync + 'static) -> Self {
        Self(Arc::new(test))
    }

    pub fn test(&self, value: &str) -> bool {
        (self.0)(value)
    }
}

impl fmt::Debug for MatchPredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MatchPredicate(..)")
    }
}

/// Match target of `FieldCondition::matches`: literal, regex, string list,
/// or pure predicate.
#[derive(Debug, Clone)]
pub enum MatchPattern {
    /// Case-sensitive exact equality.
    Exact(String),
    /// Regular expression, see [`compile_regex`].
    Regex(Regex),
    /// Exact equality with any of the listed strings.
    OneOf(Vec<String>),
    /// Arbitrary pure predicate.
    Predicate(MatchPredicate),
}

impl MatchPattern {
    /// Compile a regex pattern with no flags.
    pub fn regex(pattern: &str) -> Result<Self, RegexError> {
        compile_regex(pattern, "").map(MatchPattern::Regex)
    }

    /// Compile a regex pattern with JavaScript-style flags (`"i"`, `"im"`, …).
    pub fn regex_with_flags(
        pattern: &str,
        flags: &str,
    ) -> Result<Self, RegexError> {
        compile_regex(pattern, flags).map(MatchPattern::Regex)
    }

    pub fn exact(value: impl Into<String>) -> Self {
        MatchPattern::Exact(value.into())
    }

    pub fn one_of<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        MatchPattern::OneOf(values.into_iter().map(Into::into).collect())
    }

    pub fn predicate(
        test: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> Self {
        MatchPattern::Predicate(MatchPredicate::new(test))
    }

    /// Test a candidate value (see
    /// [`matches_pattern`](crate::matches_pattern)).
    pub fn is_match(&self, value: &str) -> bool {
        matches_pattern(value, self)
    }
}

impl From<Regex> for MatchPattern {
    fn from(regex: Regex) -> Self {
        MatchPattern::Regex(regex)
    }
}

/// Supported request fields. Nested accessors use dotted paths in their
/// string form (`query.id`, `headers.user-agent`).
///
/// Multi-value fields (`Query`, `Headers`, `Cookies`, `Files`) yield every
/// value, and a condition matches when any of them does.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WafField {
    Ip,
    Method,
    Path,
    Url,
    Body,
    Files,
    Query,
    Headers,
    Cookies,
    /// `query.<name>`
    QueryParam(String),
    /// `headers.<name>`; the name is matched lowercased.
    Header(String),
    /// `cookies.<name>`
    Cookie(String),
}

impl WafField {
    /// `query.<name>`
    pub fn query(name: impl Into<String>) -> Self {
        WafField::QueryParam(name.into())
    }

    /// `headers.<name>`
    pub fn header(name: impl Into<String>) -> Self {
        WafField::Header(name.into())
    }

    /// `cookies.<name>`
    pub fn cookie(name: impl Into<String>) -> Self {
        WafField::Cookie(name.into())
    }
}

impl fmt::Display for WafField {
    /// The dotted path form (`query.id`, `headers.host`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WafField::Ip => f.write_str("ip"),
            WafField::Method => f.write_str("method"),
            WafField::Path => f.write_str("path"),
            WafField::Url => f.write_str("url"),
            WafField::Body => f.write_str("body"),
            WafField::Files => f.write_str("files"),
            WafField::Query => f.write_str("query"),
            WafField::Headers => f.write_str("headers"),
            WafField::Cookies => f.write_str("cookies"),
            WafField::QueryParam(name) => write!(f, "query.{name}"),
            WafField::Header(name) => write!(f, "headers.{name}"),
            WafField::Cookie(name) => write!(f, "cookies.{name}"),
        }
    }
}

/// Error returned for an unsupported field path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidField(pub String);

impl fmt::Display for InvalidField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported field \"{}\"", self.0)
    }
}

impl std::error::Error for InvalidField {}

impl FromStr for WafField {
    type Err = InvalidField;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let field = match value {
            "ip" => WafField::Ip,
            "method" => WafField::Method,
            "path" => WafField::Path,
            "url" => WafField::Url,
            "body" => WafField::Body,
            "files" => WafField::Files,
            "query" => WafField::Query,
            "headers" => WafField::Headers,
            "cookies" => WafField::Cookies,
            _ => {
                if let Some(name) = value.strip_prefix("query.") {
                    WafField::QueryParam(name.to_owned())
                } else if let Some(name) = value.strip_prefix("headers.") {
                    WafField::Header(name.to_owned())
                } else if let Some(name) = value.strip_prefix("cookies.") {
                    WafField::Cookie(name.to_owned())
                } else {
                    return Err(InvalidField(value.to_owned()));
                }
            }
        };
        Ok(field)
    }
}

/// Sliding-window rate limit attached to a field condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitSpec {
    /// Maximum hits inside the window before the condition matches.
    pub max: u64,
    /// Sliding window length in milliseconds.
    pub window_ms: u64,
    /// Optional key override. Defaults to the resolved field value
    /// (typically the client IP when the field is `ip`).
    pub key_prefix: Option<String>,
}

impl RateLimitSpec {
    pub fn new(max: u64, window_ms: u64) -> Self {
        Self {
            max,
            window_ms,
            key_prefix: None,
        }
    }

    pub fn key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = Some(prefix.into());
        self
    }
}

/// Match a single request field.
///
/// With `matches` / `equals` / `includes` the condition matches when any
/// value satisfies any of them. With only `rate_limit` it matches once the
/// field's bucket exceeds the limit; combined, the pattern gates the counter.
#[derive(Debug, Clone)]
pub struct FieldCondition {
    pub field: WafField,
    /// Regex, exact string, or list of strings (OR).
    pub matches: Option<MatchPattern>,
    /// Case-sensitive exact equality.
    pub equals: Option<String>,
    /// Case-insensitive substring.
    pub includes: Option<String>,
    /// When set, the condition matches after exceeding the rate limit.
    pub rate_limit: Option<RateLimitSpec>,
    /// Cheap literal gate evaluated **before** `matches` / `equals` /
    /// `includes`.
    ///
    /// A candidate value only reaches the pattern when it contains at least
    /// one of these substrings (case-insensitive). Use it whenever every
    /// payload the pattern can match necessarily contains a fixed literal — a
    /// substring search over a large body is far cheaper than a regex pass.
    ///
    /// Leave it out when unsure: an incomplete `requires` list silently
    /// narrows the rule, because a value missing every literal is never
    /// matched.
    pub requires: Option<Vec<String>>,
}

impl FieldCondition {
    pub fn new(field: WafField) -> Self {
        Self {
            field,
            matches: None,
            equals: None,
            includes: None,
            rate_limit: None,
            requires: None,
        }
    }

    pub fn matches(mut self, pattern: impl Into<MatchPattern>) -> Self {
        self.matches = Some(pattern.into());
        self
    }

    pub fn equals(mut self, value: impl Into<String>) -> Self {
        self.equals = Some(value.into());
        self
    }

    pub fn includes(mut self, needle: impl Into<String>) -> Self {
        self.includes = Some(needle.into());
        self
    }

    pub fn rate_limit(mut self, spec: RateLimitSpec) -> Self {
        self.rate_limit = Some(spec);
        self
    }

    pub fn requires<I, S>(mut self, literals: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.requires = Some(literals.into_iter().map(Into::into).collect());
        self
    }

    pub(crate) fn has_pattern(&self) -> bool {
        self.matches.is_some()
            || self.equals.is_some()
            || self.includes.is_some()
    }
}

/// Logical AND of nested conditions. An empty list never matches.
#[derive(Debug, Clone)]
pub struct AllCondition {
    pub all: Vec<WafCondition>,
}

/// Logical OR of nested conditions.
#[derive(Debug, Clone)]
pub struct AnyOfCondition {
    pub any_of: Vec<WafCondition>,
}

/// Negate a nested condition.
#[derive(Debug, Clone)]
pub struct NotCondition {
    pub not: Box<WafCondition>,
}

/// A condition tree.
#[derive(Debug, Clone)]
pub enum WafCondition {
    Field(FieldCondition),
    All(AllCondition),
    AnyOf(AnyOfCondition),
    Not(NotCondition),
}

impl WafCondition {
    /// `{ all: [...] }`
    pub fn all(conditions: impl IntoIterator<Item = WafCondition>) -> Self {
        WafCondition::All(AllCondition {
            all: conditions.into_iter().collect(),
        })
    }

    /// `{ anyOf: [...] }`
    pub fn any_of(conditions: impl IntoIterator<Item = WafCondition>) -> Self {
        WafCondition::AnyOf(AnyOfCondition {
            any_of: conditions.into_iter().collect(),
        })
    }

    /// `{ not: ... }`
    #[allow(clippy::should_implement_trait)]
    pub fn not(condition: impl Into<WafCondition>) -> Self {
        WafCondition::Not(NotCondition {
            not: Box::new(condition.into()),
        })
    }
}

impl From<FieldCondition> for WafCondition {
    fn from(condition: FieldCondition) -> Self {
        WafCondition::Field(condition)
    }
}

impl From<AllCondition> for WafCondition {
    fn from(condition: AllCondition) -> Self {
        WafCondition::All(condition)
    }
}

impl From<AnyOfCondition> for WafCondition {
    fn from(condition: AnyOfCondition) -> Self {
        WafCondition::AnyOf(condition)
    }
}

impl From<NotCondition> for WafCondition {
    fn from(condition: NotCondition) -> Self {
        WafCondition::Not(condition)
    }
}

/// What a matching rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WafAction {
    /// Stop evaluating and let the request through.
    Allow,
    /// Reject the request (the first matching block wins).
    Block,
    /// Record the match and keep evaluating.
    Log,
}

impl WafAction {
    pub fn as_str(self) -> &'static str {
        match self {
            WafAction::Allow => "allow",
            WafAction::Block => "block",
            WafAction::Log => "log",
        }
    }
}

impl fmt::Display for WafAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One WAF rule.
#[derive(Debug, Clone)]
pub struct WafRule {
    pub id: String,
    pub when: WafCondition,
    pub action: WafAction,
    /// Human-readable reason used in logs / block responses.
    pub reason: Option<String>,
    /// Defaults to `true`.
    pub enabled: Option<bool>,
    /// Lower numbers run first. Defaults to 100. `allow` rules that match
    /// short-circuit evaluation.
    pub priority: Option<i64>,
    /// Minimum protection level required for this rule to run. Defaults to
    /// `Low` (active at every configured level): the rule runs when
    /// `config.level >= min_level`.
    pub min_level: Option<ProtectionLevel>,
}

impl WafRule {
    pub fn new(
        id: impl Into<String>,
        when: impl Into<WafCondition>,
        action: WafAction,
    ) -> Self {
        Self {
            id: id.into(),
            when: when.into(),
            action,
            reason: None,
            enabled: None,
            priority: None,
            min_level: None,
        }
    }

    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
        self
    }

    pub fn priority(mut self, priority: i64) -> Self {
        self.priority = Some(priority);
        self
    }

    pub fn min_level(mut self, level: ProtectionLevel) -> Self {
        self.min_level = Some(level);
        self
    }
}

/// Built-in rule packs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WafPresetName {
    /// Every pack below, in one list.
    Default,
    Sqli,
    Xss,
    Scanners,
    PathTraversal,
    Rfi,
    Rce,
    Protocol,
}

impl WafPresetName {
    pub fn as_str(self) -> &'static str {
        match self {
            WafPresetName::Default => "default",
            WafPresetName::Sqli => "sqli",
            WafPresetName::Xss => "xss",
            WafPresetName::Scanners => "scanners",
            WafPresetName::PathTraversal => "path-traversal",
            WafPresetName::Rfi => "rfi",
            WafPresetName::Rce => "rce",
            WafPresetName::Protocol => "protocol",
        }
    }
}

impl fmt::Display for WafPresetName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for WafPresetName {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        [
            WafPresetName::Default,
            WafPresetName::Sqli,
            WafPresetName::Xss,
            WafPresetName::Scanners,
            WafPresetName::PathTraversal,
            WafPresetName::Rfi,
            WafPresetName::Rce,
            WafPresetName::Protocol,
        ]
        .into_iter()
        .find(|preset| preset.as_str() == value)
        .ok_or_else(|| format!("unknown preset \"{value}\""))
    }
}

/// `WafConfig::decision_cache`: a short-TTL LRU of allow/block decisions
/// keyed by a request fingerprint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecisionCacheConfig {
    /// Default 256.
    pub max: Option<usize>,
    /// Default 1000 ms.
    pub ttl_ms: Option<u64>,
}

/// `WafConfig::decode`: transport decoders.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeConfig {
    /// Whole-value Base64 blobs.
    pub base64: Option<bool>,
    /// Percent-encoding on surfaces the framework does not decode.
    pub url: Option<bool>,
    /// Inline SQL comments used as token separators (`space2comment`).
    pub comments: Option<bool>,
}

/// Everything the engine needs to build its immutable rule list. Every field
/// is optional, like the TypeScript object: build it with struct-update
/// syntax or the chainable setters of the same names.
///
/// ```
/// use mini_waf::{
///     ProtectionLevel,
///     WafConfig,
///     WafPresetName,
/// };
///
/// let config = WafConfig {
///     presets: Some(vec![WafPresetName::Default]),
///     level: Some(ProtectionLevel::High),
///     ..WafConfig::default()
/// };
/// let same = WafConfig::default()
///     .presets([WafPresetName::Default])
///     .level(ProtectionLevel::High);
/// # let _ = (config, same);
/// ```
#[derive(Debug, Clone, Default)]
pub struct WafConfig {
    /// Protection level. Only rules with `min_level <= level` are applied.
    /// Default: `Balanced`.
    pub level: Option<ProtectionLevel>,
    /// Custom rules evaluated after (or instead of) presets.
    pub rules: Option<Vec<WafRule>>,
    /// Built-in rule packs to include.
    pub presets: Option<Vec<WafPresetName>>,
    /// Optional allowlist of rule ids. When present and non-empty, only those
    /// ids remain after presets + custom merge and level filtering.
    pub enabled_rule_ids: Option<Vec<String>>,
    /// Drop rules whose `id` is listed. Applied after the level filter and
    /// the optional `enabled_rule_ids` allowlist.
    pub disabled_rule_ids: Option<Vec<String>>,
    /// HTTP status used on block. Default: 403.
    pub block_status_code: Option<u16>,
    /// Response body used on block. Default: `"Forbidden"`.
    pub block_body: Option<String>,
    /// Logging is **off by default** (no I/O, no formatting):
    /// - `None` / `false` — silent
    /// - `true` — plain console at level `Info` (blocks + audit)
    /// - [`crate::WafLoggingOptions`] — verbosity + optional injectable sink
    pub logging: Option<WafLoggingSetting>,
    /// Cap length of each field value scanned by matchers (body, query,
    /// headers, …). Longer values are truncated for matching / rate-limit
    /// key material only. Default: `8192`. `0` is unlimited (not
    /// recommended in production).
    pub max_field_length: Option<usize>,
    /// Cap on distinct rate-limit keys (typically per-IP buckets). Cold keys
    /// are evicted LRU-style when the cap is exceeded. Default: `10000`.
    pub max_rate_limit_keys: Option<usize>,
    /// Optional short-TTL LRU of allow/block decisions keyed by a request
    /// fingerprint (method + path + IP + query + UA + body hash).
    ///
    /// **Disabled automatically** when any active rule uses `rate_limit`, so
    /// DoS counters always advance. Default: off.
    pub decision_cache: Option<DecisionCacheConfig>,
    /// Transport decoding. Decodes an encoded or obfuscated whole-value
    /// payload (Base64, percent-encoding on surfaces the framework does not
    /// decode, inline SQL comments between keywords) and rescans the text with
    /// the **existing** rules.
    ///
    /// A new false-positive axis, so all three are **off at `Low` /
    /// `Balanced` and auto-enabled at `High`+**. Set a field to override
    /// either way.
    pub decode: Option<DecodeConfig>,
}

impl WafConfig {
    pub fn level(mut self, level: ProtectionLevel) -> Self {
        self.level = Some(level);
        self
    }

    pub fn rules(mut self, rules: impl IntoIterator<Item = WafRule>) -> Self {
        self.rules = Some(rules.into_iter().collect());
        self
    }

    pub fn presets(
        mut self,
        presets: impl IntoIterator<Item = WafPresetName>,
    ) -> Self {
        self.presets = Some(presets.into_iter().collect());
        self
    }

    pub fn enabled_rule_ids<I, S>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.enabled_rule_ids = Some(ids.into_iter().map(Into::into).collect());
        self
    }

    pub fn disabled_rule_ids<I, S>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.disabled_rule_ids =
            Some(ids.into_iter().map(Into::into).collect());
        self
    }

    pub fn block_status_code(mut self, status_code: u16) -> Self {
        self.block_status_code = Some(status_code);
        self
    }

    pub fn block_body(mut self, body: impl Into<String>) -> Self {
        self.block_body = Some(body.into());
        self
    }

    pub fn logging(mut self, logging: impl Into<WafLoggingSetting>) -> Self {
        self.logging = Some(logging.into());
        self
    }

    pub fn max_field_length(mut self, length: usize) -> Self {
        self.max_field_length = Some(length);
        self
    }

    pub fn max_rate_limit_keys(mut self, keys: usize) -> Self {
        self.max_rate_limit_keys = Some(keys);
        self
    }

    pub fn decision_cache(mut self, cache: DecisionCacheConfig) -> Self {
        self.decision_cache = Some(cache);
        self
    }

    pub fn decode(mut self, decode: DecodeConfig) -> Self {
        self.decode = Some(decode);
        self
    }
}

/// Final verdict for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WafDecision {
    Allow,
    Block,
}

/// Outcome of evaluating one request. Rules are borrowed from the engine.
#[derive(Debug, Clone)]
pub struct WafEvaluationResult<'a> {
    pub decision: WafDecision,
    /// The `allow` rule that short-circuited, or the `block` rule that won.
    pub matched_rule: Option<&'a WafRule>,
    pub reason: Option<String>,
    /// Rules with action `log` that matched during evaluation.
    pub logged_rules: Vec<&'a WafRule>,
}

/// Whether a condition is a single-field match (`field`).
pub fn is_field_condition(condition: &WafCondition) -> bool {
    matches!(condition, WafCondition::Field(_))
}

/// Whether a condition is a logical AND (`all`).
pub fn is_all_condition(condition: &WafCondition) -> bool {
    matches!(condition, WafCondition::All(_))
}

/// Whether a condition is a logical OR (`any_of`).
pub fn is_any_of_condition(condition: &WafCondition) -> bool {
    matches!(condition, WafCondition::AnyOf(_))
}

/// Whether a condition is a negation (`not`).
pub fn is_not_condition(condition: &WafCondition) -> bool {
    matches!(condition, WafCondition::Not(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_prints_field_paths() {
        for path in [
            "ip",
            "path",
            "query",
            "query.id",
            "headers.user-agent",
            "cookies.sid",
        ] {
            assert_eq!(path.parse::<WafField>().unwrap().to_string(), path);
        }
        assert!("unknown".parse::<WafField>().is_err());
    }

    #[test]
    fn type_guards() {
        let leaf: WafCondition =
            FieldCondition::new(WafField::Path).equals("/").into();
        assert!(is_field_condition(&leaf));
        assert!(is_all_condition(&WafCondition::all([leaf.clone()])));
        assert!(is_any_of_condition(&WafCondition::any_of([leaf.clone()])));
        assert!(is_not_condition(&WafCondition::not(leaf)));
    }
}
