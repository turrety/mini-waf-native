//! JSON-serializable WAF rule DSL.
//!
//! These types mirror the JSON document [`load_rules`](crate::load_rules)
//! accepts. Patterns cannot carry live regexes or predicates: use exact
//! strings, string lists, or `{ pattern, flags? }` for a regex. Convert a rule
//! into a [`JsonValue`] to serialize it (`.to_json_string()`) or to compile it
//! with `load_rules`.
//!
//! ```
//! use mini_waf::{
//!     JsonFieldCondition,
//!     JsonMatchPattern,
//!     JsonRegexPattern,
//!     JsonValue,
//!     JsonWafRule,
//!     WafAction,
//!     WafField,
//!     load_rules,
//! };
//!
//! let rule = JsonWafRule::new(
//!     "block-union",
//!     JsonFieldCondition::new(WafField::query("id")).matches(
//!         JsonMatchPattern::Regex(
//!             JsonRegexPattern::new(r"union\s+select").flags("i"),
//!         ),
//!     ),
//!     WafAction::Block,
//! );
//! let json = JsonValue::from(vec![rule]);
//! assert!(json.to_json_string().contains(r#""field":"query.id""#));
//! assert_eq!(load_rules(&json).unwrap()[0].id, "block-union");
//! ```

use crate::domain::levels::ProtectionLevel;
use crate::domain::rules::{
    WafAction,
    WafField,
};
use crate::domain::values::JsonValue;

/// Regex expressed as pattern + optional flags (JSON-safe).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRegexPattern {
    pub pattern: String,
    pub flags: Option<String>,
}

impl JsonRegexPattern {
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            flags: None,
        }
    }

    pub fn flags(mut self, flags: impl Into<String>) -> Self {
        self.flags = Some(flags.into());
        self
    }
}

/// Serializable `matches` value: an exact string, an OR list of exact
/// strings, or a regex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonMatchPattern {
    Exact(String),
    OneOf(Vec<String>),
    Regex(JsonRegexPattern),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRateLimitSpec {
    pub max: u64,
    pub window_ms: u64,
    pub key_prefix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonFieldCondition {
    pub field: WafField,
    pub matches: Option<JsonMatchPattern>,
    pub equals: Option<String>,
    pub includes: Option<String>,
    pub requires: Option<Vec<String>>,
    pub rate_limit: Option<JsonRateLimitSpec>,
}

impl JsonFieldCondition {
    pub fn new(field: WafField) -> Self {
        Self {
            field,
            matches: None,
            equals: None,
            includes: None,
            requires: None,
            rate_limit: None,
        }
    }

    pub fn matches(mut self, pattern: JsonMatchPattern) -> Self {
        self.matches = Some(pattern);
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

    pub fn requires<I, S>(mut self, literals: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.requires = Some(literals.into_iter().map(Into::into).collect());
        self
    }

    pub fn rate_limit(mut self, spec: JsonRateLimitSpec) -> Self {
        self.rate_limit = Some(spec);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonAllCondition {
    pub all: Vec<JsonWafCondition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonAnyOfCondition {
    pub any_of: Vec<JsonWafCondition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonNotCondition {
    pub not: Box<JsonWafCondition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonWafCondition {
    Field(JsonFieldCondition),
    All(JsonAllCondition),
    AnyOf(JsonAnyOfCondition),
    Not(JsonNotCondition),
}

impl From<JsonFieldCondition> for JsonWafCondition {
    fn from(condition: JsonFieldCondition) -> Self {
        JsonWafCondition::Field(condition)
    }
}

impl From<JsonAllCondition> for JsonWafCondition {
    fn from(condition: JsonAllCondition) -> Self {
        JsonWafCondition::All(condition)
    }
}

impl From<JsonAnyOfCondition> for JsonWafCondition {
    fn from(condition: JsonAnyOfCondition) -> Self {
        JsonWafCondition::AnyOf(condition)
    }
}

impl From<JsonNotCondition> for JsonWafCondition {
    fn from(condition: JsonNotCondition) -> Self {
        JsonWafCondition::Not(condition)
    }
}

/// One rule as it appears in JSON. Alias: [`SerializableWafRule`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonWafRule {
    pub id: String,
    pub when: JsonWafCondition,
    pub action: WafAction,
    pub reason: Option<String>,
    pub enabled: Option<bool>,
    pub priority: Option<i64>,
    pub min_level: Option<ProtectionLevel>,
}

/// See [`JsonWafRule`].
pub type SerializableWafRule = JsonWafRule;

impl JsonWafRule {
    pub fn new(
        id: impl Into<String>,
        when: impl Into<JsonWafCondition>,
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

fn object(
    entries: impl IntoIterator<Item = (&'static str, Option<JsonValue>)>,
) -> JsonValue {
    JsonValue::Object(
        entries
            .into_iter()
            .filter_map(|(key, value)| Some((key.to_owned(), value?)))
            .collect(),
    )
}

fn strings(values: Vec<String>) -> JsonValue {
    JsonValue::Array(values.into_iter().map(JsonValue::String).collect())
}

impl From<JsonMatchPattern> for JsonValue {
    fn from(pattern: JsonMatchPattern) -> Self {
        match pattern {
            JsonMatchPattern::Exact(text) => JsonValue::String(text),
            JsonMatchPattern::OneOf(values) => strings(values),
            JsonMatchPattern::Regex(regex) => object([
                ("pattern", Some(JsonValue::String(regex.pattern))),
                ("flags", regex.flags.map(JsonValue::String)),
            ]),
        }
    }
}

impl From<JsonRateLimitSpec> for JsonValue {
    fn from(spec: JsonRateLimitSpec) -> Self {
        object([
            ("max", Some(JsonValue::Number(spec.max as f64))),
            ("windowMs", Some(JsonValue::Number(spec.window_ms as f64))),
            ("keyPrefix", spec.key_prefix.map(JsonValue::String)),
        ])
    }
}

impl From<JsonWafCondition> for JsonValue {
    fn from(condition: JsonWafCondition) -> Self {
        let children = |items: Vec<JsonWafCondition>| {
            JsonValue::Array(items.into_iter().map(JsonValue::from).collect())
        };
        match condition {
            JsonWafCondition::Field(field) => object([
                ("field", Some(JsonValue::String(field.field.to_string()))),
                ("matches", field.matches.map(JsonValue::from)),
                ("equals", field.equals.map(JsonValue::String)),
                ("includes", field.includes.map(JsonValue::String)),
                ("requires", field.requires.map(strings)),
                ("rateLimit", field.rate_limit.map(JsonValue::from)),
            ]),
            JsonWafCondition::All(all) => {
                object([("all", Some(children(all.all)))])
            }
            JsonWafCondition::AnyOf(any_of) => {
                object([("anyOf", Some(children(any_of.any_of)))])
            }
            JsonWafCondition::Not(not) => {
                object([("not", Some(JsonValue::from(*not.not)))])
            }
        }
    }
}

impl From<JsonWafRule> for JsonValue {
    fn from(rule: JsonWafRule) -> Self {
        object([
            ("id", Some(JsonValue::String(rule.id))),
            ("when", Some(JsonValue::from(rule.when))),
            (
                "action",
                Some(JsonValue::String(rule.action.as_str().to_owned())),
            ),
            ("reason", rule.reason.map(JsonValue::String)),
            ("enabled", rule.enabled.map(JsonValue::Bool)),
            (
                "priority",
                rule.priority
                    .map(|priority| JsonValue::Number(priority as f64)),
            ),
            (
                "minLevel",
                rule.min_level
                    .map(|level| JsonValue::String(level.as_str().to_owned())),
            ),
        ])
    }
}

impl From<Vec<JsonWafRule>> for JsonValue {
    fn from(rules: Vec<JsonWafRule>) -> Self {
        JsonValue::Array(rules.into_iter().map(JsonValue::from).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::rules::WafCondition;
    use crate::engine::load_rules::load_rules;

    #[test]
    fn round_trips_through_the_loader() {
        let rule = JsonWafRule::new(
            "login-flood",
            JsonAllCondition {
                all: vec![
                    JsonFieldCondition::new(WafField::Path)
                        .equals("/login")
                        .into(),
                    JsonNotCondition {
                        not: Box::new(
                            JsonFieldCondition::new(WafField::Ip)
                                .equals("10.0.0.1")
                                .into(),
                        ),
                    }
                    .into(),
                    JsonFieldCondition::new(WafField::Ip)
                        .rate_limit(JsonRateLimitSpec {
                            max: 5,
                            window_ms: 60_000,
                            key_prefix: Some("login".into()),
                        })
                        .into(),
                ],
            },
            WafAction::Block,
        )
        .reason("Too many login attempts")
        .priority(5)
        .min_level(ProtectionLevel::High);
        let json = JsonValue::from(vec![rule]);
        assert!(json.to_json_string().contains(
            r#""rateLimit":{"max":5,"windowMs":60000,"keyPrefix":"login"}"#
        ));
        let loaded = load_rules(&json).unwrap();
        assert_eq!(
            (loaded[0].priority, loaded[0].min_level),
            (Some(5), Some(ProtectionLevel::High))
        );
        let WafCondition::All(all) = &loaded[0].when else {
            panic!("expected all")
        };
        assert_eq!(all.all.len(), 3);
    }
}
