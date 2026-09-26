//! Load serializable (JSON) rules into live [`WafRule`] values.
//!
//! A rules document is either a top-level array or `{ "rules": [...] }`:
//!
//! ```json
//! {
//!   "rules": [
//!     {
//!       "id": "block-sqli",
//!       "action": "block",
//!       "reason": "Possible SQL injection",
//!       "when": {
//!         "field": "query.id",
//!         "matches": { "pattern": "union\\s+select", "flags": "i" }
//!       }
//!     }
//!   ]
//! }
//! ```
//!
//! `matches` is a string (exact), a string array (any of) or
//! `{ "pattern", "flags"? }` (a regex, see [`crate::compile_regex`]).

use std::fmt;

use crate::domain::levels::{
    InvalidProtectionLevel,
    ProtectionLevel,
};
use crate::domain::rules::{
    FieldCondition,
    MatchPattern,
    RateLimitSpec,
    WafAction,
    WafCondition,
    WafField,
    WafRule,
};
use crate::domain::values::JsonValue;
use crate::engine::matcher::compile_regex;
use crate::engine::normalize_condition::normalize_rule;

/// A malformed rule. `path` points at the offending key (for example
/// `rules[2].when.rateLimit.max`) so the failure is actionable at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleParseError {
    pub path: String,
    pub message: String,
}

impl RuleParseError {
    fn new(path: &str, message: impl Into<String>) -> Self {
        Self {
            path: path.to_owned(),
            message: message.into(),
        }
    }
}

impl fmt::Display for RuleParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for RuleParseError {}

type Result<T> = std::result::Result<T, RuleParseError>;
type Object = [(String, JsonValue)];

const CONDITION_KEYS: &[&str] = &[
    "field",
    "matches",
    "equals",
    "includes",
    "requires",
    "rateLimit",
];
const RULE_KEYS: &[&str] = &[
    "id", "when", "action", "reason", "enabled", "priority", "minLevel",
];
/// `Number.MAX_SAFE_INTEGER`: larger integers are not exact in JSON numbers.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

fn read_string(value: &JsonValue, path: &str) -> Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| RuleParseError::new(path, "expected a string"))
}

fn read_bool(value: &JsonValue, path: &str) -> Result<bool> {
    match value {
        JsonValue::Bool(flag) => Ok(*flag),
        _ => Err(RuleParseError::new(path, "expected a boolean")),
    }
}

fn read_integer(value: &JsonValue, path: &str) -> Result<i64> {
    let number = match value {
        JsonValue::Number(number) if number.is_finite() => *number,
        _ => return Err(RuleParseError::new(path, "expected a finite number")),
    };
    if number.fract() != 0.0 || number.abs() > MAX_SAFE_INTEGER {
        return Err(RuleParseError::new(path, "expected an integer"));
    }
    Ok(number as i64)
}

fn read_positive_integer(value: &JsonValue, path: &str) -> Result<u64> {
    let number = read_integer(value, path)?;
    u64::try_from(number)
        .ok()
        .filter(|&number| number >= 1)
        .ok_or_else(|| RuleParseError::new(path, "must be >= 1"))
}

fn read_string_array(value: &JsonValue, path: &str) -> Result<Vec<String>> {
    let items = value
        .as_array()
        .ok_or_else(|| RuleParseError::new(path, "expected a string array"))?;
    read_each(items, path, read_string)
}

fn read_each<T>(
    items: &[JsonValue],
    path: &str,
    read: impl Fn(&JsonValue, &str) -> Result<T>,
) -> Result<Vec<T>> {
    items
        .iter()
        .enumerate()
        .map(|(index, item)| read(item, &format!("{path}[{index}]")))
        .collect()
}

fn read_action(value: &JsonValue, path: &str) -> Result<WafAction> {
    match read_string(value, path)?.as_str() {
        "allow" => Ok(WafAction::Allow),
        "block" => Ok(WafAction::Block),
        "log" => Ok(WafAction::Log),
        other => Err(RuleParseError::new(
            path,
            format!(
                "invalid action \"{other}\" (expected allow | block | log)"
            ),
        )),
    }
}

fn read_level(value: &JsonValue, path: &str) -> Result<ProtectionLevel> {
    read_string(value, path)?.parse().map_err(
        |error: InvalidProtectionLevel| {
            RuleParseError::new(path, error.to_string())
        },
    )
}

fn read_field(value: &JsonValue, path: &str) -> Result<WafField> {
    let raw = read_string(value, path)?;
    raw.parse().map_err(|_| {
        RuleParseError::new(path, format!("unsupported field \"{raw}\""))
    })
}

/// A JSON object being read, with its path for error messages.
struct Node<'a> {
    object: &'a Object,
    path: &'a str,
}

impl<'a> Node<'a> {
    fn new(value: &'a JsonValue, path: &'a str) -> Result<Self> {
        let object = value.as_object().ok_or_else(|| {
            RuleParseError::new(path, "expected a JSON object")
        })?;
        Ok(Self { object, path })
    }

    fn at(&self, key: &str) -> String {
        format!("{}.{key}", self.path)
    }

    fn get(&self, key: &str) -> Option<&'a JsonValue> {
        self.object
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    fn optional<T>(
        &self,
        key: &str,
        read: impl FnOnce(&JsonValue, &str) -> Result<T>,
    ) -> Result<Option<T>> {
        self.get(key)
            .map(|value| read(value, &self.at(key)))
            .transpose()
    }

    /// A key that must be present; `missing` is the error when it is not.
    fn required<T>(
        &self,
        key: &str,
        missing: &str,
        read: impl FnOnce(&JsonValue, &str) -> Result<T>,
    ) -> Result<T> {
        let value = self
            .get(key)
            .ok_or_else(|| RuleParseError::new(&self.at(key), missing))?;
        read(value, &self.at(key))
    }

    fn reject_unexpected(&self, allowed: &[&str]) -> Result<()> {
        match self
            .object
            .iter()
            .find(|(key, _)| !allowed.contains(&key.as_str()))
        {
            Some((key, _)) => Err(RuleParseError::new(
                self.path,
                format!("unexpected key \"{key}\""),
            )),
            None => Ok(()),
        }
    }

    /// `all` / `anyOf` / `not` must be the object's only key.
    fn expect_only(&self, key: &str) -> Result<()> {
        if self.object.len() > 1 {
            return Err(RuleParseError::new(
                self.path,
                format!("`{key}` cannot be mixed with other keys"),
            ));
        }
        Ok(())
    }
}

fn load_match_pattern(value: &JsonValue, path: &str) -> Result<MatchPattern> {
    match value {
        JsonValue::String(text) => Ok(MatchPattern::Exact(text.clone())),
        JsonValue::Array(_) => {
            read_string_array(value, path).map(MatchPattern::OneOf)
        }
        JsonValue::Object(_) => load_regex(&Node::new(value, path)?),
        _ => Err(RuleParseError::new(
            path,
            "expected a string, string array, or { pattern, flags? }",
        )),
    }
}

/// `{ "pattern", "flags"? }`. A flag error points at `flags`, any other
/// compile error at the pattern object.
fn load_regex(node: &Node) -> Result<MatchPattern> {
    let pattern = node.required("pattern", "expected a string", read_string)?;
    let flags = node.optional("flags", read_string)?.unwrap_or_default();
    compile_regex(&pattern, &flags)
        .map(MatchPattern::Regex)
        .map_err(|error| {
            let path = if error.0.contains("flag") {
                node.at("flags")
            } else {
                node.path.to_owned()
            };
            RuleParseError::new(&path, error.0)
        })
}

fn load_rate_limit(value: &JsonValue, path: &str) -> Result<RateLimitSpec> {
    let node = Node::new(value, path)?;
    Ok(RateLimitSpec {
        max: node.required(
            "max",
            "expected a finite number",
            read_positive_integer,
        )?,
        window_ms: node.required(
            "windowMs",
            "expected a finite number",
            read_positive_integer,
        )?,
        key_prefix: node.optional("keyPrefix", read_string)?,
    })
}

fn load_children(node: &Node, key: &str) -> Result<Vec<WafCondition>> {
    node.expect_only(key)?;
    let path = node.at(key);
    let items = node
        .get(key)
        .and_then(JsonValue::as_array)
        .ok_or_else(|| RuleParseError::new(&path, "expected an array"))?;
    read_each(items, &path, load_condition)
}

fn load_condition(value: &JsonValue, path: &str) -> Result<WafCondition> {
    let node = Node::new(value, path)?;
    if node.has("all") {
        return load_children(&node, "all").map(WafCondition::all);
    }
    if node.has("anyOf") {
        return load_children(&node, "anyOf").map(WafCondition::any_of);
    }
    if node.has("not") {
        node.expect_only("not")?;
        return node
            .required("not", "required", load_condition)
            .map(WafCondition::not);
    }
    load_field_condition(&node).map(WafCondition::Field)
}

fn load_field_condition(node: &Node) -> Result<FieldCondition> {
    if !node.has("field") {
        return Err(RuleParseError::new(
            node.path,
            "expected field condition or all / anyOf / not",
        ));
    }
    let field = node.required("field", "expected a string", read_field)?;
    node.reject_unexpected(CONDITION_KEYS)?;

    let condition = FieldCondition {
        field,
        matches: node.optional("matches", load_match_pattern)?,
        equals: node.optional("equals", read_string)?,
        includes: node.optional("includes", read_string)?,
        requires: node.optional("requires", read_string_array)?,
        rate_limit: node.optional("rateLimit", load_rate_limit)?,
    };
    if !condition.has_pattern() && condition.rate_limit.is_none() {
        return Err(RuleParseError::new(
            node.path,
            "field condition needs matches, equals, includes, or rateLimit",
        ));
    }
    Ok(condition)
}

fn load_rule(value: &JsonValue, path: &str) -> Result<WafRule> {
    let node = Node::new(value, path)?;
    let id = node.required("id", "expected a string", read_string)?;
    if id.is_empty() {
        return Err(RuleParseError::new(&node.at("id"), "must be non-empty"));
    }
    let rule = WafRule {
        id,
        when: node.required("when", "required", load_condition)?,
        action: node.required("action", "expected a string", read_action)?,
        reason: node.optional("reason", read_string)?,
        enabled: node.optional("enabled", read_bool)?,
        priority: node.optional("priority", read_integer)?,
        min_level: node.optional("minLevel", read_level)?,
    };
    node.reject_unexpected(RULE_KEYS)?;
    Ok(normalize_rule(rule))
}

/// Compile a parsed JSON value (an array of rules, or `{ "rules": [...] }`)
/// into live [`WafRule`] values (regexes compiled from `{ pattern, flags? }`).
pub fn load_rules(value: &JsonValue) -> Result<Vec<WafRule>> {
    if let Some(items) = value.as_array() {
        return read_each(items, "rules", load_rule);
    }
    match value.get("rules") {
        Some(rules) => {
            let items = rules.as_array().ok_or_else(|| {
                RuleParseError::new("$.rules", "expected an array")
            })?;
            read_each(items, "$.rules", load_rule)
        }
        None => Err(RuleParseError::new(
            "$",
            concat!(
                "expected a JSON array of rules ",
                "or an object with a \"rules\" array",
            ),
        )),
    }
}

/// Parse JSON text and compile its rules.
pub fn parse_rules_from_json(input: &str) -> Result<Vec<WafRule>> {
    let value = JsonValue::parse(input).map_err(|error| {
        RuleParseError::new("$", format!("failed to parse JSON ({error})"))
    })?;
    load_rules(&value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "rules": [
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
      ]
    }"#;

    #[test]
    fn parses_a_rules_document() {
        let rules = parse_rules_from_json(SAMPLE).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "json-block-sqli");
        let WafCondition::Field(field) = &rules[0].when else {
            panic!("expected a field condition")
        };
        assert_eq!(field.field, WafField::query("id"));
        assert!(field.matches.as_ref().unwrap().is_match("1 UNION  SELECT"));
        assert_eq!(rules[1].priority, Some(1));
    }

    #[test]
    fn accepts_top_level_arrays_and_string_lists() {
        let rules = parse_rules_from_json(
            r#"[{ "id": "m", "action": "block", "when": {
        "field": "method", "matches": ["TRACE", "TRACK"]
      } }]"#,
        )
        .unwrap();
        let WafCondition::Field(field) = &rules[0].when else {
            panic!()
        };
        let Some(MatchPattern::OneOf(list)) = &field.matches else {
            panic!()
        };
        assert_eq!(list, &["TRACE", "TRACK"]);
    }

    #[test]
    fn supports_nested_conditions_and_requires() {
        let rules = parse_rules_from_json(
            r#"[{ "id": "c", "action": "block", "when": { "anyOf": [
        { "field": "path", "equals": "/admin" },
        { "all": [
          { "field": "method", "equals": "POST" },
          { "field": "path", "includes": "upload", "requires": ["UP"] }
        ] }
      ] } }]"#,
        )
        .unwrap();
        let WafCondition::AnyOf(children) = &rules[0].when else {
            panic!()
        };
        let WafCondition::All(inner) = &children.any_of[1] else {
            panic!()
        };
        let WafCondition::Field(field) = &inner.all[1] else {
            panic!()
        };
        assert_eq!(field.requires, Some(vec!["up".to_owned()]));
    }

    /// A one-rule document around a `when` condition.
    fn with_when(when: &str) -> String {
        with_rule(&format!(r#""action":"block","when":{when}"#))
    }

    /// A one-rule document with id `x` and the given members.
    fn with_rule(members: &str) -> String {
        format!(r#"[{{"id":"x",{members}}}]"#)
    }

    #[test]
    fn rejects_invalid_shapes_with_paths() {
        let cases = [
            (r#"{"rules":[{}]}"#.to_owned(), "$.rules[0].id"),
            (
                with_rule(concat!(
                    r#""action":"explode","#,
                    r#""when":{"field":"path","equals":"/"}"#,
                )),
                "rules[0].action",
            ),
            (
                format!(
                    r#"{{"rules":{}}}"#,
                    with_when(r#"{"field":"unknown","equals":"x"}"#)
                ),
                "$.rules[0].when.field",
            ),
            (
                with_when(r#"{"field":"query","matches":"d","requires":[1]}"#),
                "rules[0].when.requires[0]",
            ),
            (
                with_when(
                    r#"{"field":"ip","rateLimit":{"max":0,"windowMs":1}}"#,
                ),
                "rules[0].when.rateLimit.max",
            ),
            (with_when(r#"{"field":"ip"}"#), "rules[0].when"),
            (
                with_when(r#"{"field":"ip","equals":"1","extra":1}"#),
                "rules[0].when",
            ),
            (
                with_when(
                    r#"{"field":"ip","matches":{"pattern":"a","flags":"x"}}"#,
                ),
                "rules[0].when.matches.flags",
            ),
            (with_when(r#"{"all":[],"field":"ip"}"#), "rules[0].when"),
            (
                with_rule(concat!(
                    r#""action":"block","minLevel":"max","#,
                    r#""when":{"field":"ip","equals":"1"}"#,
                )),
                "rules[0].minLevel",
            ),
            ("{".to_owned(), "$"),
        ];
        for (input, path) in cases {
            let error = parse_rules_from_json(&input).unwrap_err();
            assert_eq!(error.path, path, "{input} -> {error}");
        }
    }
}
