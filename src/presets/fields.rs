//! Shared building blocks of the preset packs: field groups, the regex
//! compiler and the fan-out helper.

use crate::domain::rules::{
    FieldCondition,
    MatchPattern,
    WafCondition,
    WafField,
};
use crate::engine::matcher::compile_regex;

/// Fields that usually carry attacker-controlled payloads.
pub(crate) const PAYLOAD_FIELDS: [WafField; 3] =
    [WafField::Query, WafField::Body, WafField::Cookies];
/// Payload fields plus the request path (URL-borne injection).
pub(crate) const PAYLOAD_PATH_FIELDS: [WafField; 4] = [
    WafField::Query,
    WafField::Body,
    WafField::Path,
    WafField::Cookies,
];
/// URL-borne fields only — for patterns too noisy to scan in bodies.
pub(crate) const URL_FIELDS: [WafField; 3] =
    [WafField::Query, WafField::Path, WafField::Cookies];

/// Compile a preset regex. Preset patterns are constants covered by the test
/// suite, so a failure is a programming error.
pub(crate) fn re(pattern: &str, flags: &str) -> MatchPattern {
    match compile_regex(pattern, flags) {
        Ok(regex) => MatchPattern::Regex(regex),
        Err(error) => panic!("invalid preset regex {pattern:?}: {error}"),
    }
}

/// Fan one pattern out over several fields as a logical OR. The compiled
/// regex is shared (cloning it is a reference-count bump).
///
/// `requires` is the literal prefilter: it must list a substring that
/// **every** string the pattern can match contains, or the rule silently
/// stops detecting those payloads.
pub(crate) fn any_field_matches(
    fields: &[WafField],
    pattern: &MatchPattern,
    requires: &[&str],
) -> WafCondition {
    WafCondition::any_of(fields.iter().map(|field| {
        let condition =
            FieldCondition::new(field.clone()).matches(pattern.clone());
        match requires {
            [] => condition.into(),
            literals => condition.requires(literals.iter().copied()).into(),
        }
    }))
}
