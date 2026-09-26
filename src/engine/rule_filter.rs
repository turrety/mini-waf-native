//! Rule-id allow / deny lists.

use std::collections::HashSet;

use crate::domain::rules::WafRule;

/// Optional allowlist: when `enabled_rule_ids` is present and non-empty, keep
/// only rules whose `id` is listed. `None` / empty is a no-op.
pub fn filter_rules_by_enabled_ids(
    rules: Vec<WafRule>,
    enabled_rule_ids: Option<&[String]>,
) -> Vec<WafRule> {
    match id_set(enabled_rule_ids) {
        Some(allowed) => rules
            .into_iter()
            .filter(|rule| allowed.contains(rule.id.as_str()))
            .collect(),
        None => rules,
    }
}

/// Drop rules whose `id` appears in `disabled_rule_ids`. `None` / empty is a
/// no-op.
pub fn filter_rules_by_disabled_ids(
    rules: Vec<WafRule>,
    disabled_rule_ids: Option<&[String]>,
) -> Vec<WafRule> {
    match id_set(disabled_rule_ids) {
        Some(disabled) => rules
            .into_iter()
            .filter(|rule| !disabled.contains(rule.id.as_str()))
            .collect(),
        None => rules,
    }
}

/// The ids as a set, or `None` when the list is absent or empty.
fn id_set(ids: Option<&[String]>) -> Option<HashSet<&str>> {
    let ids = ids.filter(|ids| !ids.is_empty())?;
    Some(ids.iter().map(String::as_str).collect())
}
