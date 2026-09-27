//! Condition-tree queries.

use crate::domain::rules::{
    WafCondition,
    WafRule,
};

/// True when any leaf in the condition tree carries a `rate_limit` side
/// effect.
pub fn condition_has_rate_limit(condition: &WafCondition) -> bool {
    match condition {
        WafCondition::Field(field) => field.rate_limit.is_some(),
        WafCondition::All(all) => all.all.iter().any(condition_has_rate_limit),
        WafCondition::AnyOf(any_of) => {
            any_of.any_of.iter().any(condition_has_rate_limit)
        }
        WafCondition::Not(not) => condition_has_rate_limit(&not.not),
    }
}

/// True when the rule list includes at least one `rate_limit` condition.
pub fn rules_have_rate_limit(rules: &[WafRule]) -> bool {
    rules
        .iter()
        .any(|rule| condition_has_rate_limit(&rule.when))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::rules::{
        FieldCondition,
        RateLimitSpec,
        WafField,
    };

    #[test]
    fn detects_nested_rate_limits() {
        let limited = FieldCondition::new(WafField::Ip)
            .rate_limit(RateLimitSpec::new(1, 1_000));
        let tree = WafCondition::all([
            FieldCondition::new(WafField::Path).equals("/login").into(),
            WafCondition::not(limited),
        ]);
        assert!(condition_has_rate_limit(&tree));
        assert!(!condition_has_rate_limit(
            &FieldCondition::new(WafField::Path).equals("/").into()
        ));
    }
}
