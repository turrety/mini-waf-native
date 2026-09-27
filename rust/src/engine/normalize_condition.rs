//! Pre-lowercase static `includes` and `requires` needles (matching is
//! case-insensitive), so the hot path never lowercases a constant.

use crate::domain::rules::{
    AllCondition,
    AnyOfCondition,
    FieldCondition,
    NotCondition,
    WafCondition,
    WafRule,
};

/// Deep-normalize a condition tree.
pub fn normalize_condition(condition: WafCondition) -> WafCondition {
    match condition {
        WafCondition::Field(field) => {
            WafCondition::Field(lowercase_needles(field))
        }
        WafCondition::All(AllCondition { all }) => {
            WafCondition::All(AllCondition {
                all: all.into_iter().map(normalize_condition).collect(),
            })
        }
        WafCondition::AnyOf(AnyOfCondition { any_of }) => {
            WafCondition::AnyOf(AnyOfCondition {
                any_of: any_of.into_iter().map(normalize_condition).collect(),
            })
        }
        WafCondition::Not(NotCondition { not }) => {
            WafCondition::Not(NotCondition {
                not: Box::new(normalize_condition(*not)),
            })
        }
    }
}

fn lowercase_needles(mut field: FieldCondition) -> FieldCondition {
    field.includes = field.includes.map(|needle| needle.to_lowercase());
    field.requires = field.requires.map(|literals| {
        literals
            .iter()
            .map(|literal| literal.to_lowercase())
            .collect()
    });
    field
}

/// Normalize a rule's condition tree.
pub fn normalize_rule(mut rule: WafRule) -> WafRule {
    rule.when = normalize_condition(rule.when);
    rule
}

/// Normalize every rule in a list.
pub fn normalize_rules(rules: Vec<WafRule>) -> Vec<WafRule> {
    rules.into_iter().map(normalize_rule).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::rules::{
        WafAction,
        WafField,
    };

    #[test]
    fn lowercases_needles() {
        let rule = WafRule::new(
            "r",
            FieldCondition::new(WafField::Body)
                .includes("CuRl")
                .requires(["DANGER"]),
            WafAction::Block,
        );
        let WafCondition::Field(field) = normalize_rule(rule).when else {
            panic!("expected a field condition")
        };
        assert_eq!(field.includes.as_deref(), Some("curl"));
        assert_eq!(field.requires, Some(vec!["danger".to_owned()]));
    }
}
