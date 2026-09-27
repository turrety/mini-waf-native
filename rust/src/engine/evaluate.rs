//! Rule compilation and condition evaluation.
//!
//! The engine compiles its rule list once: every distinct field gets a slot,
//! and each condition tree becomes a [`Program`] whose leaves point at slots,
//! so evaluation reads memoized field values by index.

use std::collections::HashMap;

use crate::domain::context::WafHttpContext;
use crate::domain::rules::{
    FieldCondition,
    MatchPattern,
    RateLimitSpec,
    WafCondition,
    WafField,
    WafRule,
};
use crate::engine::condition_utils::condition_has_rate_limit;
use crate::engine::field_resolver::{
    FieldResolveOptions,
    FieldResolver,
};
use crate::engine::matcher::{
    contains_any_lower,
    includes_lower,
    matches_pattern_view,
};
use crate::engine::normalize_condition::normalize_condition;
use crate::engine::rate_limit::RateLimitPort;
use crate::utils::time::now_ms;

/// Rate-limit state reported as `X-RateLimit-*` response headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitInfo {
    pub limit: u64,
    pub remaining: u64,
    pub reset_at: i64,
}

/// Evaluation result: match flag + optional rate-limit headers payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConditionEvaluation {
    pub matched: bool,
    pub rate_limit_info: Option<RateLimitInfo>,
}

impl ConditionEvaluation {
    const NO_MATCH: Self = Self {
        matched: false,
        rate_limit_info: None,
    };
}

/// Options of [`evaluate_condition`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EvaluateOptions {
    pub fields: FieldResolveOptions,
}

/// A condition tree whose fields are resolved to memo slots.
#[derive(Debug, Clone)]
pub(crate) enum Program {
    Leaf {
        slot: usize,
        condition: FieldCondition,
    },
    All(Vec<Program>),
    AnyOf(Vec<Program>),
    Not(Box<Program>),
}

/// Rules compiled for evaluation, parallel to the rule list.
#[derive(Debug, Clone, Default)]
pub(crate) struct CompiledRules {
    /// Slot index → field.
    pub(crate) fields: Vec<WafField>,
    pub(crate) programs: Vec<Program>,
    /// Per rule: whether its condition carries a rate-limit side effect.
    pub(crate) rate_limited: Vec<bool>,
}

impl CompiledRules {
    /// Compile conditions. `includes` / `requires` needles are lowercased on
    /// the way, so callers may pass rules that were never normalized.
    pub(crate) fn compile<'c>(
        conditions: impl IntoIterator<Item = &'c WafCondition>,
    ) -> Self {
        let mut compiler = Compiler::default();
        let mut programs = Vec::new();
        let mut rate_limited = Vec::new();
        for condition in conditions {
            let normalized = normalize_condition(condition.clone());
            rate_limited.push(condition_has_rate_limit(&normalized));
            programs.push(compiler.compile(normalized));
        }
        Self {
            fields: compiler.fields,
            programs,
            rate_limited,
        }
    }

    pub(crate) fn from_rules(rules: &[WafRule]) -> Self {
        Self::compile(rules.iter().map(|rule| &rule.when))
    }
}

/// Assigns one slot per distinct field while compiling condition trees.
#[derive(Default)]
struct Compiler {
    slots: HashMap<WafField, usize>,
    fields: Vec<WafField>,
}

impl Compiler {
    fn compile(&mut self, condition: WafCondition) -> Program {
        match condition {
            WafCondition::Field(leaf) => Program::Leaf {
                slot: self.slot_of(&leaf.field),
                condition: leaf,
            },
            WafCondition::All(all) => Program::All(self.compile_all(all.all)),
            WafCondition::AnyOf(any_of) => {
                Program::AnyOf(self.compile_all(any_of.any_of))
            }
            WafCondition::Not(not) => {
                Program::Not(Box::new(self.compile(*not.not)))
            }
        }
    }

    fn compile_all(&mut self, conditions: Vec<WafCondition>) -> Vec<Program> {
        conditions
            .into_iter()
            .map(|condition| self.compile(condition))
            .collect()
    }

    fn slot_of(&mut self, field: &WafField) -> usize {
        if let Some(&slot) = self.slots.get(field) {
            return slot;
        }
        self.fields.push(field.clone());
        self.slots.insert(field.clone(), self.fields.len() - 1);
        self.fields.len() - 1
    }
}

pub(crate) struct Evaluator<'r, 'a> {
    pub(crate) fields: &'r FieldResolver<'a>,
    pub(crate) rate_limits: &'r dyn RateLimitPort,
    pub(crate) now: i64,
}

/// One candidate value against a leaf. Needles were lowercased when the rule
/// was compiled; `lower` is present whenever `includes` / `requires` is set,
/// and `view` is the value regexes run on (see [`js_regex_view`]).
///
/// [`js_regex_view`]: crate::engine::matcher::js_regex_view
fn value_matches(
    condition: &FieldCondition,
    value: &str,
    lower: Option<&str>,
    view: &str,
) -> bool {
    if let (Some(requires), Some(haystack)) = (&condition.requires, lower) {
        if !contains_any_lower(haystack, requires) {
            return false;
        }
    }
    if condition.equals.as_deref() == Some(value) {
        return true;
    }
    if let (Some(needle), Some(haystack)) = (&condition.includes, lower) {
        if includes_lower(haystack, needle) {
            return true;
        }
    }
    condition
        .matches
        .as_ref()
        .is_some_and(|pattern| matches_pattern_view(value, view, pattern))
}

impl<'r> Evaluator<'r, '_> {
    /// Whether any value of the slot (decoded extras included) satisfies the
    /// leaf's `matches` / `equals` / `includes`, behind its `requires` gate.
    fn pattern_matches(&self, slot: usize, condition: &FieldCondition) -> bool {
        let fields = self.fields;
        let values = fields.values(slot).iter().chain(fields.extras(slot));
        let has_regex =
            matches!(condition.matches, Some(MatchPattern::Regex(_)));
        let views = if has_regex { fields.views(slot) } else { &[] };
        let view_of = |index: usize, value: &'r str| -> &'r str {
            views.get(index).and_then(Option::as_deref).unwrap_or(value)
        };

        if condition.includes.is_none() && condition.requires.is_none() {
            return values.enumerate().any(|(index, value)| {
                value_matches(condition, value, None, view_of(index, value))
            });
        }
        let lowered = fields
            .values_lower(slot)
            .iter()
            .chain(fields.extras_lower(slot));
        values
            .zip(lowered)
            .enumerate()
            .any(|(index, (value, lower))| {
                value_matches(
                    condition,
                    value,
                    Some(lower),
                    view_of(index, value),
                )
            })
    }

    fn evaluate_leaf(
        &self,
        slot: usize,
        condition: &FieldCondition,
    ) -> ConditionEvaluation {
        let has_pattern = condition.has_pattern();
        if has_pattern && !self.pattern_matches(slot, condition) {
            return ConditionEvaluation::NO_MATCH;
        }
        match &condition.rate_limit {
            Some(limit) => self.hit_rate_limit(slot, condition, limit),
            None => ConditionEvaluation {
                matched: has_pattern,
                rate_limit_info: None,
            },
        }
    }

    /// Count one hit in the field's bucket; the leaf matches once the bucket
    /// exceeds the limit.
    fn hit_rate_limit(
        &self,
        slot: usize,
        condition: &FieldCondition,
        limit: &RateLimitSpec,
    ) -> ConditionEvaluation {
        let material = self.fields.joined(slot);
        let key = match &limit.key_prefix {
            Some(prefix) => format!("{prefix}:{material}"),
            None => format!("{}:{material}", condition.field),
        };
        let hit = self.rate_limits.hit(
            &key,
            limit.max,
            limit.window_ms,
            Some(self.now),
        );
        let info = RateLimitInfo {
            limit: limit.max,
            remaining: hit.remaining,
            reset_at: hit.reset_at,
        };
        ConditionEvaluation {
            matched: hit.exceeded,
            rate_limit_info: Some(info),
        }
    }

    /// Evaluate a compiled condition. `All` / `AnyOf` short-circuit in order,
    /// so a rate-limited leaf after a failed sibling is not counted.
    pub(crate) fn evaluate(&self, program: &Program) -> ConditionEvaluation {
        match program {
            Program::Leaf { slot, condition } => {
                self.evaluate_leaf(*slot, condition)
            }
            Program::All(children) => self.evaluate_until(children, false),
            Program::AnyOf(children) => self.evaluate_until(children, true),
            Program::Not(inner) => {
                let result = self.evaluate(inner);
                ConditionEvaluation {
                    matched: !result.matched,
                    ..result
                }
            }
        }
    }

    /// Evaluate children in order until one yields `decisive` (`false` for
    /// `All`, `true` for `AnyOf`). Without a decisive child, `All` matches when
    /// it has children and `AnyOf` does not match. The latest rate-limit info
    /// seen is kept either way.
    fn evaluate_until(
        &self,
        children: &[Program],
        decisive: bool,
    ) -> ConditionEvaluation {
        let mut rate_limit_info = None;
        for child in children {
            let result = self.evaluate(child);
            rate_limit_info = result.rate_limit_info.or(rate_limit_info);
            if result.matched == decisive {
                return ConditionEvaluation {
                    matched: decisive,
                    rate_limit_info,
                };
            }
        }
        ConditionEvaluation {
            matched: !decisive && !children.is_empty(),
            rate_limit_info,
        }
    }
}

/// Evaluate one condition against a request. Rate-limit side effects go
/// through `rate_limits` (typically the shared
/// [`RateLimitStore`](crate::RateLimitStore)).
///
/// The engine compiles its rules once; this standalone form compiles the
/// condition on every call.
pub fn evaluate_condition(
    ctx: &dyn WafHttpContext,
    condition: &WafCondition,
    rate_limits: &dyn RateLimitPort,
    options: Option<&EvaluateOptions>,
) -> ConditionEvaluation {
    let options = options.copied().unwrap_or_default();
    let compiled = CompiledRules::compile([condition]);
    let fields = FieldResolver::new(ctx, &compiled.fields, options.fields);
    let evaluator = Evaluator {
        fields: &fields,
        rate_limits,
        now: now_ms(),
    };
    evaluator.evaluate(&compiled.programs[0])
}
