//! The C enums, carried as `u32` so an out-of-range value from C is a
//! `None` rather than undefined behaviour. Discriminants follow declaration
//! order in the header.

use waf::{
    ProtectionLevel,
    WafAction,
    WafDecision,
    WafLogLevel,
    WafPresetName,
};

const PROTECTION_LEVELS: [ProtectionLevel; 4] = [
    ProtectionLevel::Low,
    ProtectionLevel::Balanced,
    ProtectionLevel::High,
    ProtectionLevel::Paranoid,
];
const ACTIONS: [WafAction; 3] =
    [WafAction::Allow, WafAction::Block, WafAction::Log];
const PRESETS: [WafPresetName; 8] = [
    WafPresetName::Default,
    WafPresetName::Sqli,
    WafPresetName::Xss,
    WafPresetName::Scanners,
    WafPresetName::PathTraversal,
    WafPresetName::Rfi,
    WafPresetName::Rce,
    WafPresetName::Protocol,
];
const LOG_LEVELS: [WafLogLevel; 3] =
    [WafLogLevel::Error, WafLogLevel::Info, WafLogLevel::Debug];
const DECISIONS: [WafDecision; 2] = [WafDecision::Allow, WafDecision::Block];

fn from_c<T: Copy>(values: &[T], value: u32) -> Option<T> {
    values.get(usize::try_from(value).ok()?).copied()
}

fn to_c<T: PartialEq>(values: &[T], value: &T) -> u32 {
    let index = values.iter().position(|candidate| candidate == value);
    index.map_or(0, |index| index as u32)
}

pub fn protection_level(value: u32) -> Option<ProtectionLevel> {
    from_c(&PROTECTION_LEVELS, value)
}

pub fn protection_level_to_c(level: ProtectionLevel) -> u32 {
    to_c(&PROTECTION_LEVELS, &level)
}

pub fn action(value: u32) -> Option<WafAction> {
    from_c(&ACTIONS, value)
}

pub fn action_to_c(action: WafAction) -> u32 {
    to_c(&ACTIONS, &action)
}

pub fn preset(value: u32) -> Option<WafPresetName> {
    from_c(&PRESETS, value)
}

pub fn log_level(value: u32) -> Option<WafLogLevel> {
    from_c(&LOG_LEVELS, value)
}

pub fn decision_to_c(decision: WafDecision) -> u32 {
    to_c(&DECISIONS, &decision)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_out_of_range_values() {
        for level in PROTECTION_LEVELS {
            let value = protection_level_to_c(level);
            assert_eq!(protection_level(value), Some(level));
        }
        for action in ACTIONS {
            assert_eq!(super::action(action_to_c(action)), Some(action));
        }
        assert_eq!(protection_level(4), None);
        assert_eq!(preset(8), None);
        assert_eq!(log_level(u32::MAX), None);
        assert_eq!(decision_to_c(WafDecision::Block), 1);
    }
}
