//! Protection levels control which rules are active.
//!
//! Every rule declares a `min_level`; it runs only when the configured level
//! is at least as strict (`Low < Balanced < High < Paranoid`).
//!
//! - `Low` — high signal / low false positives (obvious scanners, classic SQLi,
//!   traversal, RFI)
//! - `Balanced` — the default; low + common XSS, null bytes, uploads, rate
//!   limit
//! - `High` — balanced + aggressive heuristics (SSI, hex flood, pollution,
//!   blind SQLi) and the transport decoders
//! - `Paranoid` — high + legacy rules with elevated false positives

use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum ProtectionLevel {
    Low,
    #[default]
    Balanced,
    High,
    Paranoid,
}

/// Every level, from least to most strict.
pub const PROTECTION_LEVELS: [ProtectionLevel; 4] = [
    ProtectionLevel::Low,
    ProtectionLevel::Balanced,
    ProtectionLevel::High,
    ProtectionLevel::Paranoid,
];

/// Level used when `WafConfig::level` is omitted.
pub const DEFAULT_PROTECTION_LEVEL: ProtectionLevel = ProtectionLevel::Balanced;

/// `min_level` of a rule that does not set one: active at every level.
pub const DEFAULT_RULE_MIN_LEVEL: ProtectionLevel = ProtectionLevel::Low;

impl ProtectionLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            ProtectionLevel::Low => "low",
            ProtectionLevel::Balanced => "balanced",
            ProtectionLevel::High => "high",
            ProtectionLevel::Paranoid => "paranoid",
        }
    }
}

/// Numeric rank of a protection level, ordered `Low` (0) through
/// `Paranoid` (3). Useful for comparing two levels directly.
pub fn protection_level_rank(level: ProtectionLevel) -> u8 {
    level as u8
}

/// True when `configured` is at least as strict as `min_level` (i.e. a rule
/// with that minimum should run).
pub fn is_level_active(
    configured: ProtectionLevel,
    min_level: ProtectionLevel,
) -> bool {
    protection_level_rank(configured) >= protection_level_rank(min_level)
}

/// Whether an arbitrary string is a valid [`ProtectionLevel`].
pub fn is_protection_level(value: &str) -> bool {
    value.parse::<ProtectionLevel>().is_ok()
}

impl fmt::Display for ProtectionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when a string is not one of `low | balanced | high |
/// paranoid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidProtectionLevel(pub String);

impl fmt::Display for InvalidProtectionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid protection level \"{}\"", self.0)
    }
}

impl std::error::Error for InvalidProtectionLevel {}

impl FromStr for ProtectionLevel {
    type Err = InvalidProtectionLevel;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        PROTECTION_LEVELS
            .into_iter()
            .find(|level| level.as_str() == value)
            .ok_or_else(|| InvalidProtectionLevel(value.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_low_to_paranoid() {
        assert!(
            protection_level_rank(ProtectionLevel::Low)
                < protection_level_rank(ProtectionLevel::Balanced)
        );
        assert!(is_level_active(
            ProtectionLevel::Balanced,
            ProtectionLevel::Low
        ));
        assert!(!is_level_active(
            ProtectionLevel::Low,
            ProtectionLevel::Balanced
        ));
        assert!(is_level_active(
            ProtectionLevel::Paranoid,
            ProtectionLevel::High
        ));
        assert!(!is_level_active(
            ProtectionLevel::High,
            ProtectionLevel::Paranoid
        ));
    }

    #[test]
    fn parses_and_prints() {
        assert_eq!(
            "high".parse::<ProtectionLevel>(),
            Ok(ProtectionLevel::High)
        );
        assert!("extreme".parse::<ProtectionLevel>().is_err());
        assert!(
            is_protection_level("paranoid") && !is_protection_level("extreme")
        );
        assert_eq!(ProtectionLevel::default().to_string(), "balanced");
    }
}
