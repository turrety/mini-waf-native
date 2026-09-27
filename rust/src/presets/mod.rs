//! Built-in rule packs, derived from OWASP CRS categories.
//!
//! Rule ids are public API: users disable rules by id, and the test suite
//! asserts which id fires for each attack.

mod default;
pub(crate) mod fields;
mod path_traversal;
mod protocol;
mod rce;
mod rfi;
mod scanners;
mod sqli;
mod xss;

use std::collections::HashSet;

pub use default::default_rules;
pub use path_traversal::path_traversal_rules;
pub use protocol::protocol_rules;
pub use rce::rce_rules;
pub use rfi::rfi_rules;
pub use scanners::scanner_rules;
pub use sqli::sqli_rules;
pub use xss::xss_rules;

use crate::domain::rules::{
    WafPresetName,
    WafRule,
};

fn preset_map(name: WafPresetName) -> &'static [WafRule] {
    match name {
        WafPresetName::Default => default_rules(),
        WafPresetName::Sqli => sqli_rules(),
        WafPresetName::Xss => xss_rules(),
        WafPresetName::Scanners => scanner_rules(),
        WafPresetName::PathTraversal => path_traversal_rules(),
        WafPresetName::Rfi => rfi_rules(),
        WafPresetName::Rce => rce_rules(),
        WafPresetName::Protocol => protocol_rules(),
    }
}

/// Resolve preset names into a flat rule list, deduplicated by id (the first
/// occurrence wins).
pub fn resolve_presets(names: &[WafPresetName]) -> Vec<WafRule> {
    let mut seen = HashSet::new();
    names
        .iter()
        .flat_map(|&name| preset_map(name))
        .filter(|rule| seen.insert(rule.id.as_str()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_preset_compiles_with_unique_ids() {
        let all = default_rules();
        let ids: HashSet<&str> =
            all.iter().map(|rule| rule.id.as_str()).collect();
        assert_eq!(ids.len(), all.len(), "duplicate preset id");
        assert!(ids.iter().all(|id| id.starts_with("preset-")));
    }

    #[test]
    fn default_is_the_union_of_every_pack() {
        let parts = [
            WafPresetName::Scanners,
            WafPresetName::Protocol,
            WafPresetName::Sqli,
            WafPresetName::Xss,
            WafPresetName::PathTraversal,
            WafPresetName::Rfi,
            WafPresetName::Rce,
        ];
        let expected: usize =
            parts.iter().map(|&name| preset_map(name).len()).sum();
        assert_eq!(default_rules().len(), expected);
        assert_eq!(
            resolve_presets(&[WafPresetName::Default, WafPresetName::Sqli])
                .len(),
            expected
        );
    }
}
