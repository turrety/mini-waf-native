//! The `default` preset: every other pack in one list.

use std::sync::LazyLock;

use crate::domain::rules::WafRule;
use crate::presets::{
    path_traversal_rules,
    protocol_rules,
    rce_rules,
    rfi_rules,
    scanner_rules,
    sqli_rules,
    xss_rules,
};

static RULES: LazyLock<Vec<WafRule>> = LazyLock::new(|| {
    [
        scanner_rules(),
        protocol_rules(),
        sqli_rules(),
        xss_rules(),
        path_traversal_rules(),
        rfi_rules(),
        rce_rules(),
    ]
    .concat()
});

/// Combined baseline pack used by `presets: [WafPresetName::Default]`.
pub fn default_rules() -> &'static [WafRule] {
    &RULES
}
