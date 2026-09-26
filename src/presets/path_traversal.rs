//! Path traversal and local file inclusion (CRS REQUEST-930).
//!
//! `path` is exposed exactly as it arrived on the wire — still encoded — so
//! the encoded, double-encoded and overlong-UTF-8 variants matter.

use std::sync::LazyLock;

use crate::domain::levels::ProtectionLevel::{
    Balanced,
    High,
    Low,
};
use crate::domain::rules::{
    WafAction,
    WafField,
    WafRule,
};
use crate::presets::fields::{
    PAYLOAD_PATH_FIELDS,
    URL_FIELDS,
    any_field_matches,
    re,
};

/// Classic `../` and encoded variants (CRS 930100/110 simplified).
const PATH_TRAVERSAL: &str =
    r"(\.\.(\/|\\)|\.\.%(2[fF]|5[cC])|\.\.;(?:\/|\\))+";

/// Percent-encoded, double-encoded and overlong-UTF-8 traversal (CRS 930100).
const ENCODED_TRAVERSAL: &str = concat!(
    r"%(?:25)?2[eE]%(?:25)?2[eE]|\.%(?:25)?2[eE]|%(?:25)?2[eE]\.|%c0%a[ef]|",
    r"%c1%9c|%e0%80%a[ef]|%f0%80%80%a[ef]|%c0%2[eEfF]|%u2216|%uff0e",
);

/// Sensitive OS paths probed in LFI (CRS 930120/130 subset).
const OS_FILE_ACCESS: &str = concat!(
    r"(?:\/etc\/(?:passwd|shadow|hosts|issue|crontab)|(?:^|[\\/])(?:boot|",
    r"win)\.ini\b|\/proc\/(?:self|version)|\/windows\/system32\/|",
    r"\\windows\\system32\\)",
);

/// Windows UNC / administrative-share path. URL-borne fields only: a JSON
/// body routinely carries `\\` as the escape of one backslash.
const UNC_PATH: &str = concat!(
    r"\\\\[\w.$-]{1,60}\\[\w$.]|%5c%5c[\w.%]{1,60}%5c|\\\\\?\\|\b[a-zA-Z]\$\\|",
    r"\badmin\$",
);

/// VCS, secrets and backup files in the path (CRS 930130-ish).
const RESTRICTED_PATH: &str = concat!(
    r"(?:\/|^)(?:\.git(?:\/|$)|\.env(?:\.|$)|\.htaccess|\.htpasswd|\.DS_Store|",
    r"wp-config\.php|web\.config|composer\.(?:json|lock)|id_rsa(?:\.pub)?)",
);

fn rules() -> Vec<WafRule> {
    vec![
        WafRule::new(
            "preset-path-traversal",
            any_field_matches(
                &PAYLOAD_PATH_FIELDS,
                &re(PATH_TRAVERSAL, ""),
                &[".."],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Low)
        .reason("Path traversal attempt"),
        WafRule::new(
            "preset-path-traversal-encoded",
            any_field_matches(
                &[WafField::Path, WafField::Query, WafField::Cookies],
                &re(ENCODED_TRAVERSAL, "i"),
                &["%"],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Low)
        .reason("Encoded or double-encoded path traversal attempt"),
        WafRule::new(
            "preset-lfi-os-files",
            any_field_matches(
                &PAYLOAD_PATH_FIELDS,
                &re(OS_FILE_ACCESS, "i"),
                &["/etc/", ".ini", "/proc/", "system32"],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Low)
        .reason("Possible local file inclusion of OS path"),
        WafRule::new(
            "preset-lfi-unc-path",
            any_field_matches(
                &URL_FIELDS,
                &re(UNC_PATH, "i"),
                &["\\", "%5c", "$"],
            ),
            WafAction::Block,
        )
        .priority(48)
        .min_level(High)
        .reason("Possible UNC / administrative-share path access"),
        WafRule::new(
            "preset-lfi-restricted-files",
            any_field_matches(
                &[WafField::Path, WafField::Query, WafField::Url],
                &re(RESTRICTED_PATH, "i"),
                &[
                    ".git",
                    ".env",
                    ".htaccess",
                    ".htpasswd",
                    ".ds_store",
                    "wp-config.php",
                    "web.config",
                    "composer.",
                    "id_rsa",
                ],
            ),
            WafAction::Block,
        )
        .priority(48)
        .min_level(Balanced)
        .reason("Restricted or sensitive file path probe"),
    ]
}

static RULES: LazyLock<Vec<WafRule>> = LazyLock::new(rules);

/// The `path-traversal` preset.
pub fn path_traversal_rules() -> &'static [WafRule] {
    &RULES
}
