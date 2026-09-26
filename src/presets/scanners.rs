//! Known scanners, exploit kits, DoS heuristics and generic attack probes.

use std::sync::LazyLock;

use crate::domain::levels::ProtectionLevel::{
    Balanced,
    High,
    Low,
    Paranoid,
};
use crate::domain::rules::{
    FieldCondition,
    RateLimitSpec,
    WafAction,
    WafCondition,
    WafField,
    WafRule,
};
use crate::presets::fields::{
    PAYLOAD_PATH_FIELDS,
    any_field_matches,
    re,
};

/// LDAP filter injection — `*)(uid=*`, `(&(objectClass=*))`. Two-signal, so
/// ordinary parenthesised prose and Markdown links do not match.
const LDAP_INJECTION: &str = concat!(
    r"\(\s*[&|!]\s*\(|[*)]\s*\)\s*\(\s*[|&]|\(\s*(?:uid|cn|sn|mail|",
    r"objectclass|userpassword|givenname|member(?:of)?)\s*=\s*[*)]",
);

/// LDAP extensible-match / OID matching-rule injection — `attr:2.5.13.5:=x`.
const LDAP_MATCHING_RULE: &str = concat!(
    r"(?:\d+\.){3,}\d+\s*:\s*=|:\s*(?:caseignorematch|caseexactmatch|",
    r"integermatch|distinguishednamematch)\s*:\s*=",
);

/// GraphQL schema introspection. `__typename`, which real clients send
/// constantly, is deliberately **not** matched.
const GRAPHQL_INTROSPECTION: &str =
    r"\b__schema\b|\bIntrospectionQuery\b|\b__type\s*\(\s*name\s*:";

const SCANNER_UA: &str = concat!(
    r"(?:sqlmap|nikto|nmap|masscan|acunetix|nessus|burpsuite|w3af|dirbuster|",
    r"owasp_dirbuster|havij|openvas|zgrab|nuclei|ffuf|fuzz faster|feroxbuster|",
    r"gobuster|wfuzz|dirsearch|wpscan|arachni|sqlninja|wafw00f|whatweb)",
);

const SCANNER_UA_BROAD: &str = concat!(
    r"(?:morfeus|pmafind|httrack|blackwidow|wget|libwww-perl|python-requests|",
    r"scrapy|go-http-client|java\/|curl\/)",
);

fn rules() -> Vec<WafRule> {
    vec![
        WafRule::new(
            "preset-ldap-filter",
            any_field_matches(
                &PAYLOAD_PATH_FIELDS,
                &re(LDAP_INJECTION, "i"),
                &["("],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(High)
        .reason("Possible LDAP filter injection"),
        WafRule::new(
            "preset-ldap-matching-rule",
            any_field_matches(
                &PAYLOAD_PATH_FIELDS,
                &re(LDAP_MATCHING_RULE, "i"),
                &[":="],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(High)
        .reason("Possible LDAP extensible-match (OID matching rule) injection"),
        WafRule::new(
            "preset-scanners-ua",
            FieldCondition::new(WafField::header("user-agent"))
                .matches(re(SCANNER_UA, "i")),
            WafAction::Block,
        )
        .priority(40)
        .min_level(Low)
        .reason("Known scanner or exploit tool"),
        WafRule::new(
            "preset-scanners-ua-broad",
            FieldCondition::new(WafField::header("user-agent"))
                .matches(re(SCANNER_UA_BROAD, "i")),
            WafAction::Block,
        )
        .priority(42)
        .min_level(Paranoid)
        .reason("Broad scanner / scraper user-agent list"),
        WafRule::new(
            "preset-null-byte",
            any_field_matches(
                &[
                    WafField::Query,
                    WafField::Path,
                    WafField::Body,
                    WafField::Headers,
                ],
                &re(r"\x00", ""),
                &["\0"],
            ),
            WafAction::Block,
        )
        .priority(45)
        .min_level(Balanced)
        .reason("Null-byte injection attempt"),
        WafRule::new(
            "preset-data-exposure",
            WafCondition::any_of([
                FieldCondition::new(WafField::Path)
                    .matches(re(r"phpinfo\.php", "i"))
                    .requires(["phpinfo.php"])
                    .into(),
                FieldCondition::new(WafField::Query)
                    .matches(re(
                        concat!(
                            r"phpinfo\.php|",
                            r"HTTP_RAW_POST_DATA|HTTP_(?:POS|GE)T_VARS",
                        ),
                        "i",
                    ))
                    .requires(["phpinfo.php", "http_raw_post_data", "http_"])
                    .into(),
                FieldCondition::new(WafField::Body)
                    .matches(re(
                        r"HTTP_RAW_POST_DATA|HTTP_(?:POS|GE)T_VARS",
                        "i",
                    ))
                    .requires(["http_raw_post_data", "http_"])
                    .into(),
            ]),
            WafAction::Block,
        )
        .priority(48)
        .min_level(High)
        .reason("Possible data-exposure probe"),
        WafRule::new(
            "preset-prototype-pollution",
            any_field_matches(
                &[WafField::Query, WafField::Body, WafField::Cookies],
                &re(
                    concat!(
                        r"(?:__proto__|",
                        r#"constructor\s*\[\s*['"]prototype['"]\s*\])"#,
                    ),
                    "i",
                ),
                &["__proto__", "constructor"],
            ),
            WafAction::Block,
        )
        .priority(48)
        .min_level(High)
        .reason("Possible prototype pollution"),
        WafRule::new(
            "preset-hex-flood",
            any_field_matches(
                &[WafField::Query, WafField::Body],
                &re(r"(?:\\x[a-f0-9]{2,4}){25}", "i"),
                &["\\x"],
            ),
            WafAction::Block,
        )
        .priority(48)
        .min_level(High)
        .reason("Excessive hexadecimal escape sequence"),
        WafRule::new(
            "preset-excessive-header",
            FieldCondition::new(WafField::Headers)
                .matches(re(r"^[\s\S]{2048,}", "")),
            WafAction::Block,
        )
        .priority(45)
        .min_level(Paranoid)
        .reason("Excessive header length"),
        WafRule::new(
            "preset-shebang",
            any_field_matches(
                &[WafField::Query, WafField::Body],
                &re(r"#!\/(?:bin|usr\/bin)\/", ""),
                &["#!/"],
            ),
            WafAction::Block,
        )
        .priority(48)
        .min_level(Paranoid)
        .reason("Shell shebang in request payload"),
        WafRule::new(
            "preset-graphql-introspection",
            any_field_matches(
                &[WafField::Query, WafField::Body],
                &re(GRAPHQL_INTROSPECTION, "i"),
                &["__schema", "introspectionquery", "__type"],
            ),
            WafAction::Block,
        )
        .priority(48)
        .min_level(Paranoid)
        .reason("Possible GraphQL schema introspection probe"),
        WafRule::new(
            "preset-dos-rate-limit",
            FieldCondition::new(WafField::Ip).rate_limit(
                RateLimitSpec::new(120, 60_000).key_prefix("preset-dos"),
            ),
            WafAction::Block,
        )
        .priority(90)
        .min_level(Balanced)
        .reason("Possible Denial of Service — request rate exceeded"),
    ]
}

static RULES: LazyLock<Vec<WafRule>> = LazyLock::new(rules);

/// The `scanners` preset.
pub fn scanner_rules() -> &'static [WafRule] {
    &RULES
}
