//! Remote / local file inclusion, PHP RCE probes, XXE and dangerous uploads.

use std::sync::LazyLock;

use regex::bytes::Regex;

use crate::domain::levels::ProtectionLevel::{
    Balanced,
    High,
    Low,
};
use crate::domain::rules::{
    FieldCondition,
    MatchPattern,
    WafAction,
    WafField,
    WafRule,
};
use crate::engine::matcher::{
    compile_regex,
    js_regex_view,
    matches_pattern_view,
};
use crate::presets::fields::{
    PAYLOAD_FIELDS,
    PAYLOAD_PATH_FIELDS,
    any_field_matches,
    re,
};

/// PHP / stream wrappers (CRS 931110-ish). No legitimate meaning in input.
const STREAM_WRAPPER: &str = concat!(
    r"\b(?:php|data|expect|zip|phar|glob|ogg|rar|zlib|input|compress\.(?:zlib|",
    r"bzip2))\s*:\/\/|\bfile\s*:\/\/\/|\bphp:\/\/filter\b|",
    r"\ballow_url_(?:include|fopen)\b",
);

/// Remote inclusion of a server-side script: an absolute URL ending in an
/// executable web extension, or the CRS 931130 trailing-`?` trick. Deliberately
/// narrow so OAuth `redirect_uri`, CDN links and webhooks stay clean.
const REMOTE_INCLUDE: &str = concat!(
    r#"(?:^|[=,(\s"'])(?:https?|ftps?):\/\/[^\s'"<>]{1,200}?(?:\.(?:php\d?|"#,
    r#"phtml|phps|pht|inc|txt|asp|aspx|jsp|jspx|cgi|pl)\b|\?\s*$)"#,
);

/// PHP inclusion syntax; the quote / paren / variable after the keyword
/// separates `include('x')` from the English word or a JSON key.
const INCLUDE_SYNTAX: &str =
    r#"\b(?:include|require)(?:_once)?\b\s*(?:\(\s*['"$]|\s+['"$])"#;

/// PHP execution sinks and known RCE entry points (CRS 933).
const PHP_RCE: &str = concat!(
    r"\b(?:eval|assert|preg_replace)\s*\(\s*(?:base64_decode|exec|",
    r"file_get_contents|gzinflate|passthru|shell_exec|system|",
    r"str_rot13)?\s*\(?|\b(?:XDEBUG_SESSION_START|invokefunction|",
    r"call_user_func(?:_array)?|create_function|proc_open|popen|pcntl_exec)\b|",
    r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[",
);

/// XXE arms that need no look-around: an `<!ENTITY … SYSTEM|PUBLIC>`
/// reference, a `<!DOCTYPE>` declaring an entity, and a `SYSTEM` / `PUBLIC`
/// identifier pointing at a file or URL scheme.
const XXE_ENTITY: &str = concat!(
    r#"<!ENTITY\b[\s\S]{0,200}?\b(?:SYSTEM|PUBLIC)\b|"#,
    r#"<!DOCTYPE\b[\s\S]{0,200}?<!ENTITY\b|\b(?:SYSTEM|PUBLIC)\s+["'](?:file|"#,
    r#"https?|ftp|php|expect|jar|netdoc|gopher|data):"#,
);

/// Start of a `<!DOCTYPE … SYSTEM "…">` external DTD; the identifier must not
/// be `about:legacy-compat` (checked in code, as the regex dialect has no
/// look-ahead).
static XXE_DOCTYPE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(r#"<!DOCTYPE\b[^>]{0,200}?\bSYSTEM\s+["']"#, "i")
        .expect("valid XXE doctype regex")
});
static XXE_SYSTEM_ID: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(r#"\bSYSTEM\s+["']"#, "i").expect("valid XXE system regex")
});

/// `<!DOCTYPE x SYSTEM "…">` whose system identifier is anything but the HTML5
/// `about:legacy-compat` marker. Every `SYSTEM` inside the 200-character
/// window is tried, mirroring how a backtracking engine would retry.
fn has_external_doctype(value: &str) -> bool {
    const LEGACY_COMPAT: &[u8] = b"about:legacy-compat";
    let bytes = value.as_bytes();
    XXE_DOCTYPE.find_iter(bytes).any(|doctype| {
        // `<!DOCTYPE` + `[^>]{0,200}?`: SYSTEM starts within 200 bytes, before
        // any `>`.
        let latest_start = doctype.start() + "<!DOCTYPE".len() + 200;
        let tag_end = bytes[doctype.start()..]
            .iter()
            .position(|&b| b == b'>')
            .map_or(bytes.len(), |offset| doctype.start() + offset);
        XXE_SYSTEM_ID
            .find_iter(&bytes[..tag_end])
            .filter(|system| {
                (doctype.start()..=latest_start).contains(&system.start())
            })
            .any(|system| {
                let identifier = &bytes[system.end()..];
                identifier.len() < LEGACY_COMPAT.len()
                    || !identifier[..LEGACY_COMPAT.len()]
                        .eq_ignore_ascii_case(LEGACY_COMPAT)
            })
    })
}

/// Server-executable upload extensions.
const DANGEROUS_UPLOAD: &str = concat!(
    r"\.(?:php\d?|phtml|phps|pht|phar|aspx?|asa|asax|cer|cdx|jspx?|jsw|jsv|",
    r"shtml?|cgi|pl|py|rb|sh|bash|exe|dll|jar|war|bat|cmd|ps1|htaccess|",
    r"htpasswd)$",
);

/// Double extension (`shell.php.jpg`) and null-byte truncation.
const UPLOAD_EXTENSION_BYPASS: &str = concat!(
    r"\.(?:php\d?|phtml|phps|pht|phar|aspx?|jspx?|shtml?|cgi|exe|",
    r"sh)(?:\.[a-z0-9]{1,6})+$|\.(?:php\d?|aspx?|jspx?)\x00",
);

fn rules() -> Vec<WafRule> {
    let xxe_regex = re(XXE_ENTITY, "i");
    // A predicate sees the raw value, so it applies the JavaScript whitespace
    // view itself before running its regexes.
    let xxe = MatchPattern::predicate(move |value| {
        let view = js_regex_view(value);
        let view = view.as_deref().unwrap_or(value);
        matches_pattern_view(view, view, &xxe_regex)
            || has_external_doctype(view)
    });
    vec![
        WafRule::new(
            "preset-rfi",
            any_field_matches(
                &PAYLOAD_PATH_FIELDS,
                &re(STREAM_WRAPPER, "i"),
                &["://", "allow_url_"],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Low)
        .reason("Possible file inclusion via stream wrapper"),
        WafRule::new(
            "preset-rce-php",
            any_field_matches(
                &PAYLOAD_FIELDS,
                &re(PHP_RCE, "i"),
                &[
                    "eval",
                    "assert",
                    "preg_replace",
                    "xdebug_session_start",
                    "invokefunction",
                    "call_user_func",
                    "create_function",
                    "proc_open",
                    "popen",
                    "pcntl_exec",
                    "$_",
                ],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Low)
        .reason("Possible remote code execution payload"),
        WafRule::new(
            "preset-rfi-remote-url",
            any_field_matches(
                &PAYLOAD_PATH_FIELDS,
                &re(REMOTE_INCLUDE, "i"),
                &["://"],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Balanced)
        .reason("Possible remote file inclusion of a server-side script"),
        WafRule::new(
            "preset-rfi-include-syntax",
            any_field_matches(
                &PAYLOAD_FIELDS,
                &re(INCLUDE_SYNTAX, "i"),
                &["include", "require"],
            ),
            WafAction::Block,
        )
        .priority(52)
        .min_level(Balanced)
        .reason("PHP include / require syntax in request input"),
        WafRule::new(
            "preset-xxe-doctype",
            any_field_matches(
                &[WafField::Body, WafField::Query],
                &xxe,
                &["<!entity", "system", "public"],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(High)
        .reason("Possible XML external entity (XXE) injection"),
        WafRule::new(
            "preset-dangerous-upload",
            FieldCondition::new(WafField::Files)
                .matches(re(DANGEROUS_UPLOAD, "i")),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Balanced)
        .reason("Dangerous executable upload extension"),
        WafRule::new(
            "preset-upload-extension-bypass",
            FieldCondition::new(WafField::Files)
                .matches(re(UPLOAD_EXTENSION_BYPASS, "i")),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Balanced)
        .reason("Upload extension bypass (double extension / null byte)"),
    ]
}

static RULES: LazyLock<Vec<WafRule>> = LazyLock::new(rules);

/// The `rfi` preset.
pub fn rfi_rules() -> &'static [WafRule] {
    &RULES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_doctype_ignores_the_html5_legacy_marker() {
        assert!(has_external_doctype(
            r#"<!DOCTYPE x SYSTEM "//attacker/x"><x>a</x>"#
        ));
        assert!(!has_external_doctype(
            r#"<!DOCTYPE html SYSTEM "about:legacy-compat"><html></html>"#
        ));
        assert!(!has_external_doctype("<!DOCTYPE html><html></html>"));
        assert!(has_external_doctype(
            r#"<!doctype x system 'file:///etc/passwd'>"#
        ));
    }
}
