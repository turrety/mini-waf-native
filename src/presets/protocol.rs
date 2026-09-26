//! HTTP protocol and session-fixation heuristics (CRS REQUEST-920 / 921 / 943).

use std::sync::LazyLock;

use crate::domain::levels::ProtectionLevel::{
    Balanced,
    High,
    Paranoid,
};
use crate::domain::rules::{
    FieldCondition,
    MatchPattern,
    WafAction,
    WafCondition,
    WafField,
    WafRule,
};
use crate::presets::fields::{
    any_field_matches,
    re,
};
use crate::utils::ip::is_host_ip_literal;

const RESPONSE_SPLITTING: &str =
    r"[\r\n][^0-9A-Za-z_]*?(?:content-(?:type|length)|set-cookie|location)\s*:";
const REQUEST_SMUGGLING: &str = concat!(
    r"\b(?:get|p(?:ost|ut|atch)|head|options|delete|connect|",
    r"trace)\s+\S+\s+http\/[0-9]",
);
const CRLF_ENCODED_PATH: &str = concat!(
    r"%0[dD]%0[aA]|%0[aA]%0[dD]|%0[aAdD][^&#]{0,64}?(?:set-cookie|",
    r"content-(?:type|length|disposition)|location|refresh)\s*:",
);
const CRLF_DOUBLE_ENCODED: &str = concat!(
    r"%25(?:25)*(?:0[dDaA]|30[dDaA]|3[45])|%25%30%4[14]|%c0%8[aAdD]|",
    r"%e0%80%8[aAdD]|%e5%98%8[aAdD]|%u000[aAdD]",
);
const MAIL_COMMAND: &str = concat!(
    r"(?:[\r\n]|%0[aAdD]){1,3}\s*(?:RCPT\s+TO|MAIL\s+FROM|EHLO|HELO|",
    r"AUTH\s+LOGIN|STARTTLS|CAPABILITY|BDAT)\b",
);

/// Real IMAP traffic is `<tag> COMMAND`, with a short digit-bearing tag
/// (`V100`, `a001`) or `*` between the CR/LF and the verb. Requiring that tag
/// keeps multi-line prose ("…\nplease fetch the file") out.
const IMAP_COMMAND: &str = concat!(
    r"(?:[\r\n]|%0[aAdD]){1,3}[ \t]*(?:[A-Za-z0-9]*\d[A-Za-z0-9]*|",
    r"\*)[ \t]+(?:CAPABILITY|FETCH|LOGIN|LOGOUT|STARTTLS|AUTHENTICATE|",
    r"NAMESPACE|LSUB|EXPUNGE|UID)\b",
);

/// `\r\nQUIT\r\n` as sent to SMTP / POP3 / IMAP — only as a whole line.
const MAIL_TEARDOWN: &str =
    r"(?:[\r\n]|%0[aAdD])[ \t]*QUIT[ \t]*(?:[\r\n]|%0[aAdD]|$)";

const HEADER_INJECTION: &str = concat!(
    r"[\r\n]+(?:[\t ]|location|refresh|(?:set-)?cookie|host|via|",
    r"x-forwarded-(?:for|host|proto))\s*:",
);
const SESSION_FIXATION_HTML: &str = concat!(
    r#"\.cookie\b[^;]*;\s*(?:expires|domain)\s*=|"#,
    r#"\bhttp-equiv\s*=\s*["']?set-cookie\b"#,
);
const SESSION_ID_IN_URL: &str = concat!(
    r"[?&](?:phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|",
    r"laravel_session|_session_id|sessionid)=",
);
const MAIL_VERB: &str = concat!(
    r"\bRCPT\s+TO\s*:|\bMAIL\s+FROM\s*:|\bEHLO\s+[\w.-]|\bHELO\s+[\w.-]|",
    r"\bAUTH\s+LOGIN\b",
);

fn rules() -> Vec<WafRule> {
    let mail_fields = [WafField::Query, WafField::Body, WafField::Cookies];
    let path_and_url = [WafField::Path, WafField::Url];
    vec![
        WafRule::new(
            "preset-protocol-response-splitting",
            any_field_matches(
                &[
                    WafField::Query,
                    WafField::Body,
                    WafField::Cookies,
                    WafField::Path,
                ],
                &re(RESPONSE_SPLITTING, "i"),
                &["\r", "\n"],
            ),
            WafAction::Block,
        )
        .priority(45)
        .min_level(Balanced)
        .reason("Possible HTTP response splitting"),
        WafRule::new(
            "preset-protocol-request-smuggling",
            any_field_matches(
                &[WafField::Query, WafField::Body],
                &re(REQUEST_SMUGGLING, "i"),
                &["http/"],
            ),
            WafAction::Block,
        )
        .priority(45)
        .min_level(Balanced)
        .reason("Possible HTTP request smuggling probe"),
        WafRule::new(
            "preset-protocol-crlf-path",
            FieldCondition::new(WafField::Path)
                .matches(re(r"[\r\n]", ""))
                .requires(["\r", "\n"]),
            WafAction::Block,
        )
        .priority(45)
        .min_level(Balanced)
        .reason("CR/LF in request path"),
        WafRule::new(
            "preset-protocol-crlf-encoded-path",
            any_field_matches(
                &path_and_url,
                &re(CRLF_ENCODED_PATH, "i"),
                &["%0"],
            ),
            WafAction::Block,
        )
        .priority(45)
        .min_level(Balanced)
        .reason("Percent-encoded CR/LF in path or URL (response splitting)"),
        WafRule::new(
            "preset-protocol-crlf-double-encoded",
            any_field_matches(
                &path_and_url,
                &re(CRLF_DOUBLE_ENCODED, "i"),
                &["%25", "%c0", "%e0", "%e5", "%u00"],
            ),
            WafAction::Block,
        )
        .priority(45)
        .min_level(Balanced)
        .reason("Double-encoded or overlong CR/LF in path or URL"),
        WafRule::new(
            "preset-protocol-mail-command",
            any_field_matches(
                &mail_fields,
                &re(MAIL_COMMAND, "i"),
                &["\r", "\n", "%0"],
            ),
            WafAction::Block,
        )
        .priority(45)
        .min_level(High)
        .reason("Possible SMTP / IMAP command injection via CR/LF"),
        WafRule::new(
            "preset-protocol-imap-command",
            any_field_matches(
                &mail_fields,
                &re(IMAP_COMMAND, "i"),
                &["\r", "\n", "%0"],
            ),
            WafAction::Block,
        )
        .priority(45)
        .min_level(High)
        .reason("Possible IMAP command injection via CR/LF"),
        WafRule::new(
            "preset-protocol-mail-teardown",
            any_field_matches(&mail_fields, &re(MAIL_TEARDOWN, "i"), &["quit"]),
            WafAction::Block,
        )
        .priority(46)
        .min_level(High)
        .reason("Possible mail session teardown (QUIT) via CR/LF"),
        WafRule::new(
            "preset-protocol-header-injection",
            FieldCondition::new(WafField::Query)
                .matches(re(HEADER_INJECTION, "i"))
                .requires(["\r", "\n"]),
            WafAction::Block,
        )
        .priority(45)
        .min_level(High)
        .reason("Possible header injection via CR/LF in query"),
        WafRule::new(
            "preset-protocol-cl-te-conflict",
            WafCondition::all([
                FieldCondition::new(WafField::header("content-length"))
                    .matches(re(r"\S", ""))
                    .into(),
                FieldCondition::new(WafField::header("transfer-encoding"))
                    .matches(re(r"\S", ""))
                    .into(),
            ]),
            WafAction::Block,
        )
        .priority(40)
        .min_level(High)
        .reason("Content-Length and Transfer-Encoding both present"),
        WafRule::new(
            "preset-protocol-host-ip",
            FieldCondition::new(WafField::header("host"))
                .matches(MatchPattern::predicate(is_host_ip_literal)),
            WafAction::Block,
        )
        .priority(48)
        .min_level(High)
        .reason("Host header is a raw IP address"),
        WafRule::new(
            "preset-session-fixation-cookie-html",
            any_field_matches(
                &[WafField::Query, WafField::Body],
                &re(SESSION_FIXATION_HTML, "i"),
                &[".cookie", "http-equiv"],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Balanced)
        .reason("Possible session fixation via cookie HTML attributes"),
        WafRule::new(
            "preset-session-id-in-url",
            FieldCondition::new(WafField::Url)
                .matches(re(SESSION_ID_IN_URL, "i"))
                .requires([
                    "sessid",
                    "sessionid",
                    "connect.sid",
                    "laravel_session",
                    "_session_id",
                ]),
            WafAction::Block,
        )
        .priority(55)
        .min_level(High)
        .reason("Session identifier passed in URL query"),
        WafRule::new(
            "preset-protocol-mail-verb",
            any_field_matches(
                &[WafField::Query, WafField::Body],
                &re(MAIL_VERB, "i"),
                &["rcpt", "mail from", "ehlo", "helo", "auth login"],
            ),
            WafAction::Block,
        )
        .priority(46)
        .min_level(Paranoid)
        .reason("SMTP / IMAP command verb in request input"),
        WafRule::new(
            "preset-protocol-empty-ua",
            FieldCondition::new(WafField::header("user-agent")).equals(""),
            WafAction::Block,
        )
        .priority(60)
        .min_level(Paranoid)
        .reason("Empty or missing User-Agent"),
    ]
}

static RULES: LazyLock<Vec<WafRule>> = LazyLock::new(rules);

/// The `protocol` preset.
pub fn protocol_rules() -> &'static [WafRule] {
    &RULES
}
