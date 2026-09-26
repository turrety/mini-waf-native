//! Reflected / stored XSS and SSI payloads.

use std::sync::LazyLock;

use crate::domain::levels::ProtectionLevel::{
    Balanced,
    High,
    Paranoid,
};
use crate::domain::rules::{
    FieldCondition,
    WafAction,
    WafField,
    WafRule,
};
use crate::presets::fields::{
    PAYLOAD_FIELDS,
    any_field_matches,
    re,
};

/// Inline script / handler injection shared by query, cookies and path.
const XSS_CORE: &str = concat!(
    r"(<\s*script\b|(?:java|vb)script\s*:|on\w+\s*=|<\s*img\b[^>]*\bonerror\b|",
    r"<\s*svg\b[^>]*\bonload\b|\bdocument\s*(?:\?\.|\.)\s*(?:cookie|location|",
    r"write(?:ln)?)\b)",
);

/// Body variant: no `<svg onload>` / `document.location` arms.
const XSS_BODY: &str = concat!(
    r"(<\s*script\b|(?:java|vb)script\s*:|on\w+\s*=|<\s*img\b[^>]*\bonerror\b|",
    r"\bdocument\s*(?:\?\.|\.)\s*(?:cookie|write(?:ln)?)\b)",
);

const XSS_HEADERS: &str = r"(<\s*script\b|(?:java|vb)script\s*:)";

/// Percent- / entity- / unicode-encoded `<script` (CRS 941100 variants).
const XSS_ENCODED_TAG: &str = concat!(
    r"(?:%3[cC]|&lt;|&#0{0,3}60;?|&#[xX]0{0,3}3[cC];?|\\u0{0,2}3[cC]|",
    r"\\x3[cC])\s*(?:%2[fF]|\/)?\s*(?:script|img|svg|iframe|body|object|",
    r"embed)\b",
);

/// URI schemes that render attacker-controlled markup or code.
/// `data:image/png` and friends are deliberately not matched.
const XSS_DANGEROUS_URI: &str = concat!(
    r"\bdata\s*:\s*(?:text\/html|image\/svg\+xml|",
    r"application\/(?:x-)?(?:javascript|ecmascript)|text\/javascript)",
);

/// Attribute vectors without an `on*` prefix (CRS 941150 / 941210).
const XSS_ATTRIBUTE_VECTOR: &str = concat!(
    r#"(?:\b(?:srcdoc|formaction|dynsrc|lowsrc)\s*=|\bxlink\s*:\s*href\s*=|"#,
    r#"\bexpression\s*\(\s*[^)]{0,60}\)|"#,
    r#"\battributeName\s*=\s*["']?\s*(?:href|xlink:href|values|from|to)\b|"#,
    r#"<\s*set\b[^>]{0,120}\battributeName\b)"#,
);

/// JavaScript primitives used to decode, build or exfiltrate a payload.
/// `High`: CMS and snippet-sharing apps legitimately post JS text.
const XSS_JS_PRIMITIVES: &str = concat!(
    r#"(?:\bString\s*\.\s*fromCharCode\s*\(|\batob\s*\(|\bunescape\s*\(|"#,
    r#"\bFunction\s*\(\s*["'`]|\b(?:window|top|self|"#,
    r#"parent)\s*\.\s*(?:location|name|document)\b|"#,
    r#"\bdocument\s*\.\s*domain\b|\bnavigator\s*\.\s*sendBeacon\s*\(|"#,
    r#"\bXMLHttpRequest\b|\bimport\s*\(\s*["'`]\s*(?:https?:|\/\/))"#,
);

const SSI_INJECTION: &str =
    r"<!--#\s*(?:config|echo|exec|flastmod|fsize|include)\b";

const GENERIC_HTML_TAG: &str = concat!(
    r"<\s*(?:iframe|object|embed|link|meta|base|form|svg|math|foreignobject|",
    r"template|marquee|details|portal|frame(?:set)?)\b",
);

const EVAL_ALERT: &str = r"\b(?:eval|alert|prompt|confirm)\s*\(";

/// Indirect sink calls: `alert.call(0,1)`, ``alert`1` ``, `alert?.(1)`,
/// `(alert)(1)`.
const XSS_INDIRECT_CALL: &str = concat!(
    r"\b(?:alert|prompt|confirm|eval)\s*(?:\.\s*(?:call|apply|bind)\s*\(|",
    r"\?\.\s*[(`]|`)|\(\s*(?:alert|prompt|confirm|eval)\s*\)\s*[`(]",
);

/// A quote / bracket breaking out of a string context straight into a sink.
const XSS_BREAKOUT_CALL: &str =
    r#"['"`]\s*[-+;,)}\]>]\s*(?:alert|prompt|confirm|eval)\s*(?:\?\.)?\s*[(`]"#;

fn rules() -> Vec<WafRule> {
    let core = re(XSS_CORE, "i");
    let payload_and_path = [
        WafField::Query,
        WafField::Body,
        WafField::Cookies,
        WafField::Path,
    ];
    let sinks = ["alert", "prompt", "confirm", "eval"];
    vec![
        WafRule::new(
            "preset-xss-query",
            FieldCondition::new(WafField::Query).matches(core.clone()),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Balanced)
        .reason("Possible XSS in query string"),
        WafRule::new(
            "preset-xss-body",
            FieldCondition::new(WafField::Body).matches(re(XSS_BODY, "i")),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Balanced)
        .reason("Possible XSS in body"),
        WafRule::new(
            "preset-xss-headers",
            FieldCondition::new(WafField::Headers)
                .matches(re(XSS_HEADERS, "i")),
            WafAction::Block,
        )
        .priority(55)
        .min_level(Balanced)
        .reason("Possible XSS in headers"),
        WafRule::new(
            "preset-xss-cookies",
            FieldCondition::new(WafField::Cookies).matches(core.clone()),
            WafAction::Block,
        )
        .priority(55)
        .min_level(Balanced)
        .reason("Possible XSS in cookies"),
        WafRule::new(
            "preset-xss-path",
            FieldCondition::new(WafField::Path).matches(core),
            WafAction::Block,
        )
        .priority(55)
        .min_level(Balanced)
        .reason("Possible XSS in path"),
        WafRule::new(
            "preset-xss-encoded-tag",
            any_field_matches(
                &payload_and_path,
                &re(XSS_ENCODED_TAG, "i"),
                &["%3c", "&lt;", "&#", "\\u", "\\x3"],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Balanced)
        .reason("Encoded HTML tag used to evade XSS filtering"),
        WafRule::new(
            "preset-xss-dangerous-uri",
            any_field_matches(
                &payload_and_path,
                &re(XSS_DANGEROUS_URI, "i"),
                &["data"],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(Balanced)
        .reason("Renderable data: URI (HTML / SVG / JavaScript)"),
        WafRule::new(
            "preset-xss-attribute-vector",
            any_field_matches(
                &PAYLOAD_FIELDS,
                &re(XSS_ATTRIBUTE_VECTOR, "i"),
                &[
                    "srcdoc",
                    "formaction",
                    "dynsrc",
                    "lowsrc",
                    "xlink",
                    "expression",
                    "attributename",
                    "<set",
                ],
            ),
            WafAction::Block,
        )
        .priority(52)
        .min_level(Balanced)
        .reason("Possible XSS via HTML attribute vector"),
        WafRule::new(
            "preset-ssi-injection",
            any_field_matches(
                &[
                    WafField::Query,
                    WafField::Body,
                    WafField::Path,
                    WafField::Cookies,
                ],
                &re(SSI_INJECTION, "i"),
                &["<!--#"],
            ),
            WafAction::Block,
        )
        .priority(50)
        .min_level(High)
        .reason("Possible SSI command injection"),
        WafRule::new(
            "preset-xss-js-primitives",
            any_field_matches(
                &PAYLOAD_FIELDS,
                &re(XSS_JS_PRIMITIVES, "i"),
                &[],
            ),
            WafAction::Block,
        )
        .priority(55)
        .min_level(High)
        .reason("JavaScript primitive used to decode or exfiltrate a payload"),
        WafRule::new(
            "preset-xss-generic-tags",
            any_field_matches(
                &[WafField::Query, WafField::Body],
                &re(GENERIC_HTML_TAG, "i"),
                &["<"],
            ),
            WafAction::Block,
        )
        .priority(55)
        .min_level(Paranoid)
        .reason("Generic HTML tag in request (paranoid XSS)"),
        WafRule::new(
            "preset-xss-indirect-call",
            any_field_matches(
                &payload_and_path,
                &re(XSS_INDIRECT_CALL, "i"),
                &sinks,
            ),
            WafAction::Block,
        )
        .priority(55)
        .min_level(High)
        .reason(concat!(
            "Possible XSS via indirect sink call ",
            "(call/apply/optional chaining)",
        )),
        WafRule::new(
            "preset-xss-breakout-call",
            any_field_matches(
                &payload_and_path,
                &re(XSS_BREAKOUT_CALL, "i"),
                &sinks,
            ),
            WafAction::Block,
        )
        .priority(55)
        .min_level(High)
        .reason(
            "Possible XSS breakout from a string/attribute into a sink call",
        ),
        WafRule::new(
            "preset-xss-eval-alert",
            any_field_matches(
                &[WafField::Query, WafField::Body],
                &re(EVAL_ALERT, "i"),
                &[],
            ),
            WafAction::Block,
        )
        .priority(55)
        .min_level(Paranoid)
        .reason("Possible eval/alert XSS probe"),
    ]
}

static RULES: LazyLock<Vec<WafRule>> = LazyLock::new(rules);

/// The `xss` preset.
pub fn xss_rules() -> &'static [WafRule] {
    &RULES
}
