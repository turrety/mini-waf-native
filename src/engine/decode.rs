//! Transport decoders.
//!
//! Decoding is a *matching-only* concern: decoded variants are appended to the
//! candidate bag scanned by `matches` / `includes`, never to rate-limit key
//! material or `equals` semantics. Existing rules therefore scan the decoded
//! form with zero rule changes.

use std::ops::RangeInclusive;

use crate::domain::values::JsonValue;
use crate::utils::encoding::{
    decode_base64,
    decode_form_component,
    decode_uri_component,
};

/// Which decoders run, resolved once per engine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeSettings {
    /// Decode whole-value Base64 payloads (e.g. GoTestWAF `Base64Flat`).
    pub base64: bool,
    /// Percent-decode values the framework did not decode (path, raw body).
    pub url: bool,
    /// Strip inline SQL comments used as token separators.
    pub comments: bool,
}

impl DecodeSettings {
    pub fn any(self) -> bool {
        self.base64 || self.url || self.comments
    }
}

/// Minimum length before a value is even considered Base64. Short tokens carry
/// no useful payload once decoded and are the noisiest false-positive source.
const MIN_BASE64_LENGTH: usize = 16;

/// Hard cap on decoded candidates produced per field per request.
const MAX_DECODED_CANDIDATES: usize = 16;

/// Maximum fraction of non-printable bytes tolerated in decoded output. This
/// is the load-bearing gate: high-entropy identifiers (dashless UUIDs, hashes,
/// encrypted cookies) decode to binary noise and are rejected here.
const MAX_NONPRINTABLE_RATIO: f64 = 0.1;

/// Whole-value standard Base64 shape: `^[A-Za-z0-9+/]+={0,2}$`, length at least
/// [`MIN_BASE64_LENGTH`] and not `≡ 1 (mod 4)` (the one impossible length;
/// unpadded blobs are common, so a multiple of four is not required).
fn looks_like_base64(value: &str) -> bool {
    let length = value.len();
    if length < MIN_BASE64_LENGTH || length % 4 == 1 {
        return false;
    }
    let body = value.trim_end_matches('=');
    let padding = length - body.len();
    padding <= 2 && !body.is_empty() && body.bytes().all(is_base64_byte)
}

fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
}

/// Printable ASCII plus tab, line feed and carriage return.
fn is_printable(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7e)
}

/// Whether at most [`MAX_NONPRINTABLE_RATIO`] of the bytes are non-printable.
/// Bails as soon as the budget is exceeded, so binary blobs fail in the first
/// few bytes.
fn is_mostly_printable(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let budget = (bytes.len() as f64 * MAX_NONPRINTABLE_RATIO).floor() as usize;
    let mut non_printable = 0;
    bytes.iter().all(|&byte| {
        non_printable += usize::from(!is_printable(byte));
        non_printable <= budget
    })
}

fn decode_base64_text(value: &str) -> Option<String> {
    let bytes = decode_base64(value)?;
    if !is_mostly_printable(&bytes) {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Expand candidate values with their Base64-decoded forms.
///
/// A cost funnel: the shape test rejects nearly all benign text, the length
/// cap bounds fan-out, and the printable-ratio gate rejects non-text blobs
/// before the regex battery ever sees them.
pub fn expand_base64_candidates(
    values: &[String],
    settings: DecodeSettings,
) -> Vec<String> {
    if !settings.base64 {
        return Vec::new();
    }
    values
        .iter()
        .filter(|value| looks_like_base64(value))
        .take(MAX_DECODED_CANDIDATES)
        .filter_map(|value| decode_base64_text(value))
        .collect()
}

/// Percent-decode once, only when it can change something and succeeds.
fn decode_url_once(value: &str) -> Option<String> {
    if !value.contains('%') {
        return None;
    }
    decode_uri_component(value).filter(|decoded| decoded != value)
}

/// Expand candidate values with their percent-decoded forms. Clean traffic
/// pays one `contains('%')` per value.
pub fn expand_url_candidates(
    values: &[String],
    settings: DecodeSettings,
) -> Vec<String> {
    if !settings.url {
        return Vec::new();
    }
    values
        .iter()
        .filter_map(|value| decode_url_once(value))
        .take(MAX_DECODED_CANDIDATES)
        .collect()
}

/// Longest comment body treated as a separator. Longer comments are prose in
/// posted code, not evasion, and are left intact.
const MAX_SEPARATOR_COMMENT: usize = 32;

/// Replace each short inline SQL comment (`/**/`, `/*a*/`) with one space so
/// `SELECT/**/value/**/FROM` collapses to `SELECT value FROM`.
///
/// Versioned comments (`/*!50000SELECT*/`) are preserved: the database
/// executes their body, and `preset-sqli-versioned-comment` already catches
/// them. Returns `None` when nothing changed.
fn strip_inline_sql_comments(value: &str) -> Option<String> {
    if !value.contains("/*") {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut copied_until = 0;
    let mut index = 0;
    while index + 1 < bytes.len() {
        match separator_comment_end(bytes, index) {
            Some(end) => {
                out.push_str(&value[copied_until..index]);
                out.push(' ');
                index = end;
                copied_until = end;
            }
            None => index += 1,
        }
    }
    if copied_until == 0 {
        return None;
    }
    out.push_str(&value[copied_until..]);
    Some(out)
}

/// When a separator comment opens at `start` — `/*`, not versioned (`/*!`),
/// a body without `*` of at most [`MAX_SEPARATOR_COMMENT`] bytes, then `*/`
/// — the index just past it.
fn separator_comment_end(bytes: &[u8], start: usize) -> Option<usize> {
    let rest = &bytes[start..];
    if !rest.starts_with(b"/*") || rest.get(2) == Some(&b'!') {
        return None;
    }
    let star = 2 + rest[2..]
        .iter()
        .take(MAX_SEPARATOR_COMMENT + 1)
        .position(|&byte| byte == b'*')?;
    (rest.get(star + 1) == Some(&b'/')).then_some(start + star + 2)
}

/// Expand candidate values with their comment-stripped forms.
pub fn expand_comment_candidates(
    values: &[String],
    settings: DecodeSettings,
) -> Vec<String> {
    if !settings.comments {
        return Vec::new();
    }
    values
        .iter()
        .filter_map(|value| strip_inline_sql_comments(value))
        .take(MAX_DECODED_CANDIDATES)
        .collect()
}

/// Bound the path split so a pathological path cannot fan the rescan out.
const MAX_PATH_SEGMENTS: usize = 24;

/// Split a URL path into segments long enough to carry a Base64 payload, so
/// `/download/<blob>` becomes a whole-value decoder candidate.
pub fn extract_path_segments(raw: &str) -> Vec<String> {
    if !raw.contains('/') {
        return Vec::new();
    }
    raw.split('/')
        .filter(|segment| segment.len() >= MIN_BASE64_LENGTH)
        .take(MAX_PATH_SEGMENTS)
        .map(str::to_owned)
        .collect()
}

/// Cap on the values pulled out of one body (JSON leaves, form values,
/// multipart fields).
const MAX_BODY_VALUES: usize = 64;
const MAX_JSON_DEPTH: usize = 6;

fn collect_json_strings(node: &JsonValue, depth: usize, out: &mut Vec<String>) {
    if out.len() >= MAX_BODY_VALUES {
        return;
    }
    match node {
        JsonValue::String(text) if text.len() >= MIN_BASE64_LENGTH => {
            out.push(text.clone())
        }
        JsonValue::Array(_) | JsonValue::Object(_)
            if depth >= MAX_JSON_DEPTH => {}
        JsonValue::Array(items) => items
            .iter()
            .for_each(|item| collect_json_strings(item, depth + 1, out)),
        JsonValue::Object(entries) => entries
            .iter()
            .for_each(|(_, item)| collect_json_strings(item, depth + 1, out)),
        _ => {}
    }
}

/// The body parsed as JSON. Gated by a one-character sniff, so non-JSON
/// bodies pay nothing beyond that check.
fn parse_json_body(raw: &str) -> Option<JsonValue> {
    if !matches!(
        raw.trim_start().as_bytes().first(),
        Some(b'{' | b'[' | b'"')
    ) {
        return None;
    }
    JsonValue::parse(raw).ok()
}

fn json_string_values(parsed: &JsonValue) -> Vec<String> {
    let mut out = Vec::new();
    collect_json_strings(parsed, 0, &mut out);
    out
}

/// The delimiter line of a `multipart/form-data` body (`--<boundary>`), when
/// the body starts with one.
fn multipart_delimiter(raw: &str) -> Option<&str> {
    if !raw.starts_with("--") {
        return None;
    }
    let line = raw.split(['\r', '\n']).next()?;
    let valid = line.len() > 2 && !line.contains(char::is_whitespace);
    valid.then_some(line)
}

/// The contents of a multipart body's form fields. File parts are skipped:
/// frameworks hand them over as uploads, not as body values.
fn multipart_values(raw: &str, delimiter: &str) -> Vec<String> {
    raw.split(delimiter)
        .skip(1)
        .take_while(|part| !part.starts_with("--"))
        .filter_map(|part| {
            let part = part.trim_start_matches(['\r', '\n']);
            let (headers, content) = part
                .split_once("\r\n\r\n")
                .or_else(|| part.split_once("\n\n"))?;
            let is_file = headers.to_ascii_lowercase().contains("filename=");
            (!is_file).then(|| content.trim_end_matches(['\r', '\n']))
        })
        .filter(|content| content.len() >= MIN_BASE64_LENGTH)
        .take(MAX_BODY_VALUES)
        .map(str::to_owned)
        .collect()
}

/// A body shaped like `application/x-www-form-urlencoded`: it holds a `=`
/// and is not markup (XML attributes hold `=` too).
fn looks_like_form(raw: &str) -> bool {
    raw.contains('=') && !raw.trim_start().starts_with('<')
}

/// The form-decoded values of a urlencoded body.
fn form_values(raw: &str) -> Vec<String> {
    raw.split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(_, value)| decode_form_component(value))
        .filter(|value| value.len() >= MIN_BASE64_LENGTH)
        .take(MAX_BODY_VALUES)
        .collect()
}

/// What a raw body hides a payload in, beyond its own text.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BodyValues {
    /// Long JSON string leaves, form values or multipart field contents:
    /// decoder input, since a payload in one of them is not a whole-value
    /// blob inside the body.
    pub values: Vec<String>,
    /// The JSON strings (keys and values) written with `\u` or `\/` escapes,
    /// decoded: the text the application receives, which the raw body only
    /// shows escaped.
    pub escaped: Vec<String>,
}

/// Whether the `"` at `quote` is unescaped: an odd run of backslashes before
/// it escapes it.
fn is_unescaped_quote(bytes: &[u8], quote: usize) -> bool {
    if bytes[quote] != b'"' {
        return false;
    }
    let backslashes = bytes[..quote]
        .iter()
        .rev()
        .take_while(|&&byte| byte == b'\\')
        .count();
    backslashes % 2 == 0
}

/// The next `\u` or `\/` escape at or after `from`. Walks escape by escape,
/// so the second backslash of `\\` never starts one.
fn next_hiding_escape(raw: &str, from: usize) -> Option<usize> {
    let mut at = from;
    loop {
        at += raw.get(at..)?.find('\\')?;
        if matches!(raw.as_bytes().get(at + 1), Some(b'u' | b'/')) {
            return Some(at);
        }
        at += 2;
    }
}

/// The byte range of the string literal (quotes included) holding the byte
/// at `inside`. In valid JSON a backslash only occurs inside a string, and
/// every `"` inside one is escaped, so the nearest unescaped quotes around it
/// delimit it.
fn enclosing_literal(
    bytes: &[u8],
    inside: usize,
) -> Option<RangeInclusive<usize>> {
    let start = (0..inside)
        .rev()
        .find(|&index| is_unescaped_quote(bytes, index))?;
    let end = (inside..bytes.len())
        .find(|&index| is_unescaped_quote(bytes, index))?;
    Some(start..=end)
}

/// The JSON strings (keys and values) written with `\u` or `\/` escapes,
/// decoded by the JSON parser. Only valid JSON reaches here, so each escape
/// is found directly and nothing else in the body is walked. Capped like
/// every decoder's output.
fn escaped_json_strings(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    while out.len() < MAX_DECODED_CANDIDATES {
        let Some(literal) = next_hiding_escape(raw, from)
            .and_then(|escape| enclosing_literal(raw.as_bytes(), escape))
        else {
            break;
        };
        from = literal.end() + 1;
        if let Some(Ok(JsonValue::String(text))) =
            raw.get(literal).map(JsonValue::parse)
        {
            out.push(text);
        }
    }
    out
}

/// Split a raw body the way a framework's body parsers would: JSON, then
/// multipart, then urlencoded form. A body the framework already parsed
/// arrives as JSON and takes the first branch.
pub fn extract_body_values(raw: &str) -> BodyValues {
    if let Some(parsed) = parse_json_body(raw) {
        return BodyValues {
            values: json_string_values(&parsed),
            escaped: escaped_json_strings(raw),
        };
    }
    let values = match multipart_delimiter(raw) {
        Some(delimiter) => multipart_values(raw, delimiter),
        None if looks_like_form(raw) => form_values(raw),
        None => Vec::new(),
    };
    BodyValues {
        values,
        escaped: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ON_BASE64: DecodeSettings = DecodeSettings {
        base64: true,
        url: false,
        comments: false,
    };
    const ON_URL: DecodeSettings = DecodeSettings {
        base64: false,
        url: true,
        comments: false,
    };
    const ON_COMMENTS: DecodeSettings = DecodeSettings {
        base64: false,
        url: false,
        comments: true,
    };
    const OFF: DecodeSettings = DecodeSettings {
        base64: false,
        url: false,
        comments: false,
    };

    pub(crate) fn b64(text: &str) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = text.as_bytes();
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            let sextets =
                [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
            for (index, sextet) in sextets.iter().enumerate() {
                if index <= chunk.len() {
                    out.push(ALPHABET[*sextet as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn base64_is_off_unless_enabled() {
        assert!(
            expand_base64_candidates(
                &strings(&[&b64("union select 1,2")]),
                OFF
            )
            .is_empty()
        );
    }

    #[test]
    fn base64_decodes_whole_value_blobs() {
        let blob = b64("union select pass from users");
        assert_eq!(
            expand_base64_candidates(&[blob], ON_BASE64),
            ["union select pass from users"]
        );
    }

    #[test]
    fn base64_ignores_short_values_and_impossible_lengths() {
        assert!(
            expand_base64_candidates(&strings(&["YWJj"]), ON_BASE64).is_empty()
        );
        assert!(
            expand_base64_candidates(&["A".repeat(17)], ON_BASE64).is_empty()
        );
    }

    #[test]
    fn base64_decodes_unpadded_blobs() {
        let unpadded = b64("<body onload=alert(1)>")
            .trim_end_matches('=')
            .to_owned();
        assert_ne!(unpadded.len() % 4, 0);
        assert_eq!(
            expand_base64_candidates(&[unpadded], ON_BASE64),
            ["<body onload=alert(1)>"]
        );
    }

    #[test]
    fn base64_rejects_non_alphabet_values_and_binary_noise() {
        assert!(
            expand_base64_candidates(
                &strings(&["union select from a"]),
                ON_BASE64
            )
            .is_empty()
        );
        assert!(
            expand_base64_candidates(
                &strings(&["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.ab"]),
                ON_BASE64
            )
            .is_empty()
        );
        assert!(
            expand_base64_candidates(
                &strings(&["550e8400e29b41d4a716446655440000"]),
                ON_BASE64
            )
            .is_empty()
        );
    }

    #[test]
    fn base64_caps_fan_out() {
        let many: Vec<String> = (0..40)
            .map(|index| {
                b64(&format!("benign payload number {index} padded out"))
            })
            .collect();
        assert!(expand_base64_candidates(&many, ON_BASE64).len() <= 16);
    }

    #[test]
    fn url_decodes_only_when_it_changes_something() {
        assert!(
            expand_url_candidates(&strings(&["%3Cscript%3E"]), OFF).is_empty()
        );
        assert_eq!(
            expand_url_candidates(
                &strings(&["%3Cimg%20src%3Dx%20onerror%3D1%3E"]),
                ON_URL
            ),
            ["<img src=x onerror=1>"]
        );
        assert!(
            expand_url_candidates(
                &strings(&["plain value", "a=b&c=d"]),
                ON_URL
            )
            .is_empty()
        );
        assert!(
            expand_url_candidates(
                &strings(&["100% pure", "bad %ZZ seq"]),
                ON_URL
            )
            .is_empty()
        );
        let many: Vec<String> =
            (0..40).map(|index| format!("%3Cx{index}%3E")).collect();
        assert!(expand_url_candidates(&many, ON_URL).len() <= 16);
    }

    #[test]
    fn comments_collapse_separator_comments() {
        assert!(
            expand_comment_candidates(&strings(&["1/**/UNION/**/SELECT"]), OFF)
                .is_empty()
        );
        assert_eq!(
            expand_comment_candidates(
                &strings(&["SELECT/**/value/**/FROM/**/secrets"]),
                ON_COMMENTS
            ),
            ["SELECT value FROM secrets"]
        );
        assert_eq!(
            expand_comment_candidates(
                &strings(&["1/*x*/AND/*y*/2=2"]),
                ON_COMMENTS
            ),
            ["1 AND 2=2"]
        );
    }

    #[test]
    fn comments_preserve_versioned_and_long_comments() {
        assert!(
            expand_comment_candidates(
                &strings(&["1/*!50000UNION*/SELECT"]),
                ON_COMMENTS
            )
            .is_empty()
        );
        let long =
            "x /* this is a long explanatory comment about the code */ y";
        assert!(
            expand_comment_candidates(&strings(&[long]), ON_COMMENTS)
                .is_empty()
        );
        assert!(
            expand_comment_candidates(
                &strings(&["plain value", "a/b path"]),
                ON_COMMENTS
            )
            .is_empty()
        );
    }

    fn body_values(raw: &str) -> Vec<String> {
        extract_body_values(raw).values
    }

    #[test]
    fn json_strings_are_extracted() {
        let blob = b64("1 UNION SELECT a FROM b");
        assert!(body_values(&format!(r#"{{"q":"{blob}"}}"#)).contains(&blob));
        let nested = b64("<body onload=alert(1)> padding here");
        assert!(
            body_values(&format!(r#"{{"a":{{"b":["{nested}"]}}}}"#))
                .contains(&nested)
        );
        assert!(body_values(r#"{"a":"short","b":"tiny"}"#).is_empty());
        assert!(body_values("{ not valid json").is_empty());
    }

    #[test]
    fn escaped_json_strings_are_decoded() {
        let escaped = |raw: &str| extract_body_values(raw).escaped;
        assert_eq!(
            escaped(r#"{"test": true, "q": "\u003cscript\u003e\/x"}"#),
            ["<script>/x"]
        );
        // Keys count, and a duplicate key a parser would drop is still seen.
        assert_eq!(
            escaped(r#"{"\u0071": 1, "q": "\u0027 or 1=1", "q": "x"}"#),
            ["q", "' or 1=1"]
        );
        assert_eq!(escaped(r#"["\ud83d\ude00", "plain"]"#), ["😀"]);
    }

    #[test]
    fn strings_without_hiding_escapes_are_skipped() {
        let escaped = |raw: &str| extract_body_values(raw).escaped;
        assert!(escaped(r#"{"q": "<b>", "r": "a\nb \"c\""}"#).is_empty());
        assert!(escaped(r#"{"path": "C:\\users\\u0041"}"#).is_empty());
        assert!(escaped(r"a=\u003c").is_empty());
    }

    #[test]
    fn form_values_are_extracted_and_decoded() {
        let blob = b64("1 UNION SELECT a FROM b");
        assert_eq!(body_values(&format!("x=1&q={blob}")), [blob]);
        assert_eq!(
            body_values("q=union+select%20password+from+users"),
            ["union select password from users"]
        );
        assert!(body_values("name=value&other=thing").is_empty());
        assert!(body_values(r#"<a href="0123456789abcdefgh">"#).is_empty());
    }

    #[test]
    fn multipart_fields_are_extracted_but_not_files() {
        let blob = b64("1 UNION SELECT a FROM b");
        let body = format!(
            "--XyZ\r\n\
             Content-Disposition: form-data; name=\"q\"\r\n\r\n\
             {blob}\r\n\
             --XyZ\r\n\
             Content-Disposition: form-data; name=\"f\"; \
             filename=\"a.txt\"\r\n\r\n\
             {}\r\n\
             --XyZ--\r\n",
            b64("file contents are not body values")
        );
        assert_eq!(body_values(&body), [blob]);
        assert!(body_values("--not a delimiter\r\n").is_empty());
    }

    #[test]
    fn path_segments_are_extracted() {
        let blob = b64("<body onload=alert(1)> path payload");
        assert!(
            extract_path_segments(&format!("/download/{blob}")).contains(&blob)
        );
        assert!(extract_path_segments("/a/b/c/short").is_empty());
        assert!(extract_path_segments("noslashhere-but-long").is_empty());
    }
}
