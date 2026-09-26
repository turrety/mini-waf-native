//! Pattern matching and the regex dialect used by rules.

use std::fmt;

use regex::bytes::{
    Regex,
    RegexBuilder,
};

use crate::domain::rules::MatchPattern;

/// Compiled-program budget per pattern. The presets use bounded repetitions
/// such as `[\s\S]{0,160}?`, which need more room than the crate default.
const REGEX_SIZE_LIMIT: usize = 64 * 1024 * 1024;

/// Why a regex could not be compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegexError(pub String);

impl fmt::Display for RegexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RegexError {}

/// Compile a rule regex with JavaScript-style flags.
///
/// Patterns run over the raw UTF-8 bytes of each value with Unicode mode
/// **off** unless `u` or `v` is given. That matches JavaScript's default
/// semantics for rules (`\w`, `\d`, `\b` and case folding are ASCII) and keeps
/// the compiled automata small. Non-ASCII literals still match their UTF-8
/// encoding.
///
/// Supported flags: `i` (case-insensitive), `m` (multi-line anchors), `s`
/// (`.` matches newlines), `u` / `v` (Unicode classes). `g`, `y` and `d` are
/// accepted and ignored: a rule only asks whether the value matches.
///
/// The dialect is the [`regex`] crate's: linear-time, so no pattern can be
/// driven into catastrophic backtracking, but look-around and backreferences
/// are not supported.
pub fn compile_regex(pattern: &str, flags: &str) -> Result<Regex, RegexError> {
    validate_flags(flags)?;
    RegexBuilder::new(pattern)
        .unicode(flags.contains('u') || flags.contains('v'))
        .case_insensitive(flags.contains('i'))
        .multi_line(flags.contains('m'))
        .dot_matches_new_line(flags.contains('s'))
        // JavaScript's `.` and multi-line anchors treat `\r` as a line
        // terminator too.
        .crlf(true)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|error| RegexError(error.to_string()))
}

/// The value a rule regex actually runs on: `value` with JavaScript-only
/// whitespace mapped to ASCII, or `None` when there is none (the common case,
/// decided by one `is_ascii` scan).
///
/// Without the `u` flag, the `regex` crate's `\s` is ASCII-only, while
/// JavaScript's also matches NBSP, the `U+2000` spaces, `U+3000`, `U+FEFF`, …
/// which an attacker can use as a token separator (`UNION\u{A0}SELECT`).
/// Mapping them to a space (and the `U+2028` / `U+2029` line separators to
/// `\n`) gives `\s`, `\S`, `[^\s]`, `.` and `$` their JavaScript meaning
/// without touching the patterns themselves. Rewriting the patterns instead was
/// measured to defeat the crate's literal prefilters.
pub fn js_regex_view(value: &str) -> Option<String> {
    if value.is_ascii()
        || !value.chars().any(|ch| js_space_replacement(ch).is_some())
    {
        return None;
    }
    Some(
        value
            .chars()
            .map(|ch| js_space_replacement(ch).unwrap_or(ch))
            .collect(),
    )
}

fn js_space_replacement(c: char) -> Option<char> {
    match c {
        '\u{A0}'
        | '\u{1680}'
        | '\u{2000}'..='\u{200A}'
        | '\u{202F}'
        | '\u{205F}'
        | '\u{3000}'
        | '\u{FEFF}' => Some(' '),
        '\u{2028}' | '\u{2029}' => Some('\n'),
        _ => None,
    }
}

/// Reject unknown or duplicated regex flags, like JavaScript's `RegExp`.
pub(crate) fn validate_flags(flags: &str) -> Result<(), RegexError> {
    let mut seen = Vec::with_capacity(flags.len());
    for flag in flags.chars() {
        if !"dgimsuvy".contains(flag) {
            return Err(RegexError(format!("invalid regex flag \"{flag}\"")));
        }
        if seen.contains(&flag) {
            return Err(RegexError("duplicate regex flags".to_owned()));
        }
        seen.push(flag);
    }
    Ok(())
}

/// Test a candidate string against a match pattern.
pub fn matches_pattern(value: &str, pattern: &MatchPattern) -> bool {
    match pattern {
        MatchPattern::Regex(_) => {
            let view = js_regex_view(value);
            matches_pattern_view(
                value,
                view.as_deref().unwrap_or(value),
                pattern,
            )
        }
        _ => matches_pattern_view(value, value, pattern),
    }
}

/// [`matches_pattern`] with the [`js_regex_view`] of `value` already computed
/// (the engine memoizes it per field).
pub(crate) fn matches_pattern_view(
    value: &str,
    view: &str,
    pattern: &MatchPattern,
) -> bool {
    match pattern {
        MatchPattern::Exact(expected) => value == expected,
        MatchPattern::Regex(regex) => regex.is_match(view.as_bytes()),
        MatchPattern::OneOf(options) => {
            options.iter().any(|option| option == value)
        }
        MatchPattern::Predicate(predicate) => predicate.test(value),
    }
}

/// Case-insensitive substring check when both sides are already lowercased.
pub fn includes_lower(haystack_lower: &str, needle_lower: &str) -> bool {
    needle_lower.is_empty()
        || (needle_lower.len() <= haystack_lower.len()
            && haystack_lower.contains(needle_lower))
}

/// True when the lowercased haystack contains any of the lowercased needles.
/// Backs the `requires` prefilter.
pub fn contains_any_lower(
    haystack_lower: &str,
    needles_lower: &[String],
) -> bool {
    needles_lower
        .iter()
        .any(|needle| includes_lower(haystack_lower, needle))
}

/// Case-insensitive substring. Lowers both sides once per call.
pub fn includes_ignore_case(haystack: &str, needle: &str) -> bool {
    includes_lower(&haystack.to_lowercase(), &needle.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_every_pattern_kind() {
        assert!(MatchPattern::exact("abc").is_match("abc"));
        assert!(!MatchPattern::exact("abc").is_match("ab"));
        let regex = MatchPattern::regex_with_flags("foo", "g").unwrap();
        assert!(regex.is_match("foo") && regex.is_match("foo"));
        assert!(MatchPattern::one_of(["a", "b"]).is_match("b"));
        assert!(!MatchPattern::one_of(["a", "b"]).is_match("z"));
        let loopback = MatchPattern::predicate(|ip| ip.starts_with("127."));
        assert!(
            loopback.is_match("127.0.0.1") && !loopback.is_match("10.0.0.1")
        );
    }

    #[test]
    fn uses_ascii_semantics_by_default() {
        let word = MatchPattern::regex(r"^\w+$").unwrap();
        assert!(word.is_match("abc_1"));
        assert!(!word.is_match("ação"));
        let unicode = MatchPattern::regex_with_flags(r"^\w+$", "u").unwrap();
        assert!(unicode.is_match("ação"));
    }

    #[test]
    fn whitespace_follows_javascript() {
        let is = |pattern: &str, value: &str| {
            MatchPattern::regex_with_flags(pattern, "i")
                .unwrap()
                .is_match(value)
        };
        for space in [
            "\u{A0}", "\u{2003}", "\u{3000}", "\u{FEFF}", "\u{2028}", "\t",
            "\x0B",
        ] {
            assert!(
                is(r"union\s+select", &format!("UNION{space}SELECT")),
                "{space:?}"
            );
            assert!(!is(r"^\S$", space), "{space:?}");
            assert!(is(r"a[\s(]b", &format!("a{space}b")), "{space:?}");
            assert!(!is(r"^[^\s'<]+$", &format!("a{space}b")), "{space:?}");
        }
        assert!(is(r"^\S+$", "ação"));
        assert!(!is(r"^\s$", "\u{85}"));
        assert_eq!(js_regex_view("plain ascii"), None);
        assert_eq!(js_regex_view("ação"), None);
        assert_eq!(
            js_regex_view("a\u{A0}b\u{2028}c").as_deref(),
            Some("a b\nc")
        );
        // `.` stops at `\r` and the line separators, as in JavaScript.
        assert!(!is(r"a.b", "a\rb") && !is(r"a.b", "a\u{2028}b"));
        assert!(
            MatchPattern::regex_with_flags(r"a.b", "s")
                .unwrap()
                .is_match("a\rb")
        );
    }

    #[test]
    fn rejects_bad_flags() {
        assert!(compile_regex("a", "x").is_err());
        assert!(compile_regex("a", "ii").is_err());
        assert!(compile_regex("(", "").is_err());
    }

    #[test]
    fn substring_helpers() {
        assert!(includes_ignore_case("Hello World", "world"));
        assert!(!includes_ignore_case("Hello", "xyz"));
        assert!(includes_ignore_case("abc", ""));
        assert!(!includes_ignore_case("ab", "abc"));
        assert!(includes_lower("hello world", "world"));
        assert!(!includes_lower("hello world", "WORLD"));
    }
}
