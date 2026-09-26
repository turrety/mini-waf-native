//! `Cookie` request-header parsing.

use crate::domain::values::CookieMap;
use crate::utils::encoding::decode_uri_component;

/// Decodes one cookie value. Returning `None` keeps the raw value.
pub type CookieDecoder = dyn Fn(&str) -> Option<String>;

/// Parse a `Cookie` header into a name → value map.
///
/// The first occurrence of each name wins (browser / proxy duplicates) and
/// surrounding double quotes are stripped. Values are percent-decoded unless
/// another `decode` is given; a value that fails to decode is kept raw.
pub fn parse_cookies(
    header: Option<&str>,
    decode: Option<&CookieDecoder>,
) -> CookieMap {
    let decode = decode.unwrap_or(&decode_uri_component);
    let Some(header) = header.filter(|header| !header.is_empty()) else {
        return CookieMap::new();
    };
    header
        .split(';')
        .filter_map(|pair| {
            let (name, raw) = pair.split_once('=')?;
            let value = unquote(raw.trim());
            Some((
                name.trim().to_owned(),
                decode(value).unwrap_or_else(|| value.to_owned()),
            ))
        })
        .fold(CookieMap::new(), |mut cookies, (name, value)| {
            if cookies.get(&name).is_none() {
                cookies.insert(name, value);
            }
            cookies
        })
}

/// Strip one pair of surrounding double quotes (`"value"` → `value`).
fn unquote(value: &str) -> &str {
    match value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    {
        Some(inner) if value.len() >= 2 => inner,
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(map: &CookieMap) -> Vec<(&str, &str)> {
        map.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
    }

    #[test]
    fn returns_empty_for_missing_or_empty_header() {
        assert!(parse_cookies(None, None).is_empty());
        assert!(parse_cookies(Some(""), None).is_empty());
    }

    #[test]
    fn parses_multiple_cookies() {
        assert_eq!(
            pairs(&parse_cookies(Some("a=1; b=2; c=3"), None)),
            [("a", "1"), ("b", "2"), ("c", "3")]
        );
    }

    #[test]
    fn keeps_the_first_duplicate_and_strips_quotes() {
        assert_eq!(
            pairs(&parse_cookies(Some("id=first; id=second"), None)),
            [("id", "first")]
        );
        assert_eq!(
            pairs(&parse_cookies(Some("token=\"quoted\""), None)),
            [("token", "quoted")]
        );
    }

    #[test]
    fn skips_segments_without_equals() {
        assert_eq!(
            pairs(&parse_cookies(Some("alone; ok=1"), None)),
            [("ok", "1")]
        );
    }

    #[test]
    fn decodes_and_falls_back_to_raw() {
        assert_eq!(
            pairs(&parse_cookies(Some("q=hello%20world"), None)),
            [("q", "hello world")]
        );
        assert_eq!(
            pairs(&parse_cookies(Some("x=%E0%A4%A"), None)),
            [("x", "%E0%A4%A")]
        );
    }

    #[test]
    fn accepts_a_custom_decoder() {
        let upper = |v: &str| Some(v.to_uppercase());
        let map = parse_cookies(Some("role=admin"), Some(&upper));
        assert_eq!(pairs(&map), [("role", "ADMIN")]);
    }
}
