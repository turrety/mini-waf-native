//! Percent-decoding and Base64 helpers with JavaScript-compatible semantics.

/// Percent-decode like JavaScript's `decodeURIComponent`.
///
/// Returns `None` for a malformed escape (`%`, `%ZZ`) or when the decoded
/// bytes are not valid UTF-8 — the cases where `decodeURIComponent` throws.
/// `+` is left as-is, exactly like the JavaScript function.
pub fn decode_uri_component(input: &str) -> Option<String> {
    if !input.contains('%') {
        return Some(input.to_owned());
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = hex_value(*bytes.get(index + 1)?)?;
            let low = hex_value(*bytes.get(index + 2)?)?;
            out.push((high << 4) | low);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode a URL query component, where `+` also means a space
/// (`application/x-www-form-urlencoded`). Malformed escapes are kept verbatim.
pub fn decode_form_component(input: &str) -> String {
    let spaced = input.replace('+', " ");
    decode_uri_component(&spaced).unwrap_or(spaced)
}

fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode standard-alphabet Base64, padded or not.
///
/// Mirrors Node's lenient `Buffer.from(value, 'base64')` for well-formed input:
/// trailing `=` padding is optional and leftover bits are ignored. Returns
/// `None` when a non-alphabet character appears before the padding.
pub fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let body = input.trim_end_matches('=');
    let sextets: Vec<u8> = body.bytes().map(sextet).collect::<Option<_>>()?;
    let mut out = Vec::with_capacity(sextets.len() * 3 / 4);
    for chunk in sextets.chunks(4) {
        match *chunk {
            [a, b, c, d] => {
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
                out.push((c << 6) | d);
            }
            [a, b, c] => {
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
            }
            [a, b] => out.push((a << 2) | (b >> 4)),
            // A single trailing sextet carries fewer than 8 bits: ignored.
            _ => {}
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_uri_components_like_javascript() {
        assert_eq!(
            decode_uri_component("hello%20world").as_deref(),
            Some("hello world")
        );
        assert_eq!(decode_uri_component("a+b").as_deref(), Some("a+b"));
        assert_eq!(decode_uri_component("%E2%9C%93").as_deref(), Some("✓"));
        assert_eq!(decode_uri_component("100%"), None);
        assert_eq!(decode_uri_component("bad %ZZ"), None);
        assert_eq!(decode_uri_component("%E0%A4%A"), None);
        assert_eq!(
            decode_uri_component("%C0%AF"),
            None,
            "overlong UTF-8 is rejected"
        );
    }

    #[test]
    fn decodes_form_components() {
        assert_eq!(decode_form_component("a+b%21"), "a b!");
        assert_eq!(decode_form_component("50%"), "50%");
    }

    #[test]
    fn decodes_padded_and_unpadded_base64() {
        assert_eq!(decode_base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode_base64("aGVsbG8").unwrap(), b"hello");
        assert_eq!(decode_base64("aGk").unwrap(), b"hi");
        assert!(decode_base64("a*b").is_none());
    }
}
