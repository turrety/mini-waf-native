//! Request fingerprints for the optional decision cache.

use crate::domain::context::WafHttpContext;
use crate::domain::values::HeaderValue;

/// djb2 over UTF-16 code units, as unsigned hex — the same value the
/// JavaScript implementation produces for the same string.
pub fn hash_string(input: &str) -> String {
    let hash = input.encode_utf16().fold(5381i32, |hash, unit| {
        (hash << 5).wrapping_add(hash).wrapping_add(i32::from(unit))
    });
    format!("{:x}", hash as u32)
}

/// Compact fingerprint: method, path, IP, and hashes of the sorted query, the
/// user agent and the first `body_hash_max` characters of the body.
pub fn request_fingerprint(
    ctx: &dyn WafHttpContext,
    body_hash_max: usize,
) -> String {
    [
        ctx.get_method().to_owned(),
        ctx.get_path().to_owned(),
        ctx.get_ip().to_owned(),
        hash_string(&sorted_query_material(ctx)),
        hash_string(&user_agent(ctx)),
        hash_string(truncate_chars(ctx.get_raw_body(), body_hash_max)),
    ]
    .join("|")
}

/// `key=value` pairs sorted by key, so parameter order does not matter.
fn sorted_query_material(ctx: &dyn WafHttpContext) -> String {
    let mut entries: Vec<_> = ctx.get_query().iter().collect();
    entries.sort_by_key(|(key, _)| *key);
    let pairs: Vec<String> = entries
        .iter()
        .map(|(key, value)| format!("{key}={}", value.to_match_string()))
        .collect();
    pairs.join("&")
}

fn user_agent(ctx: &dyn WafHttpContext) -> String {
    let headers = ctx.get_headers();
    let value = headers
        .get("user-agent")
        .or_else(|| headers.get("User-Agent"));
    value.map(HeaderValue::to_match_string).unwrap_or_default()
}

/// The first `max` characters of `text` (`0` keeps it whole).
fn truncate_chars(text: &str, max: usize) -> &str {
    match text.char_indices().nth(max) {
        Some((cut, _)) if max > 0 => &text[..cut],
        _ => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_javascript_djb2() {
        // (((5381 << 5) + 5381) + 97) >>> 0 = 177670
        assert_eq!(hash_string("a"), "2b606");
        assert_eq!(hash_string(""), "1505");
    }
}
