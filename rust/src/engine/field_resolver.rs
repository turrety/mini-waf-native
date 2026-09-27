//! Per-request field resolution with memoization.
//!
//! Rules are compiled once so every distinct [`WafField`] gets a numeric slot.
//! Per request, each slot lazily memoizes the field's values, their
//! lowercased forms and the decoded extras, so a request pays for each at
//! most once however many rules read it — and a lookup is an index, not a
//! hash.

use std::cell::OnceCell;

use crate::domain::context::WafHttpContext;
use crate::domain::rules::WafField;
use crate::domain::values::{
    HeaderValue,
    QueryValue,
    file_display_name,
};
use crate::engine::decode::{
    DecodeSettings,
    expand_base64_candidates,
    expand_comment_candidates,
    expand_url_candidates,
    extract_body_values,
    extract_path_segments,
};
use crate::engine::matcher::js_regex_view;

#[derive(Default)]
struct Slot {
    raw: OnceCell<Vec<String>>,
    lower: OnceCell<Vec<String>>,
    extras: OnceCell<Vec<String>>,
    extras_lower: OnceCell<Vec<String>>,
    /// Per value of `raw` then `extras`: its [`js_regex_view`], when it
    /// differs.
    views: OnceCell<Vec<Option<String>>>,
}

pub(crate) struct FieldResolver<'a> {
    ctx: &'a dyn WafHttpContext,
    /// Slot index → field, fixed when the rules were compiled.
    fields: &'a [WafField],
    /// Truncate each value to this many characters. `0` is unlimited.
    max_field_length: usize,
    decode: DecodeSettings,
    slots: Vec<Slot>,
}

fn truncate(value: String, max_chars: usize) -> String {
    // A value no longer than `max_chars` bytes cannot hold more characters.
    if max_chars == 0 || value.len() <= max_chars {
        return value;
    }
    match value.char_indices().nth(max_chars) {
        Some((cut, _)) => value[..cut].to_owned(),
        None => value,
    }
}

fn resolve(ctx: &dyn WafHttpContext, field: &WafField) -> Vec<String> {
    match field {
        WafField::Ip => vec![ctx.get_ip().to_owned()],
        WafField::Method => vec![ctx.get_method().to_owned()],
        WafField::Path => vec![ctx.get_path().to_owned()],
        WafField::Url => vec![ctx.get_url().to_owned()],
        WafField::Body => vec![ctx.get_raw_body().to_owned()],
        WafField::Files => file_names(ctx),
        WafField::Query => ctx
            .get_query()
            .values()
            .map(QueryValue::to_match_string)
            .collect(),
        WafField::Headers => ctx
            .get_headers()
            .values()
            .map(HeaderValue::to_match_string)
            .collect(),
        WafField::Cookies => ctx.get_cookies().values().cloned().collect(),
        WafField::QueryParam(name) => vec![query_param(ctx, name)],
        WafField::Header(name) => vec![header(ctx, name)],
        WafField::Cookie(name) => vec![cookie(ctx, name)],
    }
}

fn file_names(ctx: &dyn WafHttpContext) -> Vec<String> {
    ctx.get_files()
        .iter()
        .map(file_display_name)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

fn query_param(ctx: &dyn WafHttpContext, name: &str) -> String {
    ctx.get_query()
        .get(name)
        .map(QueryValue::to_match_string)
        .unwrap_or_default()
}

/// Header names are matched lowercased; the dedicated accessor wins over the
/// header bag.
fn header(ctx: &dyn WafHttpContext, name: &str) -> String {
    let name = name.to_lowercase();
    ctx.get_header(&name).unwrap_or_else(|| {
        ctx.get_headers()
            .get(&name)
            .map(HeaderValue::to_match_string)
            .unwrap_or_default()
    })
}

fn cookie(ctx: &dyn WafHttpContext, name: &str) -> String {
    ctx.get_cookies().get(name).cloned().unwrap_or_default()
}

/// Options of the standalone field resolvers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FieldResolveOptions {
    /// Truncate each candidate string to this many characters. `0` is
    /// unlimited.
    pub max_field_length: usize,
    /// Transport-decode settings (used by condition evaluation; the raw
    /// resolvers below ignore them).
    pub decode: Option<DecodeSettings>,
}

/// Resolve one or more string candidates for a field. Multi-value fields
/// (query, headers, cookies, files) return every value, so the matcher can
/// OR across them. With `max_field_length` set, each candidate is truncated
/// before matching (rate-limit key material uses the same truncated view).
///
/// The engine memoizes this per request; these standalone resolvers do not.
pub fn resolve_field_values(
    ctx: &dyn WafHttpContext,
    field: &WafField,
    options: Option<&FieldResolveOptions>,
) -> Vec<String> {
    let max_field_length =
        options.map_or(0, |options| options.max_field_length);
    resolve(ctx, field)
        .into_iter()
        .map(|value| truncate(value, max_field_length))
        .collect()
}

/// Same candidates as [`resolve_field_values`], lowercased.
pub fn resolve_field_values_lower(
    ctx: &dyn WafHttpContext,
    field: &WafField,
    options: Option<&FieldResolveOptions>,
) -> Vec<String> {
    lowercase_all(&resolve_field_values(ctx, field, options))
}

/// Join all candidates with `|` — rate-limit key material.
pub fn resolve_field_joined(
    ctx: &dyn WafHttpContext,
    field: &WafField,
    options: Option<&FieldResolveOptions>,
) -> String {
    resolve_field_values(ctx, field, options).join("|")
}

fn lowercase_all(values: &[String]) -> Vec<String> {
    values.iter().map(|value| value.to_lowercase()).collect()
}

impl<'a> FieldResolver<'a> {
    pub(crate) fn new(
        ctx: &'a dyn WafHttpContext,
        fields: &'a [WafField],
        options: FieldResolveOptions,
    ) -> Self {
        Self {
            ctx,
            fields,
            max_field_length: options.max_field_length,
            decode: options.decode.unwrap_or_default(),
            slots: std::iter::repeat_with(Slot::default)
                .take(fields.len())
                .collect(),
        }
    }

    /// Every value of a field, truncated to the configured length. These are
    /// what `equals` compares and what rate-limit keys are built from.
    pub(crate) fn values(&self, slot: usize) -> &[String] {
        self.slots[slot].raw.get_or_init(|| {
            resolve(self.ctx, &self.fields[slot])
                .into_iter()
                .map(|value| truncate(value, self.max_field_length))
                .collect()
        })
    }

    /// [`Self::values`], lowercased (for `includes` and `requires`).
    pub(crate) fn values_lower(&self, slot: usize) -> &[String] {
        self.slots[slot]
            .lower
            .get_or_init(|| lowercase_all(self.values(slot)))
    }

    /// Decoded variants appended to the match bag. Empty while decoding is
    /// off.
    pub(crate) fn extras(&self, slot: usize) -> &[String] {
        if !self.decode.any() {
            return &[];
        }
        self.slots[slot].extras.get_or_init(|| {
            let (input, escaped) = self.decoder_input(slot);
            expand_base64_candidates(&input, self.decode)
                .into_iter()
                .chain(expand_url_candidates(&input, self.decode))
                .chain(expand_comment_candidates(&input, self.decode))
                .chain(escaped.into_iter().filter(|_| self.decode.url))
                .collect()
        })
    }

    /// What the decoders scan: the values plus, for a body or a path, the
    /// pieces a payload hides in (one JSON string, form value or multipart
    /// field; one path segment), which are not whole-value blobs on their
    /// own. For a JSON body, also its `\u` / `\/`-escaped strings decoded,
    /// which are match candidates themselves.
    fn decoder_input(&self, slot: usize) -> (Vec<String>, Vec<String>) {
        let values = self.values(slot);
        let (pieces, escaped) = match (&self.fields[slot], values.first()) {
            (WafField::Body, Some(body)) => {
                let body = extract_body_values(body);
                (body.values, body.escaped)
            }
            (WafField::Path, Some(path)) => {
                (extract_path_segments(path), Vec::new())
            }
            _ => (Vec::new(), Vec::new()),
        };
        (values.iter().cloned().chain(pieces).collect(), escaped)
    }

    /// [`Self::extras`], lowercased.
    pub(crate) fn extras_lower(&self, slot: usize) -> &[String] {
        if !self.decode.any() {
            return &[];
        }
        self.slots[slot]
            .extras_lower
            .get_or_init(|| lowercase_all(self.extras(slot)))
    }

    /// The regex view of every value of [`Self::values`] then
    /// [`Self::extras`]; `None` (or a short slice) where it is the value
    /// itself. All-ASCII fields, the common case, allocate nothing.
    pub(crate) fn views(&self, slot: usize) -> &[Option<String>] {
        self.slots[slot].views.get_or_init(|| {
            let values = || self.values(slot).iter().chain(self.extras(slot));
            if values().all(|value| value.is_ascii()) {
                return Vec::new();
            }
            values().map(|value| js_regex_view(value)).collect()
        })
    }

    /// All values joined with `|`: rate-limit key material.
    pub(crate) fn joined(&self, slot: usize) -> String {
        self.values(slot).join("|")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_by_characters() {
        assert_eq!(truncate("abcdef".into(), 3), "abc");
        assert_eq!(truncate("ação".into(), 2), "aç");
        assert_eq!(truncate("abc".into(), 0), "abc");
        assert_eq!(truncate("abc".into(), 10), "abc");
    }
}
