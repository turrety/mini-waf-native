//! A small, dependency-free JSON parser and serializer for [`JsonValue`].
//!
//! The engine needs JSON in two places: loading serializable rules
//! ([`crate::parse_rules_from_json`]) and pulling string leaves out of request
//! bodies for the transport decoders. Both only need a faithful value tree, so
//! this module keeps the crate free of a serialization framework.
//!
//! Object keys keep their document order. Nesting is capped at
//! [`MAX_DEPTH`] so a hostile body cannot drive unbounded recursion.

use std::fmt::{
    self,
    Write as _,
};

use crate::domain::values::{
    JsonObject,
    JsonValue,
};

/// Maximum nesting depth accepted by [`JsonValue::parse`].
pub const MAX_DEPTH: usize = 128;

/// Why a JSON document failed to parse, with the byte offset of the problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError {
    pub offset: usize,
    pub message: &'static str,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.message, self.offset)
    }
}

impl std::error::Error for JsonError {}

impl JsonValue {
    /// Parse a complete JSON document. Trailing non-whitespace is an error.
    pub fn parse(input: &str) -> Result<Self, JsonError> {
        let mut parser = Parser {
            bytes: input.as_bytes(),
            pos: 0,
        };
        let value = parser.value(0)?;
        parser.skip_whitespace();
        if parser.pos != parser.bytes.len() {
            return Err(parser.error("unexpected trailing characters"));
        }
        Ok(value)
    }

    /// Serialize back to compact JSON text (the `JSON.stringify` shape).
    pub fn to_json_string(&self) -> String {
        let mut out = String::new();
        write_value(self, &mut out);
        out
    }
}

impl fmt::Display for JsonValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_json_string())
    }
}

/// Render a number the way JavaScript's `String(number)` does for the common
/// cases: integral values print without a fractional part.
pub(crate) fn format_number(value: f64) -> String {
    if !value.is_finite() {
        return "null".to_owned();
    }
    // Rust's `Display` for f64 already omits `.0` and never uses exponents.
    format!("{value}")
}

fn write_value(value: &JsonValue, out: &mut String) {
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Number(number) => out.push_str(&format_number(*number)),
        JsonValue::String(text) => write_string(text, out),
        JsonValue::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        JsonValue::Object(entries) => {
            out.push('{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(item, out);
            }
            out.push('}');
        }
    }
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn error(&self, message: &'static str) -> JsonError {
        JsonError {
            offset: self.pos,
            message,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Consume `byte` when it is next.
    fn eat(&mut self, byte: u8) -> bool {
        let found = self.peek() == Some(byte);
        self.pos += usize::from(found);
        found
    }

    fn expect(
        &mut self,
        byte: u8,
        message: &'static str,
    ) -> Result<(), JsonError> {
        if self.eat(byte) {
            Ok(())
        } else {
            Err(self.error(message))
        }
    }

    /// Consume a run of ASCII digits; `false` when there was none.
    fn eat_digits(&mut self) -> bool {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        self.pos > start
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn literal(
        &mut self,
        text: &[u8],
        value: JsonValue,
    ) -> Result<JsonValue, JsonError> {
        if !self.bytes[self.pos..].starts_with(text) {
            return Err(self.error("invalid literal"));
        }
        self.pos += text.len();
        Ok(value)
    }

    fn value(&mut self, depth: usize) -> Result<JsonValue, JsonError> {
        if depth > MAX_DEPTH {
            return Err(self.error("nesting too deep"));
        }
        self.skip_whitespace();
        match self.peek() {
            None => Err(self.error("unexpected end of input")),
            Some(b'n') => self.literal(b"null", JsonValue::Null),
            Some(b't') => self.literal(b"true", JsonValue::Bool(true)),
            Some(b'f') => self.literal(b"false", JsonValue::Bool(false)),
            Some(b'"') => self.string().map(JsonValue::String),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.error("unexpected character")),
        }
    }

    fn array(&mut self, depth: usize) -> Result<JsonValue, JsonError> {
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.eat(b']') {
            return Ok(JsonValue::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_whitespace();
            if self.eat(b']') {
                return Ok(JsonValue::Array(items));
            }
            self.expect(b',', "expected ',' or ']'")?;
        }
    }

    fn object(&mut self, depth: usize) -> Result<JsonValue, JsonError> {
        self.pos += 1;
        let mut entries = Vec::new();
        self.skip_whitespace();
        if self.eat(b'}') {
            return Ok(JsonValue::Object(entries));
        }
        loop {
            let (key, value) = self.member(depth)?;
            insert_last_wins(&mut entries, key, value);
            self.skip_whitespace();
            if self.eat(b'}') {
                return Ok(JsonValue::Object(entries));
            }
            self.expect(b',', "expected ',' or '}'")?;
        }
    }

    /// One `"key": value` pair of an object.
    fn member(
        &mut self,
        depth: usize,
    ) -> Result<(String, JsonValue), JsonError> {
        self.skip_whitespace();
        if self.peek() != Some(b'"') {
            return Err(self.error("expected a string key"));
        }
        let key = self.string()?;
        self.skip_whitespace();
        self.expect(b':', "expected ':'")?;
        Ok((key, self.value(depth + 1)?))
    }

    fn number(&mut self) -> Result<JsonValue, JsonError> {
        let start = self.pos;
        self.eat(b'-');
        if !(self.integer_part()
            && self.fraction_part()
            && self.exponent_part())
        {
            return Err(self.error("invalid number"));
        }
        // The slice is ASCII digits and signs by construction.
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .unwrap_or_default();
        text.parse()
            .map(JsonValue::Number)
            .map_err(|_| self.error("invalid number"))
    }

    /// `0` or a run of digits (no leading zeros).
    fn integer_part(&mut self) -> bool {
        self.eat(b'0') || self.eat_digits()
    }

    /// Optional `.digits`.
    fn fraction_part(&mut self) -> bool {
        !self.eat(b'.') || self.eat_digits()
    }

    /// Optional `e`, sign, then digits.
    fn exponent_part(&mut self) -> bool {
        if !self.eat(b'e') && !self.eat(b'E') {
            return true;
        }
        if !self.eat(b'+') {
            self.eat(b'-');
        }
        self.eat_digits()
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.pos += 1;
        let mut out = Vec::new();
        loop {
            match self.peek() {
                None => return Err(self.error("unterminated string")),
                Some(b'"') => {
                    self.pos += 1;
                    // Input was a &str and escapes only ever emit whole chars.
                    return String::from_utf8(out)
                        .map_err(|_| self.error("invalid UTF-8 in string"));
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let mut buffer = [0u8; 4];
                    out.extend_from_slice(
                        self.escape()?.encode_utf8(&mut buffer).as_bytes(),
                    );
                }
                Some(byte) if byte < 0x20 => {
                    return Err(self.error("control character in string"));
                }
                Some(byte) => {
                    out.push(byte);
                    self.pos += 1;
                }
            }
        }
    }

    /// The character of a backslash escape (the `\` already consumed).
    fn escape(&mut self) -> Result<char, JsonError> {
        let escaped = self
            .peek()
            .ok_or_else(|| self.error("unterminated escape"))?;
        self.pos += 1;
        match escaped {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{08}'),
            b'f' => Ok('\u{0c}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => self.unicode_escape(),
            _ => Err(self.error("invalid escape")),
        }
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let digits = self
            .bytes
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| self.error("truncated \\u escape"))?;
        let text = std::str::from_utf8(digits)
            .map_err(|_| self.error("invalid \\u escape"))?;
        let code = u32::from_str_radix(text, 16)
            .map_err(|_| self.error("invalid \\u escape"))?;
        self.pos += 4;
        Ok(code)
    }

    /// `\uXXXX`, pairing a high surrogate with a following low one. A lone
    /// surrogate becomes U+FFFD, like JavaScript's lossy conversion.
    fn unicode_escape(&mut self) -> Result<char, JsonError> {
        let first = self.hex4()?;
        if !(0xD800..0xDC00).contains(&first) {
            return Ok(
                char::from_u32(first).unwrap_or(char::REPLACEMENT_CHARACTER)
            );
        }
        if self.bytes[self.pos..].starts_with(b"\\u") {
            let save = self.pos;
            self.pos += 2;
            let second = self.hex4()?;
            if (0xDC00..0xE000).contains(&second) {
                let combined =
                    0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
                return Ok(char::from_u32(combined)
                    .unwrap_or(char::REPLACEMENT_CHARACTER));
            }
            self.pos = save;
        }
        Ok(char::REPLACEMENT_CHARACTER)
    }
}

/// `JSON.parse` keeps the last value of a duplicate key.
fn insert_last_wins(entries: &mut JsonObject, key: String, value: JsonValue) {
    match entries.iter_mut().find(|(existing, _)| *existing == key) {
        Some(entry) => entry.1 = value,
        None => entries.push((key, value)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_documents_in_key_order() {
        let value =
            JsonValue::parse(r#"{"b":[1,true,null],"a":{"x":"y\n"}}"#).unwrap();
        let entries = value.as_object().unwrap();
        assert_eq!(entries[0].0, "b");
        assert_eq!(
            entries[1].1.get("x").and_then(JsonValue::as_str),
            Some("y\n")
        );
    }

    #[test]
    fn round_trips_to_compact_text() {
        let text = r#"{"a":[1,2.5,"q\"s"],"b":false}"#;
        assert_eq!(JsonValue::parse(text).unwrap().to_json_string(), text);
    }

    #[test]
    fn decodes_surrogate_pairs() {
        assert_eq!(
            JsonValue::parse(r#""😀""#).unwrap(),
            JsonValue::String("😀".into())
        );
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in [
            "{",
            "[1,]",
            "{\"a\" 1}",
            "01",
            "\"abc",
            "nul",
            "[] x",
            "-",
            "1.",
            ".5",
            "1e",
            "1e+",
        ] {
            assert!(JsonValue::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_numbers_like_javascript() {
        for (text, expected) in [
            ("-0", -0.0),
            ("1.5e-3", 0.0015),
            ("2E+2", 200.0),
            ("10", 10.0),
        ] {
            assert_eq!(
                JsonValue::parse(text),
                Ok(JsonValue::Number(expected)),
                "{text}"
            );
        }
    }

    #[test]
    fn caps_nesting_depth() {
        let deep = "[".repeat(MAX_DEPTH + 5) + &"]".repeat(MAX_DEPTH + 5);
        assert!(JsonValue::parse(&deep).is_err());
    }
}
