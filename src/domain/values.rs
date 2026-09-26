//! Typed value model: JSON, headers, query strings, cookies and uploads.

use crate::utils::encoding::decode_form_component;
use crate::utils::json::format_number;
pub use crate::utils::ordered_map::OrderedMap;

/// A JSON scalar: `string | number | boolean | null`.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonPrimitive {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
}

/// A JSON array.
pub type JsonArray = Vec<JsonValue>;

/// A JSON object: key/value pairs in document order.
pub type JsonObject = Vec<(String, JsonValue)>;

/// A parsed JSON document.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(JsonArray),
    /// Key/value pairs in document order.
    Object(JsonObject),
}

impl JsonValue {
    /// Look up a key on an object. Returns `None` for other variants.
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(entries) => entries
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            JsonValue::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, JsonValue)]> {
        match self {
            JsonValue::Object(entries) => Some(entries),
            _ => None,
        }
    }
}

impl From<&str> for JsonValue {
    fn from(value: &str) -> Self {
        JsonValue::String(value.to_owned())
    }
}

impl From<String> for JsonValue {
    fn from(value: String) -> Self {
        JsonValue::String(value)
    }
}

impl From<bool> for JsonValue {
    fn from(value: bool) -> Self {
        JsonValue::Bool(value)
    }
}

impl From<f64> for JsonValue {
    fn from(value: f64) -> Self {
        JsonValue::Number(value)
    }
}

impl From<JsonPrimitive> for JsonValue {
    fn from(value: JsonPrimitive) -> Self {
        match value {
            JsonPrimitive::Null => JsonValue::Null,
            JsonPrimitive::Bool(flag) => JsonValue::Bool(flag),
            JsonPrimitive::Number(number) => JsonValue::Number(number),
            JsonPrimitive::String(text) => JsonValue::String(text),
        }
    }
}

/// One header value; repeated headers (`Set-Cookie`, `X-Forwarded-For`) may
/// arrive as several.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderValue {
    Single(String),
    Multi(Vec<String>),
}

impl HeaderValue {
    /// The first value, like most frameworks' `req.get(name)`.
    pub fn first(&self) -> Option<&str> {
        match self {
            HeaderValue::Single(value) => Some(value),
            HeaderValue::Multi(values) => values.first().map(String::as_str),
        }
    }

    /// Flatten for matching: multiple values are joined with `,`.
    pub(crate) fn to_match_string(&self) -> String {
        match self {
            HeaderValue::Single(value) => value.clone(),
            HeaderValue::Multi(values) => values.join(","),
        }
    }
}

impl From<&str> for HeaderValue {
    fn from(value: &str) -> Self {
        HeaderValue::Single(value.to_owned())
    }
}

impl From<String> for HeaderValue {
    fn from(value: String) -> Self {
        HeaderValue::Single(value)
    }
}

impl From<Vec<String>> for HeaderValue {
    fn from(values: Vec<String>) -> Self {
        HeaderValue::Multi(values)
    }
}

/// Request headers. Keys should be lowercased by the adapter, as HTTP/2 and
/// most frameworks already do; `headers.<name>` rules look names up lowercased.
pub type HeaderMap = OrderedMap<HeaderValue>;

/// Parsed cookies (`name → value`).
pub type CookieMap = OrderedMap<String>;

/// A query-string value. Frameworks with "extended" parsers turn
/// `?filter[status]=open` into a nested object and `?a[]=1&a[]=2` into an
/// array, so the model is recursive.
#[derive(Debug, Clone, PartialEq)]
pub enum QueryValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<QueryValue>),
    Object(QueryMap),
}

/// Query parameters (`name → value`).
pub type QueryMap = OrderedMap<QueryValue>;

impl From<&str> for QueryValue {
    fn from(value: &str) -> Self {
        QueryValue::String(value.to_owned())
    }
}

impl From<String> for QueryValue {
    fn from(value: String) -> Self {
        QueryValue::String(value)
    }
}

impl From<Vec<QueryValue>> for QueryValue {
    fn from(values: Vec<QueryValue>) -> Self {
        QueryValue::Array(values)
    }
}

impl From<QueryMap> for QueryValue {
    fn from(map: QueryMap) -> Self {
        QueryValue::Object(map)
    }
}

impl From<&JsonValue> for QueryValue {
    fn from(value: &JsonValue) -> Self {
        match value {
            JsonValue::Null => QueryValue::Null,
            JsonValue::Bool(flag) => QueryValue::Bool(*flag),
            JsonValue::Number(number) => QueryValue::Number(*number),
            JsonValue::String(text) => QueryValue::String(text.clone()),
            JsonValue::Array(items) => {
                QueryValue::Array(items.iter().map(QueryValue::from).collect())
            }
            JsonValue::Object(entries) => QueryValue::Object(
                entries
                    .iter()
                    .map(|(key, item)| (key.clone(), QueryValue::from(item)))
                    .collect(),
            ),
        }
    }
}

/// Depth cap so a hostile deeply-nested query cannot drive recursion cost.
const MAX_QUERY_DEPTH: usize = 6;

fn flatten_query(value: &QueryValue, depth: usize) -> String {
    match value {
        QueryValue::Null => String::new(),
        QueryValue::String(text) => text.clone(),
        QueryValue::Number(number) => format_number(*number),
        QueryValue::Bool(flag) => flag.to_string(),
        _ if depth >= MAX_QUERY_DEPTH => String::new(),
        QueryValue::Array(items) => items
            .iter()
            .map(|item| flatten_query(item, depth + 1))
            .collect::<Vec<_>>()
            .join(","),
        QueryValue::Object(map) => map
            .iter()
            .map(|(key, item)| {
                format!("{key}={}", flatten_query(item, depth + 1))
            })
            .collect::<Vec<_>>()
            .join("&"),
    }
}

impl QueryValue {
    /// Flatten into one string for matching.
    ///
    /// Nested objects are rendered back as `key=value&key=value`, which keeps
    /// bracketed parameter **names** visible to rules — that is how
    /// `?user[$ne]=null` reaches the NoSQL operator rule.
    pub(crate) fn to_match_string(&self) -> String {
        flatten_query(self, 0)
    }
}

impl QueryMap {
    /// Parse a raw query string (with or without the leading `?`).
    ///
    /// Values are form-decoded (`+` is a space). A repeated key becomes a
    /// [`QueryValue::Array`]. Bracketed names are kept verbatim, so
    /// `user[$ne]=1` stays visible to the NoSQL operator rule. Adapters whose
    /// framework already parses the query can pass that map instead.
    pub fn parse(query: &str) -> QueryMap {
        let query = query.strip_prefix('?').unwrap_or(query);
        query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                (decode_form_component(key), decode_form_component(value))
            })
            .fold(QueryMap::new(), |mut map, (key, value)| {
                append_query_value(&mut map, key, value);
                map
            })
    }
}

/// Add one decoded pair; a repeated key turns into (or extends) an array.
fn append_query_value(map: &mut QueryMap, key: String, value: String) {
    let value = QueryValue::String(value);
    let merged = match map.remove(&key) {
        None => value,
        Some(QueryValue::Array(mut items)) => {
            items.push(value);
            QueryValue::Array(items)
        }
        Some(previous) => QueryValue::Array(vec![previous, value]),
    };
    map.insert(key, merged);
}

/// An uploaded file as the multipart layer describes it. Only the name is
/// inspected (by the dangerous-upload rules), never the content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UploadedFile {
    pub fieldname: Option<String>,
    pub name: Option<String>,
    pub filename: Option<String>,
    pub originalname: Option<String>,
}

impl UploadedFile {
    /// A file known only by its client-side name.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ..Self::default()
        }
    }
}

/// Best available display name for an uploaded file, trying `name`,
/// `filename` then `originalname`. Returns `""` when the bag carries none —
/// this is what upload rules such as `preset-dangerous-upload` match against.
pub fn file_display_name(file: &UploadedFile) -> &str {
    file.name
        .as_deref()
        .or(file.filename.as_deref())
        .or(file.originalname.as_deref())
        .unwrap_or("")
}

/// Uploaded files as multipart layers hand them over: a flat list, or a map
/// of form field → files.
#[derive(Debug, Clone, PartialEq)]
pub enum FilesBag {
    List(Vec<UploadedFile>),
    Fields(OrderedMap<Vec<UploadedFile>>),
}

impl From<Vec<UploadedFile>> for FilesBag {
    fn from(files: Vec<UploadedFile>) -> Self {
        FilesBag::List(files)
    }
}

impl From<OrderedMap<Vec<UploadedFile>>> for FilesBag {
    fn from(fields: OrderedMap<Vec<UploadedFile>>) -> Self {
        FilesBag::Fields(fields)
    }
}

/// Normalize multipart file bags into a flat list. Files from a map inherit
/// their form field as `fieldname` when they carry none.
pub fn normalize_files(files: Option<FilesBag>) -> Vec<UploadedFile> {
    match files {
        None => Vec::new(),
        Some(FilesBag::List(files)) => files,
        Some(FilesBag::Fields(fields)) => fields
            .iter()
            .flat_map(|(fieldname, files)| {
                files.iter().cloned().map(move |file| UploadedFile {
                    fieldname: file
                        .fieldname
                        .clone()
                        .or_else(|| Some(fieldname.clone())),
                    ..file
                })
            })
            .collect(),
    }
}

/// A header or query value: what [`scalar_to_string`] accepts.
pub trait ScalarValue {
    fn scalar_string(&self) -> String;
}

impl ScalarValue for HeaderValue {
    fn scalar_string(&self) -> String {
        self.to_match_string()
    }
}

impl ScalarValue for QueryValue {
    fn scalar_string(&self) -> String {
        self.to_match_string()
    }
}

impl<T: ScalarValue> ScalarValue for Option<&T> {
    fn scalar_string(&self) -> String {
        self.map(ScalarValue::scalar_string).unwrap_or_default()
    }
}

/// Flatten a header / query value into a single string for matching.
///
/// Nested objects are rendered back as `key=value&key=value`, which keeps
/// bracketed parameter **names** visible to rules — that is how
/// `?user[$ne]=null` reaches the NoSQL operator rule.
pub fn scalar_to_string(value: &impl ScalarValue) -> String {
    value.scalar_string()
}

/// Serialize a JSON-compatible body for payload inspection.
pub fn json_to_string(value: Option<&JsonValue>) -> String {
    match value {
        None | Some(JsonValue::Null) => String::new(),
        Some(JsonValue::String(text)) => text.clone(),
        Some(value) => value.to_json_string(),
    }
}

/// Convert a body in any shape (text, bytes, parsed JSON, nothing) into the
/// raw body string.
pub fn body_to_string(value: impl Into<RawBody>) -> String {
    value.into().into_text()
}

/// A request body in whatever shape the framework produced it.
#[derive(Debug, Clone, PartialEq)]
pub enum RawBody {
    Empty,
    Text(String),
    Bytes(Vec<u8>),
    /// Already-parsed JSON; serialized back for inspection.
    Json(JsonValue),
}

impl RawBody {
    /// Render the body as text for matching (bytes are decoded lossily as
    /// UTF-8).
    pub(crate) fn into_text(self) -> String {
        match self {
            RawBody::Empty => String::new(),
            RawBody::Text(text) => text,
            RawBody::Bytes(bytes) => {
                String::from_utf8(bytes).unwrap_or_else(|error| {
                    String::from_utf8_lossy(error.as_bytes()).into_owned()
                })
            }
            RawBody::Json(JsonValue::String(text)) => text,
            RawBody::Json(JsonValue::Null) => String::new(),
            RawBody::Json(value) => value.to_json_string(),
        }
    }
}

impl From<String> for RawBody {
    fn from(text: String) -> Self {
        RawBody::Text(text)
    }
}

impl From<&str> for RawBody {
    fn from(text: &str) -> Self {
        RawBody::Text(text.to_owned())
    }
}

impl From<Vec<u8>> for RawBody {
    fn from(bytes: Vec<u8>) -> Self {
        RawBody::Bytes(bytes)
    }
}

impl From<&[u8]> for RawBody {
    fn from(bytes: &[u8]) -> Self {
        RawBody::Bytes(bytes.to_vec())
    }
}

impl From<JsonValue> for RawBody {
    fn from(value: JsonValue) -> Self {
        RawBody::Json(value)
    }
}

impl<T: Into<RawBody>> From<Option<T>> for RawBody {
    fn from(value: Option<T>) -> Self {
        value.map_or(RawBody::Empty, Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flattens_nested_query_values() {
        let nested: QueryMap = [("$ne", QueryValue::from("null"))].into();
        assert_eq!(QueryValue::Object(nested).to_match_string(), "$ne=null");
        let list = QueryValue::Array(vec!["node".into(), "waf".into()]);
        assert_eq!(list.to_match_string(), "node,waf");
        assert_eq!(QueryValue::Number(2.0).to_match_string(), "2");
        assert_eq!(QueryValue::Null.to_match_string(), "");
    }

    #[test]
    fn parses_raw_query_strings() {
        let query =
            QueryMap::parse("?a=1&b=hello+world&a=2&flag&user%5B%24ne%5D=x");
        assert_eq!(query.get("a").unwrap().to_match_string(), "1,2");
        assert_eq!(query.get("b").unwrap().to_match_string(), "hello world");
        assert_eq!(query.get("flag").unwrap().to_match_string(), "");
        assert_eq!(query.get("user[$ne]").unwrap().to_match_string(), "x");
    }

    #[test]
    fn renders_bodies_as_text() {
        assert_eq!(RawBody::from(b"hi".as_slice()).into_text(), "hi");
        let json = JsonValue::parse(r#"{"a":1}"#).unwrap();
        assert_eq!(RawBody::from(json).into_text(), r#"{"a":1}"#);
        assert_eq!(RawBody::from(None::<String>).into_text(), "");
    }

    #[test]
    fn picks_the_best_upload_name() {
        let file = UploadedFile {
            originalname: Some("shell.php".into()),
            ..UploadedFile::default()
        };
        assert_eq!(file_display_name(&file), "shell.php");
        assert_eq!(file_display_name(&UploadedFile::default()), "");
    }

    #[test]
    fn normalizes_file_bags() {
        let fields: OrderedMap<Vec<UploadedFile>> =
            [("avatar", vec![UploadedFile::named("a.png")])].into();
        let files = normalize_files(Some(fields.into()));
        assert_eq!(files[0].fieldname.as_deref(), Some("avatar"));
        assert!(normalize_files(None).is_empty());
        assert_eq!(
            scalar_to_string(&HeaderValue::from(vec![
                "a".to_owned(),
                "b".to_owned()
            ])),
            "a,b"
        );
        assert_eq!(scalar_to_string(&None::<&QueryValue>), "");
        assert_eq!(json_to_string(Some(&JsonValue::String("x".into()))), "x");
        assert_eq!(body_to_string(b"hi".as_slice()), "hi");
    }
}
