//! Owned in-memory request used by the integration tests.

#![allow(dead_code)]

use mini_waf::{
    CookieMap,
    HeaderMap,
    HeaderValue,
    QueryMap,
    QueryValue,
    UploadedFile,
    WafHttpContext,
    normalize_client_ip,
};

#[derive(Debug, Clone)]
pub struct MockRequest {
    pub method: String,
    pub url: String,
    pub path: String,
    pub ip: String,
    pub headers: HeaderMap,
    pub query: QueryMap,
    pub cookies: CookieMap,
    pub body: String,
    pub files: Vec<UploadedFile>,
    pub blocked: Option<(u16, String)>,
    pub response_headers: Vec<(String, String)>,
}

impl Default for MockRequest {
    fn default() -> Self {
        Self {
            method: "GET".into(),
            url: "/".into(),
            path: "/".into(),
            ip: normalize_client_ip("127.0.0.1"),
            headers: HeaderMap::new(),
            query: QueryMap::new(),
            cookies: CookieMap::new(),
            body: String::new(),
            files: Vec::new(),
            blocked: None,
            response_headers: Vec::new(),
        }
    }
}

impl MockRequest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn method(mut self, method: &str) -> Self {
        self.method = method.into();
        self
    }

    pub fn path(mut self, path: &str) -> Self {
        self.url = path.into();
        self.path = path.split('?').next().unwrap_or(path).into();
        self
    }

    pub fn ip(mut self, ip: &str) -> Self {
        self.ip = normalize_client_ip(ip);
        self
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name, HeaderValue::from(value));
        self
    }

    pub fn ua(self) -> Self {
        self.header("user-agent", "Mozilla/5.0")
    }

    pub fn query(mut self, name: &str, value: impl Into<QueryValue>) -> Self {
        self.query.insert(name, value.into());
        self
    }

    pub fn cookie(mut self, name: &str, value: &str) -> Self {
        self.cookies.insert(name, value.to_owned());
        self
    }

    pub fn body(mut self, body: &str) -> Self {
        self.body = body.into();
        self
    }

    pub fn file(mut self, file: UploadedFile) -> Self {
        self.files.push(file);
        self
    }
}

impl WafHttpContext for MockRequest {
    fn framework(&self) -> &str {
        "mock"
    }

    fn get_method(&self) -> &str {
        &self.method
    }

    fn get_url(&self) -> &str {
        &self.url
    }

    fn get_path(&self) -> &str {
        &self.path
    }

    fn get_ip(&self) -> &str {
        &self.ip
    }

    fn get_protocol(&self) -> &str {
        "http"
    }

    fn get_local_port(&self) -> u16 {
        3000
    }

    fn get_header(&self, name: &str) -> Option<String> {
        self.headers
            .get(&name.to_lowercase())
            .and_then(HeaderValue::first)
            .map(str::to_owned)
    }

    fn get_headers(&self) -> &HeaderMap {
        &self.headers
    }

    fn get_query(&self) -> &QueryMap {
        &self.query
    }

    fn get_cookies(&self) -> &CookieMap {
        &self.cookies
    }

    fn get_raw_body(&self) -> &str {
        &self.body
    }

    fn get_files(&self) -> &[UploadedFile] {
        &self.files
    }

    fn set_response_header(&mut self, name: &str, value: &str) {
        self.response_headers.push((name.into(), value.into()));
    }

    fn remove_response_header(&mut self, name: &str) {
        self.response_headers.retain(|(header, _)| header != name);
    }

    fn is_blocked(&self) -> bool {
        self.blocked.is_some()
    }

    fn drop(&mut self, status_code: Option<u16>, body: Option<&str>) {
        self.blocked = Some((
            status_code.unwrap_or(403),
            body.unwrap_or("Forbidden").into(),
        ));
    }
}

/// Standard Base64 encoding, for building decoder test payloads.
pub fn b64(text: &str) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    text.as_bytes()
        .chunks(3)
        .flat_map(|chunk| {
            let byte = |index: usize| {
                u32::from(chunk.get(index).copied().unwrap_or(0))
            };
            let triple = (byte(0) << 16) | (byte(1) << 8) | byte(2);
            (0..4).map(move |sextet| {
                if sextet <= chunk.len() {
                    ALPHABET[((triple >> (18 - 6 * sextet)) & 63) as usize]
                        as char
                } else {
                    '='
                }
            })
        })
        .collect()
}

/// Percent-encode every byte.
pub fn full_encode(text: &str) -> String {
    text.bytes().map(|byte| format!("%{byte:02x}")).collect()
}
