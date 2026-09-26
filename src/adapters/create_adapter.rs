//! The universal adapter: plug any HTTP stack into the engine by describing
//! how to read its request and write its response.
//!
//! ```
//! use mini_waf::{
//!     CustomAdapterHandlers,
//!     HeaderMap,
//!     WafConfig,
//!     WafDecision,
//!     WafPresetName,
//!     create_adapter,
//!     create_mini_waf,
//! };
//!
//! struct Request {
//!     method: String,
//!     target: String,
//!     peer: String,
//!     headers: Vec<(String, String)>,
//!     body: Vec<u8>,
//! }
//! #[derive(Default)]
//! struct Response {
//!     status: u16,
//!     body: String,
//!     headers: Vec<(String, String)>,
//! }
//!
//! let adapter = create_adapter(
//!     CustomAdapterHandlers::<Request, Response>::new("my-server")
//!         .get_method(|req| req.method.clone())
//!         .get_url(|req| req.target.clone())
//!         .get_ip(|req| req.peer.clone())
//!         .get_headers(|req| {
//!             req.headers
//!                 .iter()
//!                 .map(|(k, v)| (k.to_lowercase(), v.as_str().into()))
//!                 .collect::<HeaderMap>()
//!         })
//!         .get_raw_body(|req| req.body.clone())
//!         .set_response_header(|res, name, value| {
//!             res.headers.push((name.into(), value.into()))
//!         })
//!         .drop(|_req, res, status, body| {
//!             res.status = status;
//!             res.body = body.into();
//!         }),
//! )
//! .expect("every required handler is set");
//!
//! let waf = create_mini_waf(
//!     WafConfig::default().presets([WafPresetName::Default]),
//!     None,
//! );
//! let request = Request {
//!     method: "GET".into(),
//!     target: "/files?name=../../etc/passwd".into(),
//!     peer: "203.0.113.7".into(),
//!     headers: vec![("User-Agent".into(), "Mozilla/5.0".into())],
//!     body: Vec::new(),
//! };
//! let mut response = Response::default();
//! let result = waf.protect(&adapter, &request, &mut response);
//! assert_eq!(result.decision, WafDecision::Block);
//! assert_eq!(response.status, 403);
//! ```

use std::cell::OnceCell;
use std::fmt;

use crate::domain::context::{
    DEFAULT_BLOCK_BODY,
    DEFAULT_BLOCK_STATUS_CODE,
    WafAdapter,
    WafHttpContext,
};
use crate::domain::values::{
    CookieMap,
    FilesBag,
    HeaderMap,
    QueryMap,
    RawBody,
    UploadedFile,
    normalize_files,
};
use crate::utils::cookies::parse_cookies;
use crate::utils::ip::normalize_client_ip;

type ReqFn<Req, T> = Box<dyn Fn(&Req) -> T + Send + Sync>;
type PortFn<Req, Res> = Box<dyn Fn(&Req, &Res) -> u16 + Send + Sync>;
type HeaderFn<Req> = Box<dyn Fn(&Req, &str) -> Option<String> + Send + Sync>;
type SetHeaderFn<Res> = Box<dyn Fn(&mut Res, &str, &str) + Send + Sync>;
type RemoveHeaderFn<Res> = Box<dyn Fn(&mut Res, &str) + Send + Sync>;
type DropFn<Req, Res> = Box<dyn Fn(&Req, &mut Res, u16, &str) + Send + Sync>;

/// The request / response mappers [`create_adapter`] turns into a
/// [`WafAdapter`]. Each setter is named after the handler it sets.
///
/// Required: `get_method`, `get_url`, `get_ip`, `get_headers`,
/// `get_raw_body`, `set_response_header` and `drop`. Everything else has a
/// default:
///
/// | handler | default |
/// |---|---|
/// | `get_path` | `get_url` up to the first `?` |
/// | `get_protocol` | `"http"` |
/// | `get_local_port` | `0` |
/// | `get_header` | lookup in `get_headers` by lowercase name |
/// | `get_query` | [`QueryMap::parse`] of the part of the URL after `?` |
/// | `get_cookies` | [`parse_cookies`] of the `cookie` header |
/// | `get_files` | none |
/// | `remove_response_header` | no-op |
pub struct CustomAdapterHandlers<TRequest, TResponse> {
    name: String,
    get_method: Option<ReqFn<TRequest, String>>,
    get_url: Option<ReqFn<TRequest, String>>,
    get_path: Option<ReqFn<TRequest, String>>,
    get_ip: Option<ReqFn<TRequest, String>>,
    get_protocol: Option<ReqFn<TRequest, String>>,
    get_local_port: Option<PortFn<TRequest, TResponse>>,
    get_header: Option<HeaderFn<TRequest>>,
    get_headers: Option<ReqFn<TRequest, HeaderMap>>,
    get_query: Option<ReqFn<TRequest, QueryMap>>,
    get_cookies: Option<ReqFn<TRequest, CookieMap>>,
    get_raw_body: Option<ReqFn<TRequest, RawBody>>,
    get_files: Option<ReqFn<TRequest, FilesBag>>,
    set_response_header: Option<SetHeaderFn<TResponse>>,
    remove_response_header: Option<RemoveHeaderFn<TResponse>>,
    drop: Option<DropFn<TRequest, TResponse>>,
}

impl<TRequest, TResponse> CustomAdapterHandlers<TRequest, TResponse> {
    /// Start describing an integration named `name` (shown in logs).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            get_method: None,
            get_url: None,
            get_path: None,
            get_ip: None,
            get_protocol: None,
            get_local_port: None,
            get_header: None,
            get_headers: None,
            get_query: None,
            get_cookies: None,
            get_raw_body: None,
            get_files: None,
            set_response_header: None,
            remove_response_header: None,
            drop: None,
        }
    }

    /// HTTP method.
    pub fn get_method(
        mut self,
        handler: impl Fn(&TRequest) -> String + Send + Sync + 'static,
    ) -> Self {
        self.get_method = Some(Box::new(handler));
        self
    }

    /// Full request target including the query string (`/a/b?x=1`).
    pub fn get_url(
        mut self,
        handler: impl Fn(&TRequest) -> String + Send + Sync + 'static,
    ) -> Self {
        self.get_url = Some(Box::new(handler));
        self
    }

    /// Path **as it arrived on the wire** (still percent-encoded).
    pub fn get_path(
        mut self,
        handler: impl Fn(&TRequest) -> String + Send + Sync + 'static,
    ) -> Self {
        self.get_path = Some(Box::new(handler));
        self
    }

    /// Raw client address; it is normalized for you. Behind a proxy, derive it
    /// from `X-Forwarded-For` with
    /// [`pick_client_ip_from_xff`](crate::pick_client_ip_from_xff).
    pub fn get_ip(
        mut self,
        handler: impl Fn(&TRequest) -> String + Send + Sync + 'static,
    ) -> Self {
        self.get_ip = Some(Box::new(handler));
        self
    }

    /// `http` / `https`.
    pub fn get_protocol(
        mut self,
        handler: impl Fn(&TRequest) -> String + Send + Sync + 'static,
    ) -> Self {
        self.get_protocol = Some(Box::new(handler));
        self
    }

    /// Port the server accepted the connection on.
    pub fn get_local_port(
        mut self,
        handler: impl Fn(&TRequest, &TResponse) -> u16 + Send + Sync + 'static,
    ) -> Self {
        self.get_local_port = Some(Box::new(handler));
        self
    }

    /// One header by lowercase name.
    #[rustfmt::skip] // rustfmt cannot wrap the bound list below 80 columns.
    pub fn get_header(
        mut self,
        handler: impl Fn(&TRequest, &str) -> Option<String>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.get_header = Some(Box::new(handler));
        self
    }

    /// Every header. Lowercase the names.
    pub fn get_headers(
        mut self,
        handler: impl Fn(&TRequest) -> HeaderMap + Send + Sync + 'static,
    ) -> Self {
        self.get_headers = Some(Box::new(handler));
        self
    }

    /// Parsed query parameters, when the framework already parses them.
    pub fn get_query(
        mut self,
        handler: impl Fn(&TRequest) -> QueryMap + Send + Sync + 'static,
    ) -> Self {
        self.get_query = Some(Box::new(handler));
        self
    }

    /// Parsed cookies, when the framework already parses them.
    pub fn get_cookies(
        mut self,
        handler: impl Fn(&TRequest) -> CookieMap + Send + Sync + 'static,
    ) -> Self {
        self.get_cookies = Some(Box::new(handler));
        self
    }

    /// The request body: a `String`, `Vec<u8>`, `&[u8]`, parsed
    /// [`JsonValue`](crate::JsonValue), an `Option` of those, or a [`RawBody`].
    /// Buffer the body before calling
    /// [`protect`](crate::MiniWafInstance::protect).
    pub fn get_raw_body<B: Into<RawBody>>(
        mut self,
        handler: impl Fn(&TRequest) -> B + Send + Sync + 'static,
    ) -> Self {
        self.get_raw_body =
            Some(Box::new(move |request: &TRequest| handler(request).into()));
        self
    }

    /// Uploaded files (only their names are inspected): a list, or a
    /// [`FilesBag`] map of form field → files.
    pub fn get_files<F: Into<FilesBag>>(
        mut self,
        handler: impl Fn(&TRequest) -> F + Send + Sync + 'static,
    ) -> Self {
        self.get_files =
            Some(Box::new(move |request: &TRequest| handler(request).into()));
        self
    }

    /// Set a response header (used for `X-RateLimit-*`).
    pub fn set_response_header(
        mut self,
        handler: impl Fn(&mut TResponse, &str, &str) + Send + Sync + 'static,
    ) -> Self {
        self.set_response_header = Some(Box::new(handler));
        self
    }

    /// Remove a response header.
    pub fn remove_response_header(
        mut self,
        handler: impl Fn(&mut TResponse, &str) + Send + Sync + 'static,
    ) -> Self {
        self.remove_response_header = Some(Box::new(handler));
        self
    }

    /// End the request with a block response.
    pub fn drop(
        mut self,
        handler: impl Fn(&TRequest, &mut TResponse, u16, &str)
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.drop = Some(Box::new(handler));
        self
    }

    /// Names of the required handlers that were never set.
    fn missing_required(&self) -> Vec<&'static str> {
        [
            ("get_method", self.get_method.is_none()),
            ("get_url", self.get_url.is_none()),
            ("get_ip", self.get_ip.is_none()),
            ("get_headers", self.get_headers.is_none()),
            ("get_raw_body", self.get_raw_body.is_none()),
            ("set_response_header", self.set_response_header.is_none()),
            ("drop", self.drop.is_none()),
        ]
        .into_iter()
        .filter_map(|(name, missing)| missing.then_some(name))
        .collect()
    }
}

/// Returned by [`create_adapter`] when required handlers are missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterBuildError {
    pub missing: Vec<&'static str>,
}

impl fmt::Display for AdapterBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "adapter is missing required handlers: {}",
            self.missing.join(", ")
        )
    }
}

impl std::error::Error for AdapterBuildError {}

/// The [`WafAdapter`] built by [`create_adapter`].
pub struct CustomAdapter<TRequest, TResponse> {
    name: String,
    get_method: ReqFn<TRequest, String>,
    get_url: ReqFn<TRequest, String>,
    get_path: Option<ReqFn<TRequest, String>>,
    get_ip: ReqFn<TRequest, String>,
    get_protocol: Option<ReqFn<TRequest, String>>,
    get_local_port: Option<PortFn<TRequest, TResponse>>,
    get_header: Option<HeaderFn<TRequest>>,
    get_headers: ReqFn<TRequest, HeaderMap>,
    get_query: Option<ReqFn<TRequest, QueryMap>>,
    get_cookies: Option<ReqFn<TRequest, CookieMap>>,
    get_raw_body: ReqFn<TRequest, RawBody>,
    get_files: Option<ReqFn<TRequest, FilesBag>>,
    set_response_header: SetHeaderFn<TResponse>,
    remove_response_header: Option<RemoveHeaderFn<TResponse>>,
    drop: DropFn<TRequest, TResponse>,
}

impl<TRequest, TResponse> fmt::Debug for CustomAdapter<TRequest, TResponse> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomAdapter")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Build a WAF adapter for any framework from typed request / response
/// mappers, or report every required handler that is missing.
pub fn create_adapter<TRequest, TResponse>(
    handlers: CustomAdapterHandlers<TRequest, TResponse>,
) -> Result<CustomAdapter<TRequest, TResponse>, AdapterBuildError> {
    let missing = handlers.missing_required();
    let CustomAdapterHandlers {
        get_method: Some(get_method),
        get_url: Some(get_url),
        get_ip: Some(get_ip),
        get_headers: Some(get_headers),
        get_raw_body: Some(get_raw_body),
        set_response_header: Some(set_response_header),
        drop: Some(drop),
        name,
        get_path,
        get_protocol,
        get_local_port,
        get_header,
        get_query,
        get_cookies,
        get_files,
        remove_response_header,
    } = handlers
    else {
        return Err(AdapterBuildError { missing });
    };

    Ok(CustomAdapter {
        name,
        get_method,
        get_url,
        get_path,
        get_ip,
        get_protocol,
        get_local_port,
        get_header,
        get_headers,
        get_query,
        get_cookies,
        get_raw_body,
        get_files,
        set_response_header,
        remove_response_header,
        drop,
    })
}

impl<TRequest, TResponse> WafAdapter<TRequest, TResponse>
    for CustomAdapter<TRequest, TResponse>
{
    fn name(&self) -> &str {
        &self.name
    }

    /// Map one request / response pair into a context. The URL, path and
    /// body are read eagerly; every other value is read on first use and
    /// cached.
    fn create_context<'a>(
        &'a self,
        request: &'a TRequest,
        response: &'a mut TResponse,
    ) -> Box<dyn WafHttpContext + 'a> {
        let url = (self.get_url)(request);
        let path = match &self.get_path {
            Some(get_path) => get_path(request),
            None => path_of(&url).to_owned(),
        };
        let raw_body = (self.get_raw_body)(request).into_text();
        Box::new(CustomAdapterContext {
            adapter: self,
            request,
            response,
            url,
            path,
            raw_body,
            lazy: LazyValues::default(),
            blocked: false,
        })
    }
}

/// The request target up to the first `?`.
fn path_of(url: &str) -> &str {
    url.split_once('?').map_or(url, |(path, _)| path)
}

/// The request target after the first `?`, or `""`.
fn query_string_of(url: &str) -> &str {
    url.split_once('?').map_or("", |(_, query)| query)
}

/// Values read from the request on first use.
#[derive(Default)]
struct LazyValues {
    method: OnceCell<String>,
    ip: OnceCell<String>,
    protocol: OnceCell<String>,
    headers: OnceCell<HeaderMap>,
    query: OnceCell<QueryMap>,
    cookies: OnceCell<CookieMap>,
    files: OnceCell<Vec<UploadedFile>>,
}

/// The per-request [`WafHttpContext`] a [`CustomAdapter`] produces.
struct CustomAdapterContext<'a, TRequest, TResponse> {
    adapter: &'a CustomAdapter<TRequest, TResponse>,
    request: &'a TRequest,
    response: &'a mut TResponse,
    url: String,
    path: String,
    raw_body: String,
    lazy: LazyValues,
    blocked: bool,
}

impl<TRequest, TResponse> WafHttpContext
    for CustomAdapterContext<'_, TRequest, TResponse>
{
    fn framework(&self) -> &str {
        &self.adapter.name
    }

    fn get_method(&self) -> &str {
        self.lazy
            .method
            .get_or_init(|| (self.adapter.get_method)(self.request))
    }

    fn get_url(&self) -> &str {
        &self.url
    }

    fn get_path(&self) -> &str {
        &self.path
    }

    fn get_ip(&self) -> &str {
        self.lazy.ip.get_or_init(|| {
            normalize_client_ip(&(self.adapter.get_ip)(self.request))
        })
    }

    fn get_protocol(&self) -> &str {
        self.lazy
            .protocol
            .get_or_init(|| match &self.adapter.get_protocol {
                Some(get_protocol) => get_protocol(self.request),
                None => "http".to_owned(),
            })
    }

    fn get_local_port(&self) -> u16 {
        match &self.adapter.get_local_port {
            Some(get_local_port) => get_local_port(self.request, self.response),
            None => 0,
        }
    }

    fn get_header(&self, name: &str) -> Option<String> {
        match &self.adapter.get_header {
            Some(get_header) => get_header(self.request, name),
            None => {
                let value = self.get_headers().get(&name.to_lowercase())?;
                value.first().map(str::to_owned)
            }
        }
    }

    fn get_headers(&self) -> &HeaderMap {
        self.lazy
            .headers
            .get_or_init(|| (self.adapter.get_headers)(self.request))
    }

    fn get_query(&self) -> &QueryMap {
        self.lazy
            .query
            .get_or_init(|| match &self.adapter.get_query {
                Some(get_query) => get_query(self.request),
                None => QueryMap::parse(query_string_of(&self.url)),
            })
    }

    fn get_cookies(&self) -> &CookieMap {
        self.lazy
            .cookies
            .get_or_init(|| match &self.adapter.get_cookies {
                Some(get_cookies) => get_cookies(self.request),
                None => {
                    parse_cookies(self.get_header("cookie").as_deref(), None)
                }
            })
    }

    fn get_raw_body(&self) -> &str {
        &self.raw_body
    }

    fn get_files(&self) -> &[UploadedFile] {
        self.lazy.files.get_or_init(|| {
            let files = self
                .adapter
                .get_files
                .as_ref()
                .map(|get_files| get_files(self.request));
            normalize_files(files)
        })
    }

    fn set_response_header(&mut self, name: &str, value: &str) {
        (self.adapter.set_response_header)(self.response, name, value);
    }

    fn remove_response_header(&mut self, name: &str) {
        if let Some(remove) = &self.adapter.remove_response_header {
            remove(self.response, name);
        }
    }

    fn is_blocked(&self) -> bool {
        self.blocked
    }

    fn drop(&mut self, status_code: Option<u16>, body: Option<&str>) {
        self.blocked = true;
        let status_code = status_code.unwrap_or(DEFAULT_BLOCK_STATUS_CODE);
        (self.adapter.drop)(
            self.request,
            self.response,
            status_code,
            body.unwrap_or(DEFAULT_BLOCK_BODY),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_every_missing_handler() {
        let error = create_adapter(
            CustomAdapterHandlers::<(), ()>::new("incomplete")
                .get_method(|_| "GET".into()),
        )
        .unwrap_err();
        assert_eq!(
            error.missing,
            [
                "get_url",
                "get_ip",
                "get_headers",
                "get_raw_body",
                "set_response_header",
                "drop"
            ]
        );
    }
}
