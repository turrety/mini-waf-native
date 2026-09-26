//! The framework-agnostic request view the engine evaluates, and the adapter
//! that produces it.

use crate::domain::values::{
    CookieMap,
    HeaderMap,
    QueryMap,
    UploadedFile,
};

/// Status code of a block response when none is configured.
pub(crate) const DEFAULT_BLOCK_STATUS_CODE: u16 = 403;
/// Body of a block response when none is configured.
pub(crate) const DEFAULT_BLOCK_BODY: &str = "Forbidden";

/// Framework-agnostic HTTP view consumed by the WAF engine. Adapters map a
/// framework's request / response onto this shape.
///
/// The engine resolves **every** rule field exclusively through these
/// methods, so an implementation returning the wrong value for
/// [`get_ip`](WafHttpContext::get_ip) silently breaks every `ip` rule and
/// rate-limit bucket. Most applications get one from
/// [`create_adapter`](crate::create_adapter) instead of implementing it.
pub trait WafHttpContext {
    /// Name of the integration, for logs.
    fn framework(&self) -> &str;

    fn get_method(&self) -> &str;
    /// Full request target, including the query string.
    fn get_url(&self) -> &str;
    /// Path without the query string, **as it arrived on the wire** (still
    /// percent-encoded): the traversal rules depend on seeing the encoding.
    fn get_path(&self) -> &str;
    /// Normalized client IP (see
    /// [`normalize_client_ip`](crate::normalize_client_ip)).
    fn get_ip(&self) -> &str;
    fn get_protocol(&self) -> &str;
    fn get_local_port(&self) -> u16;

    /// One header by (lowercase) name.
    fn get_header(&self, name: &str) -> Option<String>;
    fn get_headers(&self) -> &HeaderMap;
    fn get_query(&self) -> &QueryMap;
    fn get_cookies(&self) -> &CookieMap;
    fn get_raw_body(&self) -> &str;
    fn get_files(&self) -> &[UploadedFile];

    fn set_response_header(&mut self, name: &str, value: &str);
    fn remove_response_header(&mut self, name: &str);

    fn is_blocked(&self) -> bool;
    /// Ends the request with a block response. Defaults: status 403, body
    /// `"Forbidden"`.
    fn drop(&mut self, status_code: Option<u16>, body: Option<&str>);
}

/// Maps a framework's request / response pair into a [`WafHttpContext`].
pub trait WafAdapter<TRequest, TResponse> {
    fn name(&self) -> &str;

    fn create_context<'a>(
        &'a self,
        request: &'a TRequest,
        response: &'a mut TResponse,
    ) -> Box<dyn WafHttpContext + 'a>;
}
