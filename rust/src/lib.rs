//! # mini-waf
//!
//! A minimalistic, framework-agnostic Web Application Firewall engine.
//!
//! - **Declarative rules**: field conditions (`matches` / `equals` / `includes`
//!   / `rate_limit`) composed with `all`, `any_of` and `not`.
//! - **Presets** derived from OWASP CRS categories (SQLi, XSS, RCE, RFI, path
//!   traversal, protocol, scanners), gated by four protection levels.
//! - **One universal adapter**: describe how to read your server's request and
//!   write its response once ([`create_adapter`]), then call
//!   [`MiniWafInstance::protect`] per request.
//! - **Linear-time matching**: patterns run on the [`regex`] crate, so no
//!   payload can drive a rule into catastrophic backtracking.
//!
//! This is a Rust port of the TypeScript `mini-waf`, with the same API: every
//! name is the TypeScript one in Rust casing (`createMiniWaf` →
//! [`create_mini_waf`], `getRawBody` → `get_raw_body`), string unions are
//! enums, and optional parameters and fields are `Option`s.
//!
//! ```
//! use mini_waf::{
//!     CustomAdapterHandlers,
//!     FieldCondition,
//!     HeaderMap,
//!     ProtectionLevel,
//!     RateLimitSpec,
//!     WafAction,
//!     WafCondition,
//!     WafConfig,
//!     WafField,
//!     WafPresetName,
//!     WafRule,
//!     create_adapter,
//!     create_mini_waf,
//! };
//!
//! // 1. Build the WAF once, at startup.
//! let waf = create_mini_waf(
//!     WafConfig::default()
//!         .presets([WafPresetName::Default])
//!         .level(ProtectionLevel::Balanced)
//!         .rules([
//!             WafRule::new(
//!                 "allow-health",
//!                 FieldCondition::new(WafField::Path).equals("/health"),
//!                 WafAction::Allow,
//!             )
//!             .priority(1),
//!             WafRule::new(
//!                 "login-rate-limit",
//!                 WafCondition::all([
//!                     FieldCondition::new(WafField::Path)
//!                         .equals("/login")
//!                         .into(),
//!                     FieldCondition::new(WafField::Ip)
//!                         .rate_limit(RateLimitSpec::new(5, 60_000))
//!                         .into(),
//!                 ]),
//!                 WafAction::Block,
//!             )
//!             .reason("Too many login attempts"),
//!         ]),
//!     None,
//! );
//!
//! // 2. Describe your server's request / response types once.
//! struct Req {
//!     method: &'static str,
//!     url: &'static str,
//!     peer: &'static str,
//! }
//! #[derive(Default)]
//! struct Res {
//!     status: u16,
//! }
//!
//! let adapter = create_adapter(
//!     CustomAdapterHandlers::<Req, Res>::new("example")
//!         .get_method(|r| r.method.into())
//!         .get_url(|r| r.url.into())
//!         .get_ip(|r| r.peer.into())
//!         .get_headers(|_| {
//!             HeaderMap::from([("user-agent", "Mozilla/5.0".into())])
//!         })
//!         .get_raw_body(|_| "")
//!         .set_response_header(|_, _, _| {})
//!         .drop(|_, res, status, _| res.status = status),
//! )
//! .unwrap();
//!
//! // 3. Evaluate every request.
//! let request = Req {
//!     method: "GET",
//!     url: "/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users",
//!     peer: "198.51.100.4",
//! };
//! let mut response = Res::default();
//! let result = waf.protect(&adapter, &request, &mut response);
//! assert_eq!(
//!     result.matched_rule.map(|rule| rule.id.as_str()),
//!     Some("preset-sqli-classic-query")
//! );
//! assert_eq!(response.status, 403);
//! ```

mod adapters;
mod domain;
mod engine;
mod logging;
mod presets;
mod utils;

pub use adapters::*;
pub use domain::*;
pub use engine::*;
pub use logging::*;
pub use presets::*;
pub use utils::cookies::{
    CookieDecoder,
    parse_cookies,
};
pub use utils::ip::{
    clear_ip_normalize_cache,
    ip_normalize_cache_size,
    is_host_ip_literal,
    normalize_client_ip,
    pick_client_ip_from_xff,
};

/// Compiles and runs every Rust snippet of the README as a doc test.
#[cfg(doctest)]
#[doc = include_str!("../../README.md")]
pub struct ReadmeDoctests;
