//! # mini-waf-ffi
//!
//! The C ABI of the `mini-waf` crate (imported as `waf`), built as
//! `libmini_waf` (`.so` / `.dylib` / `.dll`, plus a static library): the one
//! native layer under the C, C++, Java and .NET bindings (`c/`, `cpp/`,
//! `java/`, `dotnet/`).
//!
//! It mirrors the Rust API name for name: `waf::create_mini_waf` is
//! `mini_waf_create_mini_waf`, `WafRule::reason` is `mini_waf_waf_rule_reason`,
//! a public field `WafRule::id` is read with `mini_waf_waf_rule_get_id`. The
//! declarations live in `c/include/mini_waf.h`; a test keeps the
//! header and the exported functions in sync.

#![warn(clippy::undocumented_unsafe_blocks)]
// The safety contract is documented once, in `ffi.rs` and the header,
// rather than on each exported function.
#![allow(clippy::missing_safety_doc)]

mod adapter;
mod config;
mod context;
mod enums;
mod ffi;
mod instance;
mod logger;
mod rate_limit;
mod rules;
mod text;
mod values;
