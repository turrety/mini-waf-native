//! Standalone helpers: cookies, client IPs and the LRU, plus the Rust-only
//! pieces the TypeScript version gets from the platform (JSON, encodings,
//! clock, ordered maps).

pub(crate) mod cookies;
pub(crate) mod encoding;
pub(crate) mod ip;
pub(crate) mod json;
pub(crate) mod lru;
pub(crate) mod ordered_map;
pub(crate) mod time;
