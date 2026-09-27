//! `RateLimitStore`: the rate-limit buckets, shareable between instances so
//! a rebuilt instance keeps counting where the old one left off.

use std::sync::Arc;

use waf::{
    RateLimitStore,
    RateLimitStoreOptions,
};

use crate::ffi::{
    free_handle,
    into_handle,
};

/// The C `RateLimitStore`: a shared reference to the store, so engines and
/// the caller can hold it at once.
pub struct StoreHandle(pub Arc<RateLimitStore>);

/// `RateLimitStoreOptions` in C: `NULL` members take the default.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForeignRateLimitStoreOptions {
    pub max_keys: *const usize,
    pub idle_ms: *const i64,
    pub prune_every_hits: *const u64,
}

/// Read an optional value: `NULL` is `None`.
///
/// # Safety
///
/// A non-null `value` must point to an initialized `T`.
unsafe fn optional<T: Copy>(value: *const T) -> Option<T> {
    // SAFETY: forwarded from the caller.
    unsafe { value.as_ref() }.copied()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_rate_limit_store_new(
    options: ForeignRateLimitStoreOptions,
) -> *mut StoreHandle {
    // SAFETY: each member is null or points to a value (header contract).
    let options = unsafe {
        RateLimitStoreOptions {
            max_keys: optional(options.max_keys),
            idle_ms: optional(options.idle_ms),
            prune_every_hits: optional(options.prune_every_hits),
        }
    };
    into_handle(StoreHandle(Arc::new(RateLimitStore::new(None, options))))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_rate_limit_store_free(
    store: *mut StoreHandle,
) {
    // SAFETY: `store` is null or a live handle.
    unsafe { free_handle(store) }
}
