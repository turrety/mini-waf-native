//! Pointer plumbing shared by every exported function, plus the library-wide
//! exports (`mini_waf_version`, `mini_waf_string_free`).
//!
//! The contract every export relies on (documented for C in the header):
//!
//! - Handles come from the matching constructor and are passed back until their
//!   `*_free`. `NULL` handles are tolerated: getters return `0` / `false` /
//!   `NULL` and `*_free` does nothing.
//! - Input text is `(pointer, length)` UTF-8, copied before the call returns;
//!   invalid sequences are replaced. A `NULL` pointer is the empty string.
//! - Handles passed as inputs are borrowed and cloned, never consumed.
//! - Output text is borrowed from its handle and stays valid until that handle
//!   is freed; the optional `len` out-parameter receives its length.
//! - Callbacks are valid function pointers, called on the evaluating thread.

use std::ffi::{
    CString,
    c_char,
};
use std::{
    ptr,
    slice,
};

use crate::text::{
    CText,
    lossy_text,
};

/// Borrowed text in a list or struct: `MiniWafStr` in C. A `NULL` `data`
/// is `None` where the field is optional, and `""` elsewhere.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MiniWafStr {
    pub data: *const c_char,
    pub len: usize,
}

impl MiniWafStr {
    /// # Safety
    ///
    /// A non-null `data` must point to `len` readable bytes.
    pub unsafe fn to_text(self) -> String {
        // SAFETY: forwarded from the caller.
        unsafe { text(self.data, self.len) }
    }

    /// `None` when `data` is null.
    ///
    /// # Safety
    ///
    /// As [`MiniWafStr::to_text`].
    pub unsafe fn to_option(self) -> Option<String> {
        // SAFETY: forwarded from the caller.
        (!self.data.is_null()).then(|| unsafe { self.to_text() })
    }
}

/// The bytes behind a `(pointer, length)` pair; `NULL` is empty.
///
/// # Safety
///
/// A non-null `data` must point to `len` readable bytes.
pub unsafe fn bytes<'a>(data: *const c_char, len: usize) -> &'a [u8] {
    if data.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: `data` is non-null and the caller vouches for `len` bytes.
    unsafe { slice::from_raw_parts(data.cast(), len) }
}

/// Host text as an owned `String`.
///
/// # Safety
///
/// As [`bytes`].
pub unsafe fn text(data: *const c_char, len: usize) -> String {
    // SAFETY: forwarded from the caller.
    lossy_text(unsafe { bytes(data, len) })
}

/// The items of a `(pointer, count)` array; `NULL` is empty.
///
/// # Safety
///
/// A non-null `items` must point to `count` initialized values.
pub unsafe fn items<'a, T>(items: *const T, count: usize) -> &'a [T] {
    if items.is_null() || count == 0 {
        return &[];
    }
    // SAFETY: `items` is non-null and the caller vouches for `count` items.
    unsafe { slice::from_raw_parts(items, count) }
}

/// Every text of a `MiniWafStr` array.
///
/// # Safety
///
/// As [`items`], and each entry as [`MiniWafStr::to_text`].
pub unsafe fn texts(values: *const MiniWafStr, count: usize) -> Vec<String> {
    // SAFETY: forwarded from the caller.
    unsafe { items(values, count) }
        .iter()
        // SAFETY: forwarded from the caller.
        .map(|value| unsafe { value.to_text() })
        .collect()
}

/// Clones of the values behind an array of handles, skipping `NULL`s.
///
/// # Safety
///
/// As [`items`], and each non-null entry must be a live handle.
pub unsafe fn cloned<T: Clone>(
    handles: *const *const T,
    count: usize,
) -> Vec<T> {
    // SAFETY: forwarded from the caller.
    unsafe { items(handles, count) }
        .iter()
        // SAFETY: each entry is null or a live handle.
        .filter_map(|&handle| unsafe { handle.as_ref() }.cloned())
        .collect()
}

/// Lend `value` to C, writing its length to `len` when it is non-null.
///
/// # Safety
///
/// A non-null `len` must be writable.
pub unsafe fn lend(value: Option<&CText>, len: *mut usize) -> *const c_char {
    // SAFETY: forwarded from the caller.
    unsafe { write(len, value.map_or(0, CText::len)) };
    value.map_or(ptr::null(), CText::as_ptr)
}

/// Write `value` to `out` when it is non-null.
///
/// # Safety
///
/// A non-null `out` must be writable.
pub unsafe fn write<T>(out: *mut T, value: T) {
    if !out.is_null() {
        // SAFETY: non-null and writable per the caller.
        unsafe { out.write(value) };
    }
}

/// Write `value` to `out` and return `true`, or return `false` for `None`.
///
/// # Safety
///
/// As [`write`].
pub unsafe fn write_option<T>(out: *mut T, value: Option<T>) -> bool {
    match value {
        Some(value) => {
            // SAFETY: forwarded from the caller.
            unsafe { write(out, value) };
            true
        }
        None => false,
    }
}

/// Move a value to the heap and hand its ownership to C.
pub fn into_handle<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

/// Take back and drop a handle created by [`into_handle`].
///
/// # Safety
///
/// `handle` must be null or come from `into_handle::<T>`, not yet freed.
pub unsafe fn free_handle<T>(handle: *mut T) {
    if !handle.is_null() {
        // SAFETY: the caller vouches `handle` is a live `Box<T>`.
        drop(unsafe { Box::from_raw(handle) });
    }
}

/// Run `update` on a handle, ignoring `NULL`.
///
/// # Safety
///
/// `handle` must be null or a live handle not used elsewhere meanwhile.
pub unsafe fn update<T>(handle: *mut T, update: impl FnOnce(&mut T)) {
    // SAFETY: forwarded from the caller.
    if let Some(value) = unsafe { handle.as_mut() } {
        update(value);
    }
}

/// A string allocated for C, released with `mini_waf_string_free`.
pub fn owned_string(text: &str) -> *mut c_char {
    CString::new(text.replace('\0', ""))
        .expect("interior NULs were removed")
        .into_raw()
}

/// Write an owned copy of `message` to `error` when it is non-null.
///
/// # Safety
///
/// A non-null `error` must be writable.
pub unsafe fn report(error: *mut *mut c_char, message: &str) {
    if !error.is_null() {
        // SAFETY: non-null and writable per the caller.
        unsafe { error.write(owned_string(message)) };
    }
}

/// Return the handle, or report the failure through `error` and return
/// `NULL`.
///
/// # Safety
///
/// As [`report`].
pub unsafe fn handle_or_report<T, E: ToString>(
    result: Result<T, E>,
    error: *mut *mut c_char,
) -> *mut T {
    match result {
        Ok(value) => into_handle(value),
        Err(failure) => {
            // SAFETY: forwarded from the caller.
            unsafe { report(error, &failure.to_string()) };
            ptr::null_mut()
        }
    }
}

static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

#[unsafe(no_mangle)]
pub extern "C" fn mini_waf_version() -> *const c_char {
    VERSION.as_ptr().cast()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_string_free(string: *mut c_char) {
    if !string.is_null() {
        // SAFETY: strings handed to C come from `CString::into_raw`.
        drop(unsafe { CString::from_raw(string) });
    }
}
