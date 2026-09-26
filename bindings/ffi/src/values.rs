//! HTTP values host callbacks fill in: `MiniWafString`, `HeaderMap`,
//! `QueryMap` / `QueryValue`, `CookieMap`, `RawBody` and `FilesBag`, plus
//! the IP helpers.

use std::ffi::c_char;
use std::ptr;

use waf::{
    CookieMap,
    FilesBag,
    HeaderMap,
    HeaderValue,
    QueryMap,
    QueryValue,
    RawBody,
    UploadedFile,
    is_host_ip_literal,
    normalize_client_ip,
    pick_client_ip_from_xff,
};

use crate::ffi::{
    MiniWafStr,
    bytes,
    cloned,
    free_handle,
    into_handle,
    items,
    owned_string,
    text,
    texts,
    update,
};

/// A string a callback returns: `MiniWafString` in C, written with
/// `mini_waf_string_set`.
#[derive(Debug, Default)]
pub struct MiniWafString(pub String);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_string_set(
    out: *mut MiniWafString,
    value: *const c_char,
    value_len: usize,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let value = text(value, value_len);
        update(out, |out| out.0 = value);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_header_map_insert(
    headers: *mut HeaderMap,
    name: *const c_char,
    name_len: usize,
    values: *const MiniWafStr,
    count: usize,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let name = text(name, name_len);
        let value = match texts(values, count) {
            values if values.len() == 1 => HeaderValue::from(values[0].clone()),
            values => HeaderValue::Multi(values),
        };
        update(headers, |headers| headers.insert(name, value));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn mini_waf_query_map_new() -> *mut QueryMap {
    into_handle(QueryMap::new())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_query_map_parse(
    query: *const c_char,
    query_len: usize,
) -> *mut QueryMap {
    // SAFETY: the caller upholds the module contract for every pointer.
    into_handle(QueryMap::parse(&unsafe { text(query, query_len) }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_query_map_insert(
    query: *mut QueryMap,
    key: *const c_char,
    key_len: usize,
    value: *const QueryValue,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let key = text(key, key_len);
        if let Some(value) = value.as_ref() {
            update(query, |query| query.insert(key, value.clone()));
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_query_map_free(query: *mut QueryMap) {
    // SAFETY: `query` is null or a live handle.
    unsafe { free_handle(query) }
}

#[unsafe(no_mangle)]
pub extern "C" fn mini_waf_query_value_null() -> *mut QueryValue {
    into_handle(QueryValue::Null)
}

#[unsafe(no_mangle)]
pub extern "C" fn mini_waf_query_value_bool(value: bool) -> *mut QueryValue {
    into_handle(QueryValue::Bool(value))
}

#[unsafe(no_mangle)]
pub extern "C" fn mini_waf_query_value_number(value: f64) -> *mut QueryValue {
    into_handle(QueryValue::Number(value))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_query_value_string(
    value: *const c_char,
    value_len: usize,
) -> *mut QueryValue {
    // SAFETY: the caller upholds the module contract for every pointer.
    into_handle(QueryValue::String(unsafe { text(value, value_len) }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_query_value_array(
    values: *const *const QueryValue,
    count: usize,
) -> *mut QueryValue {
    // SAFETY: the caller upholds the module contract for every pointer.
    into_handle(QueryValue::Array(unsafe { cloned(values, count) }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_query_value_object(
    map: *const QueryMap,
) -> *mut QueryValue {
    // SAFETY: `map` is null or a live handle.
    match unsafe { map.as_ref() } {
        Some(map) => into_handle(QueryValue::Object(map.clone())),
        None => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_query_value_free(value: *mut QueryValue) {
    // SAFETY: `value` is null or a live handle.
    unsafe { free_handle(value) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_cookie_map_insert(
    cookies: *mut CookieMap,
    name: *const c_char,
    name_len: usize,
    value: *const c_char,
    value_len: usize,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let (name, value) = (text(name, name_len), text(value, value_len));
        update(cookies, |cookies| cookies.insert(name, value));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_raw_body_text(
    body: *mut RawBody,
    value: *const c_char,
    value_len: usize,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let value = text(value, value_len);
        update(body, |body| *body = RawBody::Text(value));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_raw_body_bytes(
    body: *mut RawBody,
    value: *const c_char,
    value_len: usize,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let value = bytes(value, value_len).to_vec();
        update(body, |body| *body = RawBody::Bytes(value));
    }
}

/// `UploadedFile` in C: `NULL` members are `None`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForeignUploadedFile {
    pub fieldname: MiniWafStr,
    pub name: MiniWafStr,
    pub filename: MiniWafStr,
    pub originalname: MiniWafStr,
}

impl ForeignUploadedFile {
    /// # Safety
    ///
    /// Every member must satisfy [`MiniWafStr::to_option`].
    unsafe fn to_file(self) -> UploadedFile {
        // SAFETY: forwarded from the caller.
        unsafe {
            UploadedFile {
                fieldname: self.fieldname.to_option(),
                name: self.name.to_option(),
                filename: self.filename.to_option(),
                originalname: self.originalname.to_option(),
            }
        }
    }
}

/// # Safety
///
/// As [`items`], and each file as [`ForeignUploadedFile::to_file`].
unsafe fn uploaded_files(
    files: *const ForeignUploadedFile,
    count: usize,
) -> Vec<UploadedFile> {
    // SAFETY: forwarded from the caller.
    unsafe { items(files, count) }
        .iter()
        // SAFETY: forwarded from the caller.
        .map(|file| unsafe { file.to_file() })
        .collect()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_files_bag_list(
    bag: *mut FilesBag,
    files: *const ForeignUploadedFile,
    count: usize,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let files = uploaded_files(files, count);
        update(bag, |bag| *bag = FilesBag::List(files));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_files_bag_fields_insert(
    bag: *mut FilesBag,
    fieldname: *const c_char,
    fieldname_len: usize,
    files: *const ForeignUploadedFile,
    count: usize,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let fieldname = text(fieldname, fieldname_len);
        let files = uploaded_files(files, count);
        update(bag, |bag| insert_field(bag, fieldname, files));
    }
}

/// Add one form field to a bag, turning a list bag into a fields bag.
fn insert_field(
    bag: &mut FilesBag,
    fieldname: String,
    files: Vec<UploadedFile>,
) {
    if let FilesBag::List(_) = bag {
        *bag = FilesBag::Fields(Default::default());
    }
    if let FilesBag::Fields(fields) = bag {
        fields.insert(fieldname, files);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_normalize_client_ip(
    raw: *const c_char,
    raw_len: usize,
) -> *mut c_char {
    // SAFETY: the caller upholds the module contract for every pointer.
    owned_string(&normalize_client_ip(&unsafe { text(raw, raw_len) }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_pick_client_ip_from_xff(
    forwarded_for: *const c_char,
    forwarded_for_len: usize,
) -> *mut c_char {
    // SAFETY: the caller upholds the module contract for every pointer.
    let forwarded_for = unsafe { text(forwarded_for, forwarded_for_len) };
    owned_string(&pick_client_ip_from_xff(&forwarded_for))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_is_host_ip_literal(
    host_header: *const c_char,
    host_header_len: usize,
) -> bool {
    // SAFETY: the caller upholds the module contract for every pointer.
    is_host_ip_literal(&unsafe { text(host_header, host_header_len) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fields_bag_replaces_a_list() {
        let mut bag = FilesBag::List(vec![UploadedFile::named("a.txt")]);
        insert_field(&mut bag, "avatar".into(), vec![UploadedFile::named("b")]);
        insert_field(&mut bag, "cv".into(), vec![UploadedFile::named("c")]);
        let FilesBag::Fields(fields) = bag else {
            panic!("expected a fields bag");
        };
        assert_eq!(fields.keys().collect::<Vec<_>>(), ["avatar", "cv"]);
    }
}
