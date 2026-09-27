//! HTTP values host callbacks fill in: `MiniWafString`, `HeaderMap`,
//! `QueryMap` / `QueryValue`, `CookieMap`, `RawBody` and `FilesBag`; the
//! readers of the maps a logger receives; and the IP helpers.

use std::ffi::c_char;
use std::ptr;

use waf::{
    CookieMap,
    FilesBag,
    HeaderMap,
    HeaderValue,
    OrderedMap,
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
    write,
    write_option,
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

/// Entry `index` of an ordered map, or `None` past the end.
///
/// # Safety
///
/// `map` must be null or point to a live map.
unsafe fn entry_at<'a, V>(
    map: *const OrderedMap<V>,
    index: usize,
) -> Option<(&'a String, &'a V)> {
    // SAFETY: forwarded from the caller.
    unsafe { map.as_ref() }.and_then(|map| map.iter().nth(index))
}

/// The number of entries of a map, `0` for `NULL`.
///
/// # Safety
///
/// `map` must be null or point to a live map.
unsafe fn map_len<V>(map: *const OrderedMap<V>) -> usize {
    // SAFETY: forwarded from the caller.
    unsafe { map.as_ref() }.map_or(0, OrderedMap::len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_header_map_len(
    headers: *const HeaderMap,
) -> usize {
    // SAFETY: `headers` is null or a live map.
    unsafe { map_len(headers) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_header_map_get_at(
    headers: *const HeaderMap,
    index: usize,
    name: *mut MiniWafStr,
    multi: *mut bool,
    value_count: *mut usize,
) -> bool {
    // SAFETY: `headers` is null or a live map.
    let Some((key, value)) = (unsafe { entry_at(headers, index) }) else {
        return false;
    };
    let (is_multi, count) = match value {
        HeaderValue::Single(_) => (false, 1),
        HeaderValue::Multi(values) => (true, values.len()),
    };
    // SAFETY: every out-pointer is null or writable.
    unsafe {
        write(name, MiniWafStr::of(key));
        write(multi, is_multi);
        write(value_count, count);
    }
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_header_map_get_value_at(
    headers: *const HeaderMap,
    index: usize,
    value_index: usize,
    value: *mut MiniWafStr,
) -> bool {
    // SAFETY: `headers` is null or a live map.
    let found =
        unsafe { entry_at(headers, index) }.and_then(
            |(_, header)| match header {
                HeaderValue::Single(text) => (value_index == 0).then_some(text),
                HeaderValue::Multi(values) => values.get(value_index),
            },
        );
    // SAFETY: `value` is null or writable.
    unsafe { write_option(value, found.map(|text| MiniWafStr::of(text))) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_cookie_map_len(
    cookies: *const CookieMap,
) -> usize {
    // SAFETY: `cookies` is null or a live map.
    unsafe { map_len(cookies) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_cookie_map_get_at(
    cookies: *const CookieMap,
    index: usize,
    name: *mut MiniWafStr,
    value: *mut MiniWafStr,
) -> bool {
    // SAFETY: `cookies` is null or a live map.
    let Some((key, text)) = (unsafe { entry_at(cookies, index) }) else {
        return false;
    };
    // SAFETY: both out-pointers are null or writable.
    unsafe {
        write(name, MiniWafStr::of(key));
        write(value, MiniWafStr::of(text));
    }
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_query_map_len(
    query: *const QueryMap,
) -> usize {
    // SAFETY: `query` is null or a live map.
    unsafe { map_len(query) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_query_map_get_at(
    query: *const QueryMap,
    index: usize,
    key: *mut MiniWafStr,
) -> *const QueryValue {
    // SAFETY: `query` is null or a live map.
    let Some((name, value)) = (unsafe { entry_at(query, index) }) else {
        return ptr::null();
    };
    // SAFETY: `key` is null or writable.
    unsafe { write(key, MiniWafStr::of(name)) };
    value
}

/// `QueryValueKind` in C, in declaration order.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_query_value_kind(
    value: *const QueryValue,
) -> u32 {
    // SAFETY: `value` is null or a live value.
    match unsafe { value.as_ref() } {
        None | Some(QueryValue::Null) => 0,
        Some(QueryValue::Bool(_)) => 1,
        Some(QueryValue::Number(_)) => 2,
        Some(QueryValue::String(_)) => 3,
        Some(QueryValue::Array(_)) => 4,
        Some(QueryValue::Object(_)) => 5,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_query_value_get_bool(
    value: *const QueryValue,
) -> bool {
    // SAFETY: `value` is null or a live value.
    matches!(unsafe { value.as_ref() }, Some(QueryValue::Bool(true)))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_query_value_get_number(
    value: *const QueryValue,
) -> f64 {
    // SAFETY: `value` is null or a live value.
    match unsafe { value.as_ref() } {
        Some(QueryValue::Number(number)) => *number,
        _ => 0.0,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_query_value_get_string(
    value: *const QueryValue,
    out: *mut MiniWafStr,
) -> bool {
    // SAFETY: `value` is null or a live value.
    let text = match unsafe { value.as_ref() } {
        Some(QueryValue::String(text)) => Some(MiniWafStr::of(text)),
        _ => None,
    };
    // SAFETY: `out` is null or writable.
    unsafe { write_option(out, text) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_query_value_array_len(
    value: *const QueryValue,
) -> usize {
    // SAFETY: `value` is null or a live value.
    match unsafe { value.as_ref() } {
        Some(QueryValue::Array(values)) => values.len(),
        _ => 0,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_query_value_array_get(
    value: *const QueryValue,
    index: usize,
) -> *const QueryValue {
    // SAFETY: `value` is null or a live value.
    match unsafe { value.as_ref() } {
        Some(QueryValue::Array(values)) => {
            values.get(index).map_or(ptr::null(), ptr::from_ref)
        }
        _ => ptr::null(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_query_value_get_object(
    value: *const QueryValue,
) -> *const QueryMap {
    // SAFETY: `value` is null or a live value.
    match unsafe { value.as_ref() } {
        Some(QueryValue::Object(map)) => map,
        _ => ptr::null(),
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
    /// Borrow `file`: valid while `file` is.
    pub fn of(file: &UploadedFile) -> Self {
        Self {
            fieldname: MiniWafStr::of_option(file.fieldname.as_deref()),
            name: MiniWafStr::of_option(file.name.as_deref()),
            filename: MiniWafStr::of_option(file.filename.as_deref()),
            originalname: MiniWafStr::of_option(file.originalname.as_deref()),
        }
    }

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
