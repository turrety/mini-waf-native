//! `CustomAdapterHandlers` with C callbacks, `create_adapter`, and the
//! `CustomAdapter` it builds.

use std::ffi::{
    c_char,
    c_void,
};

use waf::{
    CookieMap,
    CustomAdapter,
    CustomAdapterHandlers,
    FilesBag,
    HeaderMap,
    QueryMap,
    RawBody,
    create_adapter,
};

use crate::ffi::{
    free_handle,
    handle_or_report,
    into_handle,
    text,
    update,
};
use crate::values::MiniWafString;

/// The request pointer handed to `protect`, passed back to every callback.
pub struct ForeignRequest(pub *const c_void);
/// The response pointer handed to `protect`, passed back to every callback.
pub struct ForeignResponse(pub *mut c_void);

pub type ForeignAdapter = CustomAdapter<ForeignRequest, ForeignResponse>;

type RequestTextFn = unsafe extern "C" fn(*const c_void, *mut MiniWafString);
type LocalPortFn = unsafe extern "C" fn(*const c_void, *const c_void) -> u16;
type HeaderFn = unsafe extern "C" fn(
    *const c_void,
    *const c_char,
    usize,
    *mut MiniWafString,
) -> bool;
type HeadersFn = unsafe extern "C" fn(*const c_void, *mut HeaderMap);
type QueryFn = unsafe extern "C" fn(*const c_void, *mut QueryMap);
type CookiesFn = unsafe extern "C" fn(*const c_void, *mut CookieMap);
type RawBodyFn = unsafe extern "C" fn(*const c_void, *mut RawBody);
type FilesFn = unsafe extern "C" fn(*const c_void, *mut FilesBag);
type SetHeaderFn = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    usize,
    *const c_char,
    usize,
);
type RemoveHeaderFn = unsafe extern "C" fn(*mut c_void, *const c_char, usize);
type DropFn =
    unsafe extern "C" fn(*const c_void, *mut c_void, u16, *const c_char, usize);

/// The C `CustomAdapterHandlers`: the adapter name and whichever callbacks
/// were set.
#[derive(Clone, Default)]
pub struct ForeignAdapterHandlers {
    name: String,
    get_method: Option<RequestTextFn>,
    get_url: Option<RequestTextFn>,
    get_path: Option<RequestTextFn>,
    get_ip: Option<RequestTextFn>,
    get_protocol: Option<RequestTextFn>,
    get_local_port: Option<LocalPortFn>,
    get_header: Option<HeaderFn>,
    get_headers: Option<HeadersFn>,
    get_query: Option<QueryFn>,
    get_cookies: Option<CookiesFn>,
    get_raw_body: Option<RawBodyFn>,
    get_files: Option<FilesFn>,
    set_response_header: Option<SetHeaderFn>,
    remove_response_header: Option<RemoveHeaderFn>,
    drop: Option<DropFn>,
}

/// Call a request callback that writes a string.
///
/// # Safety
///
/// `callback` must accept `request`.
unsafe fn read_text(
    callback: RequestTextFn,
    request: &ForeignRequest,
) -> String {
    let mut out = MiniWafString::default();
    // SAFETY: forwarded from the caller.
    unsafe { callback(request.0, &mut out) };
    out.0
}

type Handlers = CustomAdapterHandlers<ForeignRequest, ForeignResponse>;

/// A handler reading one string through `callback`.
///
/// # Safety
///
/// `callback` must accept every request later passed to the handler.
unsafe fn text_reader(
    callback: RequestTextFn,
) -> impl Fn(&ForeignRequest) -> String + Send + Sync + 'static {
    // SAFETY: forwarded from the caller.
    move |request| unsafe { read_text(callback, request) }
}

/// A handler filling a value, starting from `empty()`, through `callback`.
///
/// # Safety
///
/// As [`text_reader`].
unsafe fn reader<T: 'static>(
    callback: unsafe extern "C" fn(*const c_void, *mut T),
    empty: fn() -> T,
) -> impl Fn(&ForeignRequest) -> T + Send + Sync + 'static {
    move |request| {
        let mut out = empty();
        // SAFETY: forwarded from the caller.
        unsafe { callback(request.0, &mut out) };
        out
    }
}

impl ForeignAdapterHandlers {
    /// The same handlers as Rust closures over the C callbacks.
    ///
    /// # Safety
    ///
    /// Every callback must accept the request / response pointers later
    /// passed to `protect`.
    unsafe fn to_handlers(&self) -> Handlers {
        let mut handlers = Handlers::new(self.name.clone());
        // SAFETY: here and in every handler below, the caller vouches each
        // callback accepts the pointers `protect` forwards; borrowed strings
        // outlive each call.
        unsafe {
            if let Some(callback) = self.get_method {
                handlers = handlers.get_method(text_reader(callback));
            }
            if let Some(callback) = self.get_url {
                handlers = handlers.get_url(text_reader(callback));
            }
            if let Some(callback) = self.get_path {
                handlers = handlers.get_path(text_reader(callback));
            }
            if let Some(callback) = self.get_ip {
                handlers = handlers.get_ip(text_reader(callback));
            }
            if let Some(callback) = self.get_protocol {
                handlers = handlers.get_protocol(text_reader(callback));
            }
            if let Some(callback) = self.get_headers {
                handlers =
                    handlers.get_headers(reader(callback, HeaderMap::new));
            }
            if let Some(callback) = self.get_query {
                handlers = handlers.get_query(reader(callback, QueryMap::new));
            }
            if let Some(callback) = self.get_cookies {
                handlers =
                    handlers.get_cookies(reader(callback, CookieMap::new));
            }
            if let Some(callback) = self.get_raw_body {
                handlers =
                    handlers.get_raw_body(reader(callback, || RawBody::Empty));
            }
            if let Some(callback) = self.get_files {
                let empty = || FilesBag::List(Vec::new());
                handlers = handlers.get_files(reader(callback, empty));
            }
        }
        if let Some(callback) = self.get_local_port {
            handlers = handlers.get_local_port(move |request, response| {
                // SAFETY: see above.
                unsafe { callback(request.0, response.0) }
            });
        }
        if let Some(callback) = self.get_header {
            handlers = handlers.get_header(move |request, name| {
                let mut out = MiniWafString::default();
                // SAFETY: see above.
                let found = unsafe {
                    callback(
                        request.0,
                        name.as_ptr().cast(),
                        name.len(),
                        &mut out,
                    )
                };
                found.then_some(out.0)
            });
        }
        if let Some(callback) = self.set_response_header {
            handlers =
                handlers.set_response_header(move |response, name, value| {
                    let (value_data, value_len) =
                        (value.as_ptr().cast(), value.len());
                    // SAFETY: see above.
                    unsafe {
                        callback(
                            response.0,
                            name.as_ptr().cast(),
                            name.len(),
                            value_data,
                            value_len,
                        );
                    }
                });
        }
        if let Some(callback) = self.remove_response_header {
            handlers =
                handlers.remove_response_header(move |response, name| {
                    // SAFETY: see above.
                    unsafe {
                        callback(response.0, name.as_ptr().cast(), name.len())
                    }
                });
        }
        if let Some(callback) = self.drop {
            handlers = handlers.drop(move |request, response, status, body| {
                let (body_data, body_len) = (body.as_ptr().cast(), body.len());
                // SAFETY: see above.
                unsafe {
                    callback(
                        request.0, response.0, status, body_data, body_len,
                    );
                }
            });
        }
        handlers
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_custom_adapter_handlers_new(
    name: *const c_char,
    name_len: usize,
) -> *mut ForeignAdapterHandlers {
    // SAFETY: the caller upholds the module contract for every pointer.
    let name = unsafe { text(name, name_len) };
    into_handle(ForeignAdapterHandlers {
        name,
        ..ForeignAdapterHandlers::default()
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_custom_adapter_handlers_free(
    handlers: *mut ForeignAdapterHandlers,
) {
    // SAFETY: `handlers` is null or a live handle.
    unsafe { free_handle(handlers) }
}

/// One exported setter per handler, named after it.
macro_rules! handler_setters {
    ($($setter:ident => $field:ident: $callback:ty;)*) => {$(
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $setter(
            handlers: *mut ForeignAdapterHandlers,
            callback: Option<$callback>,
        ) {
            // SAFETY: `handlers` is null or a live, unshared handle.
            unsafe { update(handlers, |handlers| handlers.$field = callback) }
        }
    )*};
}

handler_setters! {
    mini_waf_custom_adapter_handlers_get_method => get_method: RequestTextFn;
    mini_waf_custom_adapter_handlers_get_url => get_url: RequestTextFn;
    mini_waf_custom_adapter_handlers_get_path => get_path: RequestTextFn;
    mini_waf_custom_adapter_handlers_get_ip => get_ip: RequestTextFn;
    mini_waf_custom_adapter_handlers_get_protocol => get_protocol: RequestTextFn;
    mini_waf_custom_adapter_handlers_get_local_port => get_local_port: LocalPortFn;
    mini_waf_custom_adapter_handlers_get_header => get_header: HeaderFn;
    mini_waf_custom_adapter_handlers_get_headers => get_headers: HeadersFn;
    mini_waf_custom_adapter_handlers_get_query => get_query: QueryFn;
    mini_waf_custom_adapter_handlers_get_cookies => get_cookies: CookiesFn;
    mini_waf_custom_adapter_handlers_get_raw_body => get_raw_body: RawBodyFn;
    mini_waf_custom_adapter_handlers_get_files => get_files: FilesFn;
    mini_waf_custom_adapter_handlers_set_response_header => set_response_header: SetHeaderFn;
    mini_waf_custom_adapter_handlers_remove_response_header => remove_response_header: RemoveHeaderFn;
    mini_waf_custom_adapter_handlers_drop => drop: DropFn;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_create_adapter(
    handlers: *const ForeignAdapterHandlers,
    error: *mut *mut c_char,
) -> *mut ForeignAdapter {
    // SAFETY: `handlers` is null or a live handle.
    let handlers = unsafe { handlers.as_ref() }.cloned().unwrap_or_default();
    // SAFETY: the header requires the callbacks to accept the pointers
    // later passed to `protect`; `error` is null or writable.
    unsafe { handle_or_report(create_adapter(handlers.to_handlers()), error) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_custom_adapter_free(
    adapter: *mut ForeignAdapter,
) {
    // SAFETY: `adapter` is null or a live handle.
    unsafe { free_handle(adapter) }
}
