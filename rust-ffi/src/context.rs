//! `WafHttpContext` implemented by C: a table of callbacks the engine reads
//! the request through, for `mini_waf_mini_waf_instance_handle`.

use std::cell::OnceCell;
use std::ffi::{
    c_char,
    c_void,
};
use std::ptr;

use waf::{
    CookieMap,
    FilesBag,
    HeaderMap,
    QueryMap,
    UploadedFile,
    WafHttpContext,
    normalize_files,
};

use crate::values::MiniWafString;

type TextFn = unsafe extern "C" fn(*mut c_void, *mut MiniWafString);
type PortFn = unsafe extern "C" fn(*mut c_void) -> u16;
type HeaderFn = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    usize,
    *mut MiniWafString,
) -> bool;
type HeadersFn = unsafe extern "C" fn(*mut c_void, *mut HeaderMap);
type QueryFn = unsafe extern "C" fn(*mut c_void, *mut QueryMap);
type CookiesFn = unsafe extern "C" fn(*mut c_void, *mut CookieMap);
type FilesFn = unsafe extern "C" fn(*mut c_void, *mut FilesBag);
type SetHeaderFn = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    usize,
    *const c_char,
    usize,
);
type RemoveHeaderFn = unsafe extern "C" fn(*mut c_void, *const c_char, usize);
type IsBlockedFn = unsafe extern "C" fn(*mut c_void) -> bool;
type DropFn =
    unsafe extern "C" fn(*mut c_void, *const u16, *const c_char, usize);

/// The C `WafHttpContext`: `self` plus one callback per trait method, in
/// trait order. Every callback is required.
#[repr(C)]
pub struct ForeignHttpContext {
    pub this: *mut c_void,
    pub framework: Option<TextFn>,
    pub get_method: Option<TextFn>,
    pub get_url: Option<TextFn>,
    pub get_path: Option<TextFn>,
    pub get_ip: Option<TextFn>,
    pub get_protocol: Option<TextFn>,
    pub get_local_port: Option<PortFn>,
    pub get_header: Option<HeaderFn>,
    pub get_headers: Option<HeadersFn>,
    pub get_query: Option<QueryFn>,
    pub get_cookies: Option<CookiesFn>,
    pub get_raw_body: Option<TextFn>,
    pub get_files: Option<FilesFn>,
    pub set_response_header: Option<SetHeaderFn>,
    pub remove_response_header: Option<RemoveHeaderFn>,
    pub is_blocked: Option<IsBlockedFn>,
    pub drop: Option<DropFn>,
}

/// The callbacks of a complete [`ForeignHttpContext`].
#[derive(Clone, Copy)]
struct Callbacks {
    framework: TextFn,
    get_method: TextFn,
    get_url: TextFn,
    get_path: TextFn,
    get_ip: TextFn,
    get_protocol: TextFn,
    get_local_port: PortFn,
    get_header: HeaderFn,
    get_headers: HeadersFn,
    get_query: QueryFn,
    get_cookies: CookiesFn,
    get_raw_body: TextFn,
    get_files: FilesFn,
    set_response_header: SetHeaderFn,
    remove_response_header: RemoveHeaderFn,
    is_blocked: IsBlockedFn,
    drop: DropFn,
}

impl ForeignHttpContext {
    /// The callbacks, or `None` when any is missing.
    fn callbacks(&self) -> Option<Callbacks> {
        Some(Callbacks {
            framework: self.framework?,
            get_method: self.get_method?,
            get_url: self.get_url?,
            get_path: self.get_path?,
            get_ip: self.get_ip?,
            get_protocol: self.get_protocol?,
            get_local_port: self.get_local_port?,
            get_header: self.get_header?,
            get_headers: self.get_headers?,
            get_query: self.get_query?,
            get_cookies: self.get_cookies?,
            get_raw_body: self.get_raw_body?,
            get_files: self.get_files?,
            set_response_header: self.set_response_header?,
            remove_response_header: self.remove_response_header?,
            is_blocked: self.is_blocked?,
            drop: self.drop?,
        })
    }
}

/// Values read through the callbacks, cached because the trait lends them.
#[derive(Default)]
struct Cache {
    framework: OnceCell<String>,
    method: OnceCell<String>,
    url: OnceCell<String>,
    path: OnceCell<String>,
    ip: OnceCell<String>,
    protocol: OnceCell<String>,
    headers: OnceCell<HeaderMap>,
    query: OnceCell<QueryMap>,
    cookies: OnceCell<CookieMap>,
    raw_body: OnceCell<String>,
    files: OnceCell<Vec<UploadedFile>>,
}

/// A [`WafHttpContext`] backed by C callbacks.
pub struct CallbackContext {
    this: *mut c_void,
    callbacks: Callbacks,
    cache: Cache,
}

impl CallbackContext {
    /// `None` when a callback is missing.
    ///
    /// # Safety
    ///
    /// Every callback must be callable with `context.this` for as long as
    /// the returned value lives.
    pub unsafe fn new(context: &ForeignHttpContext) -> Option<Self> {
        Some(Self {
            this: context.this,
            callbacks: context.callbacks()?,
            cache: Cache::default(),
        })
    }

    fn read_text(&self, callback: TextFn) -> String {
        let mut out = MiniWafString::default();
        // SAFETY: `new` requires the callbacks to accept `this`.
        unsafe { callback(self.this, &mut out) };
        out.0
    }

    fn read<T: Default>(
        &self,
        callback: unsafe extern "C" fn(*mut c_void, *mut T),
    ) -> T {
        let mut out = T::default();
        // SAFETY: `new` requires the callbacks to accept `this`.
        unsafe { callback(self.this, &mut out) };
        out
    }
}

impl WafHttpContext for CallbackContext {
    fn framework(&self) -> &str {
        let framework = self.callbacks.framework;
        self.cache
            .framework
            .get_or_init(|| self.read_text(framework))
    }

    fn get_method(&self) -> &str {
        let get_method = self.callbacks.get_method;
        self.cache.method.get_or_init(|| self.read_text(get_method))
    }

    fn get_url(&self) -> &str {
        let get_url = self.callbacks.get_url;
        self.cache.url.get_or_init(|| self.read_text(get_url))
    }

    fn get_path(&self) -> &str {
        let get_path = self.callbacks.get_path;
        self.cache.path.get_or_init(|| self.read_text(get_path))
    }

    fn get_ip(&self) -> &str {
        let get_ip = self.callbacks.get_ip;
        self.cache.ip.get_or_init(|| self.read_text(get_ip))
    }

    fn get_protocol(&self) -> &str {
        let get_protocol = self.callbacks.get_protocol;
        self.cache
            .protocol
            .get_or_init(|| self.read_text(get_protocol))
    }

    fn get_local_port(&self) -> u16 {
        // SAFETY: `new` requires the callbacks to accept `this`.
        unsafe { (self.callbacks.get_local_port)(self.this) }
    }

    fn get_header(&self, name: &str) -> Option<String> {
        let mut out = MiniWafString::default();
        // SAFETY: `new` requires the callbacks to accept `this`; `name`
        // outlives the call.
        let found = unsafe {
            (self.callbacks.get_header)(
                self.this,
                name.as_ptr().cast(),
                name.len(),
                &mut out,
            )
        };
        found.then_some(out.0)
    }

    fn get_headers(&self) -> &HeaderMap {
        let get_headers = self.callbacks.get_headers;
        self.cache.headers.get_or_init(|| self.read(get_headers))
    }

    fn get_query(&self) -> &QueryMap {
        let get_query = self.callbacks.get_query;
        self.cache.query.get_or_init(|| self.read(get_query))
    }

    fn get_cookies(&self) -> &CookieMap {
        let get_cookies = self.callbacks.get_cookies;
        self.cache.cookies.get_or_init(|| self.read(get_cookies))
    }

    fn get_raw_body(&self) -> &str {
        let get_raw_body = self.callbacks.get_raw_body;
        self.cache
            .raw_body
            .get_or_init(|| self.read_text(get_raw_body))
    }

    fn get_files(&self) -> &[UploadedFile] {
        let get_files = self.callbacks.get_files;
        self.cache.files.get_or_init(|| {
            let mut bag = FilesBag::List(Vec::new());
            // SAFETY: `new` requires the callbacks to accept `this`.
            unsafe { get_files(self.this, &mut bag) };
            normalize_files(Some(bag))
        })
    }

    fn set_response_header(&mut self, name: &str, value: &str) {
        // SAFETY: `new` requires the callbacks to accept `this`; both
        // strings outlive the call.
        unsafe {
            (self.callbacks.set_response_header)(
                self.this,
                name.as_ptr().cast(),
                name.len(),
                value.as_ptr().cast(),
                value.len(),
            );
        }
    }

    fn remove_response_header(&mut self, name: &str) {
        // SAFETY: `new` requires the callbacks to accept `this`; `name`
        // outlives the call.
        unsafe {
            (self.callbacks.remove_response_header)(
                self.this,
                name.as_ptr().cast(),
                name.len(),
            );
        }
    }

    fn is_blocked(&self) -> bool {
        // SAFETY: `new` requires the callbacks to accept `this`.
        unsafe { (self.callbacks.is_blocked)(self.this) }
    }

    fn drop(&mut self, status_code: Option<u16>, body: Option<&str>) {
        let status = status_code.as_ref().map_or(ptr::null(), ptr::from_ref);
        let (body, body_len) =
            body.map_or((ptr::null(), 0), |body| (body.as_ptr(), body.len()));
        // SAFETY: `new` requires the callbacks to accept `this`; `status`
        // and `body` outlive the call.
        unsafe {
            (self.callbacks.drop)(self.this, status, body.cast(), body_len)
        }
    }
}
