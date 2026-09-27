//! `WafLogger` implemented by C (blocked / audit / connection callbacks,
//! installed through `WafEngineOptions`) and `WafHttpContextRef`, the
//! request those callbacks read.

use std::cell::{
    OnceCell,
    RefCell,
};
use std::ffi::{
    c_char,
    c_void,
};
use std::ptr;
use std::sync::{
    Arc,
    OnceLock,
};

use waf::{
    CookieMap,
    HeaderMap,
    QueryMap,
    WafHttpContext,
    WafLogger,
    WafRule,
};

use crate::ffi::{
    text,
    write,
};
use crate::instance::RuleViews;
use crate::rules::{
    DropUserDataFn,
    RuleHandle,
};
use crate::text::CText;
use crate::values::ForeignUploadedFile;

type RuleEventFn =
    unsafe extern "C" fn(*mut c_void, *const ContextRef<'_>, *const RuleHandle);
type EventFn = unsafe extern "C" fn(*mut c_void, *const ContextRef<'_>);

/// The C `WafLogger`: `user_data` plus one callback per event. A missing
/// callback skips its event.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForeignLogger {
    pub user_data: *mut c_void,
    pub blocked: Option<RuleEventFn>,
    pub audit: Option<RuleEventFn>,
    pub connection: Option<EventFn>,
    pub drop: Option<DropUserDataFn>,
}

/// The callbacks, shared by every engine they were installed on; `drop`
/// runs once, with the last reference.
pub struct LoggerCallbacks(ForeignLogger);

// SAFETY: the header requires the callbacks to accept `user_data` from
// whichever thread evaluates a request.
unsafe impl Send for LoggerCallbacks {}
// SAFETY: as above; the callbacks must tolerate concurrent calls.
unsafe impl Sync for LoggerCallbacks {}

impl LoggerCallbacks {
    pub fn new(logger: ForeignLogger) -> Arc<Self> {
        Arc::new(Self(logger))
    }
}

impl Drop for LoggerCallbacks {
    fn drop(&mut self) {
        if let Some(drop) = self.0.drop {
            // SAFETY: called once, when the last reference goes.
            unsafe { drop(self.0.user_data) };
        }
    }
}

/// A [`WafLogger`] that forwards to C, handing each rule over as the same
/// `WafRule *` its instance lends.
pub struct CallbackLogger {
    callbacks: Arc<LoggerCallbacks>,
    /// Filled once the instance exists; empty while it is being built.
    views: Arc<OnceLock<Arc<RuleViews>>>,
}

impl CallbackLogger {
    pub fn new(
        callbacks: Arc<LoggerCallbacks>,
        views: Arc<OnceLock<Arc<RuleViews>>>,
    ) -> Self {
        Self { callbacks, views }
    }

    fn rule_event(
        &self,
        event: Option<RuleEventFn>,
        ctx: &dyn WafHttpContext,
        rule: &WafRule,
    ) {
        let Some(event) = event else {
            return;
        };
        let view = self
            .views
            .get()
            .map_or(ptr::null(), |views| views.view_of(rule));
        let context = ContextRef::new(ctx);
        // SAFETY: the header requires the callback to accept `user_data`;
        // `context` outlives the call and `view` is null or borrowed from
        // the instance.
        unsafe { event(self.callbacks.0.user_data, &context, view) };
    }
}

impl WafLogger for CallbackLogger {
    fn blocked(&self, ctx: &dyn WafHttpContext, rule: &WafRule) {
        self.rule_event(self.callbacks.0.blocked, ctx, rule);
    }

    fn audit(&self, ctx: &dyn WafHttpContext, rule: &WafRule) {
        self.rule_event(self.callbacks.0.audit, ctx, rule);
    }

    fn connection(&self, ctx: &dyn WafHttpContext) {
        if let Some(connection) = self.callbacks.0.connection {
            let context = ContextRef::new(ctx);
            // SAFETY: the header requires the callback to accept
            // `user_data`; `context` outlives the call.
            unsafe { connection(self.callbacks.0.user_data, &context) };
        }
    }
}

/// The C `WafHttpContextRef`: the request a log event is about, readable
/// until the callback returns. Text is copied once into `texts` so C gets
/// NUL-terminated strings that live as long as the callback.
pub struct ContextRef<'a> {
    ctx: &'a dyn WafHttpContext,
    texts: RefCell<Vec<CText>>,
    files: OnceCell<Box<[ForeignUploadedFile]>>,
}

impl<'a> ContextRef<'a> {
    fn new(ctx: &'a dyn WafHttpContext) -> Self {
        Self {
            ctx,
            texts: RefCell::new(Vec::new()),
            files: OnceCell::new(),
        }
    }

    /// Lend a copy of `value`, kept until the callback returns.
    ///
    /// # Safety
    ///
    /// `len` must be null or writable.
    unsafe fn lend(&self, value: &str, len: *mut usize) -> *const c_char {
        let copy = CText::new(value);
        // SAFETY: forwarded from the caller.
        unsafe { write(len, copy.len()) };
        let pointer = copy.as_ptr();
        // The bytes are boxed, so moving `copy` keeps `pointer` valid.
        self.texts.borrow_mut().push(copy);
        pointer
    }
}

macro_rules! context_text {
    ($($name:ident => $method:ident),* $(,)?) => {$(
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            ctx: *const ContextRef<'_>,
            len: *mut usize,
        ) -> *const c_char {
            // SAFETY: `ctx` is null or the live context of the callback in
            // progress; `len` is null or writable.
            unsafe {
                match ctx.as_ref() {
                    Some(ctx) => ctx.lend(ctx.ctx.$method(), len),
                    None => {
                        write(len, 0);
                        ptr::null()
                    }
                }
            }
        }
    )*};
}

context_text! {
    mini_waf_waf_http_context_ref_framework => framework,
    mini_waf_waf_http_context_ref_get_method => get_method,
    mini_waf_waf_http_context_ref_get_url => get_url,
    mini_waf_waf_http_context_ref_get_path => get_path,
    mini_waf_waf_http_context_ref_get_ip => get_ip,
    mini_waf_waf_http_context_ref_get_protocol => get_protocol,
    mini_waf_waf_http_context_ref_get_raw_body => get_raw_body,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_http_context_ref_get_local_port(
    ctx: *const ContextRef<'_>,
) -> u16 {
    // SAFETY: `ctx` is null or the live context of the callback.
    unsafe { ctx.as_ref() }.map_or(0, |ctx| ctx.ctx.get_local_port())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_http_context_ref_get_header(
    ctx: *const ContextRef<'_>,
    name: *const c_char,
    name_len: usize,
    len: *mut usize,
) -> *const c_char {
    // SAFETY: `ctx` is null or the live context of the callback; `name`
    // holds `name_len` bytes; `len` is null or writable.
    unsafe {
        let value = ctx.as_ref().and_then(|ctx| {
            let value = ctx.ctx.get_header(&text(name, name_len))?;
            Some(ctx.lend(&value, len))
        });
        value.unwrap_or_else(|| {
            write(len, 0);
            ptr::null()
        })
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_http_context_ref_get_headers(
    ctx: *const ContextRef<'_>,
) -> *const HeaderMap {
    // SAFETY: `ctx` is null or the live context of the callback.
    unsafe { ctx.as_ref() }.map_or(ptr::null(), |ctx| ctx.ctx.get_headers())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_http_context_ref_get_query(
    ctx: *const ContextRef<'_>,
) -> *const QueryMap {
    // SAFETY: `ctx` is null or the live context of the callback.
    unsafe { ctx.as_ref() }.map_or(ptr::null(), |ctx| ctx.ctx.get_query())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_http_context_ref_get_cookies(
    ctx: *const ContextRef<'_>,
) -> *const CookieMap {
    // SAFETY: `ctx` is null or the live context of the callback.
    unsafe { ctx.as_ref() }.map_or(ptr::null(), |ctx| ctx.ctx.get_cookies())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_http_context_ref_get_files(
    ctx: *const ContextRef<'_>,
    count: *mut usize,
) -> *const ForeignUploadedFile {
    // SAFETY: `ctx` is null or the live context of the callback.
    let files = unsafe { ctx.as_ref() }.map_or(&[][..], |ctx| {
        ctx.files.get_or_init(|| {
            ctx.ctx
                .get_files()
                .iter()
                .map(ForeignUploadedFile::of)
                .collect()
        })
    });
    // SAFETY: `count` is null or writable.
    unsafe { write(count, files.len()) };
    files.as_ptr()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_http_context_ref_is_blocked(
    ctx: *const ContextRef<'_>,
) -> bool {
    // SAFETY: `ctx` is null or the live context of the callback.
    unsafe { ctx.as_ref() }.is_some_and(|ctx| ctx.ctx.is_blocked())
}
