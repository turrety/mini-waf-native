//! `create_mini_waf`, `WafEngineOptions`, `MiniWafInstance` (`rules`,
//! `handle`, `protect`, `rate_limit_store`) and `WafEvaluationResult`.

use std::ffi::{
    c_char,
    c_void,
};
use std::panic::{
    AssertUnwindSafe,
    catch_unwind,
};
use std::sync::{
    Arc,
    OnceLock,
};
use std::{
    mem,
    ptr,
};

use waf::{
    MiniWafInstance,
    WafConfig,
    WafEngineOptions,
    WafEvaluationResult,
    WafLogger,
    WafRule,
    create_mini_waf,
};

use crate::adapter::{
    ForeignAdapter,
    ForeignRequest,
    ForeignResponse,
};
use crate::context::{
    CallbackContext,
    ForeignHttpContext,
};
use crate::enums::decision_to_c;
use crate::ffi::{
    free_handle,
    into_handle,
    lend,
    update,
    write,
};
use crate::logger::{
    CallbackLogger,
    ForeignLogger,
    LoggerCallbacks,
};
use crate::rate_limit::StoreHandle;
use crate::rules::RuleHandle;
use crate::text::CText;

/// The C views of an instance's rules, shared with its logger, which
/// reports rules as the same pointers `rules` and results lend.
pub struct RuleViews {
    /// The engine's rule list; its heap buffer never moves.
    engine_rules: *const WafRule,
    rules: Box<[RuleHandle]>,
    /// Pointers into `rules`, the array `mini_waf_mini_waf_instance_rules`
    /// lends.
    pointers: Box<[*const RuleHandle]>,
}

// SAFETY: the pointers only read immutable data owned by the instance,
// which outlives every engine call that reaches them.
unsafe impl Send for RuleViews {}
// SAFETY: as above.
unsafe impl Sync for RuleViews {}

impl RuleViews {
    fn new(engine_rules: &[WafRule]) -> Self {
        let rules: Box<[RuleHandle]> =
            engine_rules.iter().cloned().map(RuleHandle::new).collect();
        let pointers = rules.iter().map(ptr::from_ref).collect();
        Self {
            engine_rules: engine_rules.as_ptr(),
            rules,
            pointers,
        }
    }

    /// The C view of an engine rule. The engine only hands out rules from
    /// its list, so the offset into it is the index into `rules`.
    pub fn view_of(&self, rule: &WafRule) -> *const RuleHandle {
        let offset = (ptr::from_ref(rule) as usize)
            .wrapping_sub(self.engine_rules as usize);
        let index = offset / mem::size_of::<WafRule>().max(1);
        match self.rules.get(index) {
            Some(view) if offset % mem::size_of::<WafRule>().max(1) == 0 => {
                view
            }
            _ => ptr::null(),
        }
    }
}

/// The C `WafEngineOptions`.
#[derive(Default)]
pub struct EngineOptionsHandle {
    logger: Option<Arc<LoggerCallbacks>>,
    rate_limit_store: Option<Arc<waf::RateLimitStore>>,
}

/// The C `MiniWafInstance`: the engine plus a C view of its rules.
pub struct InstanceHandle {
    instance: MiniWafInstance,
    views: Arc<RuleViews>,
}

impl InstanceHandle {
    fn new(config: WafConfig, options: &EngineOptionsHandle) -> Self {
        let views = Arc::new(OnceLock::new());
        let logger = options.logger.clone().map(|callbacks| {
            let logger = CallbackLogger::new(callbacks, Arc::clone(&views));
            Arc::new(logger) as Arc<dyn WafLogger>
        });
        let instance = create_mini_waf(
            config,
            Some(WafEngineOptions {
                rate_limit_store: options.rate_limit_store.clone(),
                logger,
            }),
        );
        let rule_views = Arc::new(RuleViews::new(instance.rules()));
        // Only this constructor sets it, so it is still empty.
        let _ = views.set(Arc::clone(&rule_views));
        Self {
            instance,
            views: rule_views,
        }
    }

    fn view_of(&self, rule: &WafRule) -> *const RuleHandle {
        self.views.view_of(rule)
    }

    fn evaluation(&self, result: &WafEvaluationResult<'_>) -> Evaluation {
        Evaluation {
            decision: decision_to_c(result.decision),
            matched_rule: result
                .matched_rule
                .map_or(ptr::null(), |rule| self.view_of(rule)),
            reason: result.reason.as_deref().map(CText::new),
            logged_rules: result
                .logged_rules
                .iter()
                .map(|rule| self.view_of(rule))
                .collect(),
        }
    }
}

/// The C `WafEvaluationResult`. Rule pointers borrow from the instance.
pub struct Evaluation {
    decision: u32,
    matched_rule: *const RuleHandle,
    reason: Option<CText>,
    logged_rules: Box<[*const RuleHandle]>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_create_mini_waf(
    config: *const WafConfig,
) -> *mut InstanceHandle {
    // SAFETY: `config` is null or a live handle.
    unsafe { mini_waf_create_mini_waf_with_options(config, ptr::null()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_create_mini_waf_with_options(
    config: *const WafConfig,
    options: *const EngineOptionsHandle,
) -> *mut InstanceHandle {
    // SAFETY: both are null or live handles.
    let (config, options) = unsafe { (config.as_ref(), options.as_ref()) };
    let config = config.cloned().unwrap_or_default();
    let defaults = EngineOptionsHandle::default();
    let options = options.unwrap_or(&defaults);
    catch_unwind(AssertUnwindSafe(|| InstanceHandle::new(config, options)))
        .map_or(ptr::null_mut(), into_handle)
}

#[unsafe(no_mangle)]
pub extern "C" fn mini_waf_waf_engine_options_new() -> *mut EngineOptionsHandle
{
    into_handle(EngineOptionsHandle::default())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_engine_options_logger(
    options: *mut EngineOptionsHandle,
    logger: ForeignLogger,
) {
    let callbacks = LoggerCallbacks::new(logger);
    // SAFETY: `options` is null or a live handle. Without one, dropping
    // `callbacks` still releases `user_data`.
    unsafe { update(options, |options| options.logger = Some(callbacks)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_engine_options_rate_limit_store(
    options: *mut EngineOptionsHandle,
    store: *const StoreHandle,
) {
    // SAFETY: both are null or live handles.
    unsafe {
        let store = store.as_ref().map(|store| Arc::clone(&store.0));
        update(options, |options| options.rate_limit_store = store);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_engine_options_free(
    options: *mut EngineOptionsHandle,
) {
    // SAFETY: `options` is null or a live handle.
    unsafe { free_handle(options) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_mini_waf_instance_free(
    instance: *mut InstanceHandle,
) {
    // SAFETY: `instance` is null or a live handle.
    unsafe { free_handle(instance) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_mini_waf_instance_rules(
    instance: *const InstanceHandle,
    count: *mut usize,
) -> *const *const RuleHandle {
    // SAFETY: `instance` is null or a live handle; `count` is null or
    // writable.
    unsafe {
        let rules = instance
            .as_ref()
            .map_or(&[][..], |instance| &instance.views.pointers[..]);
        write(count, rules.len());
        rules.as_ptr()
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_mini_waf_instance_rate_limit_store(
    instance: *const InstanceHandle,
) -> *mut StoreHandle {
    // SAFETY: `instance` is null or a live handle.
    unsafe { instance.as_ref() }.map_or(ptr::null_mut(), |instance| {
        into_handle(StoreHandle(Arc::clone(
            instance.instance.rate_limit_store(),
        )))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_mini_waf_instance_handle(
    instance: *const InstanceHandle,
    ctx: *const ForeignHttpContext,
) -> *mut Evaluation {
    // SAFETY: both are null or live; the header requires the callbacks to
    // accept `ctx->self` for the duration of this call.
    let (Some(instance), Some(mut ctx)) =
        (unsafe { instance.as_ref() }, unsafe {
            ctx.as_ref().and_then(|ctx| CallbackContext::new(ctx))
        })
    else {
        return ptr::null_mut();
    };
    catch_unwind(AssertUnwindSafe(|| {
        let result = instance.instance.handle(&mut ctx);
        instance.evaluation(&result)
    }))
    .map_or(ptr::null_mut(), into_handle)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_mini_waf_instance_protect(
    instance: *const InstanceHandle,
    adapter: *const ForeignAdapter,
    request: *const c_void,
    response: *mut c_void,
) -> *mut Evaluation {
    // SAFETY: both are null or live handles, only read here.
    let (Some(instance), Some(adapter)) =
        (unsafe { instance.as_ref() }, unsafe { adapter.as_ref() })
    else {
        return ptr::null_mut();
    };
    let request = ForeignRequest(request);
    let mut response = ForeignResponse(response);
    catch_unwind(AssertUnwindSafe(|| {
        let result =
            instance.instance.protect(adapter, &request, &mut response);
        instance.evaluation(&result)
    }))
    .map_or(ptr::null_mut(), into_handle)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_evaluation_result_free(
    result: *mut Evaluation,
) {
    // SAFETY: `result` is null or a live handle.
    unsafe { free_handle(result) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_evaluation_result_get_decision(
    result: *const Evaluation,
) -> u32 {
    // SAFETY: `result` is null or a live handle.
    unsafe { result.as_ref() }.map_or(0, |result| result.decision)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_evaluation_result_get_matched_rule(
    result: *const Evaluation,
) -> *const RuleHandle {
    // SAFETY: `result` is null or a live handle.
    unsafe { result.as_ref() }.map_or(ptr::null(), |result| result.matched_rule)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_evaluation_result_get_reason(
    result: *const Evaluation,
    len: *mut usize,
) -> *const c_char {
    // SAFETY: `result` is null or a live handle; `len` is null or writable.
    unsafe {
        lend(
            result.as_ref().and_then(|result| result.reason.as_ref()),
            len,
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_evaluation_result_get_logged_rules(
    result: *const Evaluation,
    count: *mut usize,
) -> *const *const RuleHandle {
    // SAFETY: `result` is null or a live handle; `count` is null or
    // writable.
    unsafe {
        let rules = result
            .as_ref()
            .map_or(&[][..], |result| &result.logged_rules[..]);
        write(count, rules.len());
        rules.as_ptr()
    }
}
