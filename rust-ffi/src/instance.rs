//! `create_mini_waf`, `MiniWafInstance` (`rules`, `handle`, `protect`) and
//! `WafEvaluationResult`.

use std::ffi::{
    c_char,
    c_void,
};
use std::panic::{
    AssertUnwindSafe,
    catch_unwind,
};
use std::{
    mem,
    ptr,
};

use waf::{
    MiniWafInstance,
    WafConfig,
    WafEvaluationResult,
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
    write,
};
use crate::rules::RuleHandle;
use crate::text::CText;

/// The C `MiniWafInstance`: the engine plus a C view of its rules.
pub struct InstanceHandle {
    instance: MiniWafInstance,
    rules: Box<[RuleHandle]>,
    /// Pointers into `rules`, the array `mini_waf_mini_waf_instance_rules`
    /// lends.
    rule_pointers: Box<[*const RuleHandle]>,
}

impl InstanceHandle {
    fn new(config: WafConfig) -> Self {
        let instance = create_mini_waf(config, None);
        let rules: Box<[RuleHandle]> = instance
            .rules()
            .iter()
            .cloned()
            .map(RuleHandle::new)
            .collect();
        let rule_pointers = rules.iter().map(ptr::from_ref).collect();
        Self {
            instance,
            rules,
            rule_pointers,
        }
    }

    /// The C view of an engine rule. Results only borrow rules from the
    /// engine's list, so the offset into it is the index into `rules`.
    fn view_of(&self, rule: &WafRule) -> *const RuleHandle {
        let engine_rules = self.instance.rules();
        let offset = (ptr::from_ref(rule) as usize)
            .wrapping_sub(engine_rules.as_ptr() as usize);
        let index = offset / mem::size_of::<WafRule>().max(1);
        match engine_rules.get(index) {
            Some(candidate) if ptr::eq(candidate, rule) => &self.rules[index],
            _ => ptr::null(),
        }
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
    let config = unsafe { config.as_ref() }.cloned().unwrap_or_default();
    catch_unwind(AssertUnwindSafe(|| InstanceHandle::new(config)))
        .map_or(ptr::null_mut(), into_handle)
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
            .map_or(&[][..], |instance| &instance.rule_pointers[..]);
        write(count, rules.len());
        rules.as_ptr()
    }
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
