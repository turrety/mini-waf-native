//! `WafConfig` and the plain structs it takes (`DecisionCacheConfig`,
//! `DecodeConfig`, `WafLoggingOptions`).

use std::ffi::c_char;

use waf::{
    DecisionCacheConfig,
    DecodeConfig,
    WafConfig,
    WafLoggingOptions,
    WafLoggingSetting,
};

use crate::enums::{
    log_level,
    preset,
    protection_level,
};
use crate::ffi::{
    MiniWafStr,
    free_handle,
    into_handle,
    items,
    text,
    texts,
    update,
};
use crate::rules::{
    RuleHandle,
    cloned_rules,
};

/// Read an optional value: `NULL` is `None`.
///
/// # Safety
///
/// A non-null `value` must point to an initialized `T`.
unsafe fn optional<T: Copy>(value: *const T) -> Option<T> {
    // SAFETY: forwarded from the caller.
    unsafe { value.as_ref() }.copied()
}

/// `DecisionCacheConfig` in C: `NULL` members are `None`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForeignDecisionCacheConfig {
    pub max: *const usize,
    pub ttl_ms: *const u64,
}

/// `DecodeConfig` in C: `NULL` members are `None`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForeignDecodeConfig {
    pub base64: *const bool,
    pub url: *const bool,
    pub comments: *const bool,
}

/// `WafLoggingOptions` in C, without the sink: `NULL` level is `None`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForeignWafLoggingOptions {
    pub level: *const u32,
}

#[unsafe(no_mangle)]
pub extern "C" fn mini_waf_waf_config_new() -> *mut WafConfig {
    into_handle(WafConfig::default())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_config_free(config: *mut WafConfig) {
    // SAFETY: `config` is null or a live handle.
    unsafe { free_handle(config) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_config_level(
    config: *mut WafConfig,
    level: u32,
) {
    if let Some(level) = protection_level(level) {
        // SAFETY: `config` is null or a live, unshared handle.
        unsafe { update(config, |config| config.level = Some(level)) }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_config_rules(
    config: *mut WafConfig,
    rules: *const *const RuleHandle,
    count: usize,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let rules = cloned_rules(rules, count);
        update(config, |config| config.rules = Some(rules));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_config_presets(
    config: *mut WafConfig,
    presets: *const u32,
    count: usize,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let presets = items(presets, count)
            .iter()
            .filter_map(|&value| preset(value));
        let presets = presets.collect();
        update(config, |config| config.presets = Some(presets));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_config_enabled_rule_ids(
    config: *mut WafConfig,
    ids: *const MiniWafStr,
    count: usize,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let ids = texts(ids, count);
        update(config, |config| config.enabled_rule_ids = Some(ids));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_config_disabled_rule_ids(
    config: *mut WafConfig,
    ids: *const MiniWafStr,
    count: usize,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let ids = texts(ids, count);
        update(config, |config| config.disabled_rule_ids = Some(ids));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_config_block_status_code(
    config: *mut WafConfig,
    status_code: u16,
) {
    // SAFETY: `config` is null or a live, unshared handle.
    unsafe {
        update(config, |config| {
            config.block_status_code = Some(status_code)
        });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_config_block_body(
    config: *mut WafConfig,
    body: *const c_char,
    body_len: usize,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let body = text(body, body_len);
        update(config, |config| config.block_body = Some(body));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_config_logging(
    config: *mut WafConfig,
    enabled: bool,
) {
    let logging = WafLoggingSetting::Enabled(enabled);
    // SAFETY: `config` is null or a live, unshared handle.
    unsafe { update(config, |config| config.logging = Some(logging)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_config_logging_options(
    config: *mut WafConfig,
    options: ForeignWafLoggingOptions,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let options = WafLoggingOptions {
            level: optional(options.level).and_then(log_level),
            sink: None,
        };
        let logging = WafLoggingSetting::Options(options);
        update(config, |config| config.logging = Some(logging));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_config_max_field_length(
    config: *mut WafConfig,
    length: usize,
) {
    // SAFETY: `config` is null or a live, unshared handle.
    unsafe { update(config, |config| config.max_field_length = Some(length)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_config_max_rate_limit_keys(
    config: *mut WafConfig,
    keys: usize,
) {
    // SAFETY: `config` is null or a live, unshared handle.
    unsafe { update(config, |config| config.max_rate_limit_keys = Some(keys)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_config_decision_cache(
    config: *mut WafConfig,
    cache: ForeignDecisionCacheConfig,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let cache = DecisionCacheConfig {
            max: optional(cache.max),
            ttl_ms: optional(cache.ttl_ms),
        };
        update(config, |config| config.decision_cache = Some(cache));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_config_decode(
    config: *mut WafConfig,
    decode: ForeignDecodeConfig,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let decode = DecodeConfig {
            base64: optional(decode.base64),
            url: optional(decode.url),
            comments: optional(decode.comments),
        };
        update(config, |config| config.decode = Some(decode));
    }
}
