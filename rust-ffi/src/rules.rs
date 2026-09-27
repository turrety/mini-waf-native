//! Rule building blocks: `MatchPattern`, `WafField`, `RateLimitSpec`,
//! `FieldCondition`, `WafCondition`, `WafRule` and `parse_rules_from_json`.

use std::ffi::{
    c_char,
    c_void,
};
use std::ptr;

use waf::{
    FieldCondition,
    MatchPattern,
    RateLimitSpec,
    WafCondition,
    WafField,
    WafRule,
    parse_rules_from_json,
};

use crate::enums::{
    action,
    action_to_c,
    protection_level,
    protection_level_to_c,
};
use crate::ffi::{
    MiniWafStr,
    cloned,
    free_handle,
    handle_or_report,
    into_handle,
    lend,
    owned_string,
    report,
    text,
    texts,
    update,
    write,
    write_option,
};
use crate::text::CText;

/// `bool test(void *user_data, const char *value, size_t len)`.
pub type MatchPredicateFn =
    unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> bool;
/// Releases a predicate's `user_data` once no pattern refers to it.
pub type DropUserDataFn = unsafe extern "C" fn(*mut c_void);

/// A C predicate and its state. The engine shares patterns across threads,
/// so the header requires `test` to be thread-safe.
struct ForeignPredicate {
    test: MatchPredicateFn,
    user_data: *mut c_void,
    drop: Option<DropUserDataFn>,
}

// SAFETY: the header requires `test` and `drop` to accept `user_data` from
// any thread, which is all these impls promise.
unsafe impl Send for ForeignPredicate {}
// SAFETY: as above; `test` must tolerate concurrent calls.
unsafe impl Sync for ForeignPredicate {}

impl ForeignPredicate {
    fn test(&self, value: &str) -> bool {
        // SAFETY: `test` is a valid predicate for `user_data` (header
        // contract) and `value` outlives the call.
        unsafe {
            (self.test)(self.user_data, value.as_ptr().cast(), value.len())
        }
    }
}

impl Drop for ForeignPredicate {
    fn drop(&mut self) {
        if let Some(drop) = self.drop {
            // SAFETY: called once, when the last clone of the pattern goes.
            unsafe { drop(self.user_data) };
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_match_pattern_regex(
    pattern: *const c_char,
    pattern_len: usize,
    error: *mut *mut c_char,
) -> *mut MatchPattern {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let pattern = text(pattern, pattern_len);
        handle_or_report(MatchPattern::regex(&pattern), error)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_match_pattern_regex_with_flags(
    pattern: *const c_char,
    pattern_len: usize,
    flags: *const c_char,
    flags_len: usize,
    error: *mut *mut c_char,
) -> *mut MatchPattern {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let pattern = text(pattern, pattern_len);
        let flags = text(flags, flags_len);
        handle_or_report(
            MatchPattern::regex_with_flags(&pattern, &flags),
            error,
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_match_pattern_exact(
    value: *const c_char,
    value_len: usize,
) -> *mut MatchPattern {
    // SAFETY: the caller upholds the module contract for every pointer.
    into_handle(MatchPattern::exact(unsafe { text(value, value_len) }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_match_pattern_one_of(
    values: *const MiniWafStr,
    count: usize,
) -> *mut MatchPattern {
    // SAFETY: the caller upholds the module contract for every pointer.
    into_handle(MatchPattern::one_of(unsafe { texts(values, count) }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_match_pattern_predicate(
    test: Option<MatchPredicateFn>,
    user_data: *mut c_void,
    drop: Option<DropUserDataFn>,
) -> *mut MatchPattern {
    let Some(test) = test else {
        return ptr::null_mut();
    };
    let predicate = ForeignPredicate {
        test,
        user_data,
        drop,
    };
    into_handle(MatchPattern::predicate(move |value| predicate.test(value)))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_match_pattern_is_match(
    pattern: *const MatchPattern,
    value: *const c_char,
    value_len: usize,
) -> bool {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let value = text(value, value_len);
        pattern
            .as_ref()
            .is_some_and(|pattern| pattern.is_match(&value))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_match_pattern_free(
    pattern: *mut MatchPattern,
) {
    // SAFETY: `pattern` is null or a live handle.
    unsafe { free_handle(pattern) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_field_from_str(
    field: *const c_char,
    field_len: usize,
    error: *mut *mut c_char,
) -> *mut WafField {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let field = text(field, field_len);
        handle_or_report(field.parse::<WafField>(), error)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_field_query(
    name: *const c_char,
    name_len: usize,
) -> *mut WafField {
    // SAFETY: the caller upholds the module contract for every pointer.
    into_handle(WafField::query(unsafe { text(name, name_len) }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_field_header(
    name: *const c_char,
    name_len: usize,
) -> *mut WafField {
    // SAFETY: the caller upholds the module contract for every pointer.
    into_handle(WafField::header(unsafe { text(name, name_len) }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_field_cookie(
    name: *const c_char,
    name_len: usize,
) -> *mut WafField {
    // SAFETY: the caller upholds the module contract for every pointer.
    into_handle(WafField::cookie(unsafe { text(name, name_len) }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_field_to_string(
    field: *const WafField,
) -> *mut c_char {
    // SAFETY: `field` is null or a live handle.
    match unsafe { field.as_ref() } {
        Some(field) => owned_string(&field.to_string()),
        None => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_field_free(field: *mut WafField) {
    // SAFETY: `field` is null or a live handle.
    unsafe { free_handle(field) }
}

/// `RateLimitSpec` in C: a plain struct; a `NULL` `key_prefix.data` is
/// `None`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForeignRateLimitSpec {
    pub max: u64,
    pub window_ms: u64,
    pub key_prefix: MiniWafStr,
}

impl ForeignRateLimitSpec {
    /// # Safety
    ///
    /// `key_prefix` must satisfy [`MiniWafStr::to_option`].
    unsafe fn to_spec(self) -> RateLimitSpec {
        RateLimitSpec {
            max: self.max,
            window_ms: self.window_ms,
            // SAFETY: forwarded from the caller.
            key_prefix: unsafe { self.key_prefix.to_option() },
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_field_condition_new(
    field: *const WafField,
) -> *mut FieldCondition {
    // SAFETY: `field` is null or a live handle.
    match unsafe { field.as_ref() } {
        Some(field) => into_handle(FieldCondition::new(field.clone())),
        None => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_field_condition_matches(
    condition: *mut FieldCondition,
    pattern: *const MatchPattern,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        if let Some(pattern) = pattern.as_ref() {
            update(condition, |condition| {
                condition.matches = Some(pattern.clone());
            });
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_field_condition_equals(
    condition: *mut FieldCondition,
    value: *const c_char,
    value_len: usize,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let value = text(value, value_len);
        update(condition, |condition| condition.equals = Some(value));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_field_condition_includes(
    condition: *mut FieldCondition,
    needle: *const c_char,
    needle_len: usize,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let needle = text(needle, needle_len);
        update(condition, |condition| condition.includes = Some(needle));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_field_condition_rate_limit(
    condition: *mut FieldCondition,
    spec: ForeignRateLimitSpec,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let spec = spec.to_spec();
        update(condition, |condition| condition.rate_limit = Some(spec));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_field_condition_requires(
    condition: *mut FieldCondition,
    literals: *const MiniWafStr,
    count: usize,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let literals = texts(literals, count);
        update(condition, |condition| condition.requires = Some(literals));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_field_condition_free(
    condition: *mut FieldCondition,
) {
    // SAFETY: `condition` is null or a live handle.
    unsafe { free_handle(condition) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_condition_field(
    condition: *const FieldCondition,
) -> *mut WafCondition {
    // SAFETY: `condition` is null or a live handle.
    match unsafe { condition.as_ref() } {
        Some(condition) => into_handle(WafCondition::from(condition.clone())),
        None => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_condition_all(
    conditions: *const *const WafCondition,
    count: usize,
) -> *mut WafCondition {
    // SAFETY: the caller upholds the module contract for every pointer.
    into_handle(WafCondition::all(unsafe { cloned(conditions, count) }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_condition_any_of(
    conditions: *const *const WafCondition,
    count: usize,
) -> *mut WafCondition {
    // SAFETY: the caller upholds the module contract for every pointer.
    into_handle(WafCondition::any_of(unsafe { cloned(conditions, count) }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_condition_not(
    condition: *const WafCondition,
) -> *mut WafCondition {
    // SAFETY: `condition` is null or a live handle.
    match unsafe { condition.as_ref() } {
        Some(condition) => into_handle(WafCondition::not(condition.clone())),
        None => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_condition_clone(
    condition: *const WafCondition,
) -> *mut WafCondition {
    // SAFETY: `condition` is null or a live handle.
    unsafe { condition.as_ref() }
        .map_or(ptr::null_mut(), |condition| into_handle(condition.clone()))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_condition_free(
    condition: *mut WafCondition,
) {
    // SAFETY: `condition` is null or a live handle.
    unsafe { free_handle(condition) }
}

/// The C `WafRule`: a rule plus its text fields ready to lend to C.
#[derive(Debug, Clone)]
pub struct RuleHandle {
    rule: WafRule,
    id: CText,
    reason: Option<CText>,
}

impl RuleHandle {
    pub fn new(rule: WafRule) -> Self {
        Self {
            id: CText::new(&rule.id),
            reason: rule.reason.as_deref().map(CText::new),
            rule,
        }
    }

    fn set_reason(&mut self, reason: String) {
        self.reason = Some(CText::new(&reason));
        self.rule.reason = Some(reason);
    }
}

/// Clones of the rules behind an array of handles, skipping `NULL`s.
///
/// # Safety
///
/// As [`cloned`].
pub unsafe fn cloned_rules(
    rules: *const *const RuleHandle,
    count: usize,
) -> Vec<WafRule> {
    // SAFETY: forwarded from the caller.
    unsafe { cloned(rules, count) }
        .into_iter()
        .map(|handle| handle.rule)
        .collect()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_rule_new(
    id: *const c_char,
    id_len: usize,
    when: *const WafCondition,
    rule_action: u32,
) -> *mut RuleHandle {
    // SAFETY: the caller upholds the module contract for every pointer.
    let (id, when) = unsafe { (text(id, id_len), when.as_ref()) };
    match (when, action(rule_action)) {
        (Some(when), Some(action)) => {
            into_handle(RuleHandle::new(WafRule::new(id, when.clone(), action)))
        }
        _ => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_rule_reason(
    rule: *mut RuleHandle,
    reason: *const c_char,
    reason_len: usize,
) {
    // SAFETY: the caller upholds the module contract for every pointer.
    unsafe {
        let reason = text(reason, reason_len);
        update(rule, |rule| rule.set_reason(reason));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_rule_enabled(
    rule: *mut RuleHandle,
    enabled: bool,
) {
    // SAFETY: `rule` is null or a live, unshared handle.
    unsafe { update(rule, |rule| rule.rule.enabled = Some(enabled)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_rule_priority(
    rule: *mut RuleHandle,
    priority: i64,
) {
    // SAFETY: `rule` is null or a live, unshared handle.
    unsafe { update(rule, |rule| rule.rule.priority = Some(priority)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_rule_min_level(
    rule: *mut RuleHandle,
    level: u32,
) {
    if let Some(level) = protection_level(level) {
        // SAFETY: `rule` is null or a live, unshared handle.
        unsafe { update(rule, |rule| rule.rule.min_level = Some(level)) }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_rule_get_id(
    rule: *const RuleHandle,
    len: *mut usize,
) -> *const c_char {
    // SAFETY: `rule` is null or a live handle; `len` is null or writable.
    unsafe { lend(rule.as_ref().map(|rule| &rule.id), len) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_rule_get_when(
    rule: *const RuleHandle,
) -> *const WafCondition {
    // SAFETY: `rule` is null or a live handle.
    unsafe { rule.as_ref() }.map_or(ptr::null(), |rule| &rule.rule.when)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_rule_get_action(
    rule: *const RuleHandle,
) -> u32 {
    // SAFETY: `rule` is null or a live handle.
    unsafe { rule.as_ref() }.map_or(0, |rule| action_to_c(rule.rule.action))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_rule_get_reason(
    rule: *const RuleHandle,
    len: *mut usize,
) -> *const c_char {
    // SAFETY: `rule` is null or a live handle; `len` is null or writable.
    unsafe { lend(rule.as_ref().and_then(|rule| rule.reason.as_ref()), len) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_rule_get_enabled(
    rule: *const RuleHandle,
    enabled: *mut bool,
) -> bool {
    // SAFETY: `rule` is null or a live handle; `enabled` is null or writable.
    unsafe {
        let value = rule.as_ref().and_then(|rule| rule.rule.enabled);
        write_option(enabled, value)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_rule_get_priority(
    rule: *const RuleHandle,
    priority: *mut i64,
) -> bool {
    // SAFETY: `rule` is null or a live handle; `priority` is null or
    // writable.
    unsafe {
        let value = rule.as_ref().and_then(|rule| rule.rule.priority);
        write_option(priority, value)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_rule_get_min_level(
    rule: *const RuleHandle,
    level: *mut u32,
) -> bool {
    // SAFETY: `rule` is null or a live handle; `level` is null or writable.
    unsafe {
        let value = rule.as_ref().and_then(|rule| rule.rule.min_level);
        write_option(level, value.map(protection_level_to_c))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_rule_clone(
    rule: *const RuleHandle,
) -> *mut RuleHandle {
    // SAFETY: `rule` is null or a live handle.
    unsafe { rule.as_ref() }
        .map_or(ptr::null_mut(), |rule| into_handle(rule.clone()))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_rule_free(rule: *mut RuleHandle) {
    // SAFETY: `rule` is null or a live handle.
    unsafe { free_handle(rule) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_parse_rules_from_json(
    input: *const c_char,
    input_len: usize,
    count: *mut usize,
    error: *mut *mut c_char,
) -> *mut *mut RuleHandle {
    // SAFETY: the caller upholds the module contract for every pointer.
    let input = unsafe { text(input, input_len) };
    let rules = match parse_rules_from_json(&input) {
        Ok(rules) => rules,
        Err(failure) => {
            // SAFETY: `count` and `error` are null or writable.
            unsafe {
                write(count, 0);
                report(error, &failure.to_string());
            }
            return ptr::null_mut();
        }
    };
    let handles: Box<[*mut RuleHandle]> = rules
        .into_iter()
        .map(|rule| into_handle(RuleHandle::new(rule)))
        .collect();
    // SAFETY: `count` is null or writable.
    unsafe { write(count, handles.len()) };
    Box::into_raw(handles).cast()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mini_waf_waf_rule_array_free(
    rules: *mut *mut RuleHandle,
    count: usize,
) {
    if rules.is_null() {
        return;
    }
    // SAFETY: `rules` and `count` come from `mini_waf_parse_rules_from_json`.
    let handles =
        unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(rules, count)) };
    for handle in handles.iter() {
        // SAFETY: each entry is a live handle the array owns.
        unsafe { free_handle(*handle) };
    }
}
