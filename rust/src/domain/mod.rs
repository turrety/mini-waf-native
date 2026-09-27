//! Domain model: values, levels, rules, the serializable rule shape and the
//! request view.

pub(crate) mod context;
pub(crate) mod levels;
pub(crate) mod rules;
pub(crate) mod serializable;
pub(crate) mod values;

pub use context::{
    WafAdapter,
    WafHttpContext,
};
pub use levels::{
    DEFAULT_PROTECTION_LEVEL,
    DEFAULT_RULE_MIN_LEVEL,
    InvalidProtectionLevel,
    PROTECTION_LEVELS,
    ProtectionLevel,
    is_level_active,
    is_protection_level,
    protection_level_rank,
};
pub use rules::{
    AllCondition,
    AnyOfCondition,
    DecisionCacheConfig,
    DecodeConfig,
    FieldCondition,
    InvalidField,
    MatchPattern,
    MatchPredicate,
    NotCondition,
    RateLimitSpec,
    WafAction,
    WafCondition,
    WafConfig,
    WafDecision,
    WafEvaluationResult,
    WafField,
    WafPresetName,
    WafRule,
    is_all_condition,
    is_any_of_condition,
    is_field_condition,
    is_not_condition,
};
pub use serializable::{
    JsonAllCondition,
    JsonAnyOfCondition,
    JsonFieldCondition,
    JsonMatchPattern,
    JsonNotCondition,
    JsonRateLimitSpec,
    JsonRegexPattern,
    JsonWafCondition,
    JsonWafRule,
    SerializableWafRule,
};
pub use values::{
    CookieMap,
    FilesBag,
    HeaderMap,
    HeaderValue,
    JsonArray,
    JsonObject,
    JsonPrimitive,
    JsonValue,
    OrderedMap,
    QueryMap,
    QueryValue,
    RawBody,
    ScalarValue,
    UploadedFile,
    body_to_string,
    file_display_name,
    json_to_string,
    normalize_files,
    scalar_to_string,
};

pub use crate::utils::json::JsonError;
