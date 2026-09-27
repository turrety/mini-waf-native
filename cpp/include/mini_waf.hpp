// mini_waf.hpp - C++17 binding of mini-waf, header-only over mini_waf.h.
//
// Every name is the Rust one: `mini_waf::create_mini_waf`, `WafConfig`,
// `WafRule`, `FieldCondition`, `CustomAdapterHandlers`, `create_adapter`,
// `MiniWafInstance::protect`, ... Rust builder methods (`fn reason(mut self,
// ..) -> Self`) are chainable on lvalues and temporaries alike, public
// fields are read with accessors of the same name (`rule.id()`), `Option`
// is `std::optional`, `Result::Err` is an exception named after the Rust
// error type. Two names collide with C++ keywords:
// `FieldCondition::requires_any` and `WafCondition::not_`.
//
//     auto waf = mini_waf::create_mini_waf(
//         mini_waf::WafConfig()
//             .presets({mini_waf::WafPresetName::Default})
//             .level(mini_waf::ProtectionLevel::Balanced));
//
// A MiniWafInstance is thread-safe; share it across request handlers.
// Handles are move-only except WafRule, whose copies are deep clones, and
// RateLimitStore, whose copies share one store (an Arc in Rust).

#ifndef MINI_WAF_HPP
#define MINI_WAF_HPP

#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

// The C API lives in mini_waf::sys (like a Rust `-sys` crate), so its
// types do not clash with the C++ ones of the same name.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef MINI_WAF_H
#error "include mini_waf.hpp instead of mini_waf.h in C++ (it wraps it)"
#endif
namespace mini_waf::sys {
#include "mini_waf.h"
}  // namespace mini_waf::sys

namespace mini_waf {

enum class ProtectionLevel { Low, Balanced, High, Paranoid };
enum class WafAction { Allow, Block, Log };
enum class WafPresetName {
    Default,
    Sqli,
    Xss,
    Scanners,
    PathTraversal,
    Rfi,
    Rce,
    Protocol,
};
enum class WafDecision { Allow, Block };
enum class WafLogLevel { Error, Info, Debug };

// Errors, named after the Rust error types.
class RegexError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};
class InvalidField : public std::runtime_error {
    using std::runtime_error::runtime_error;
};
class RuleParseError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};
class AdapterBuildError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Ordered maps, as the Rust OrderedMap: pairs in insertion order.
template <class V>
using OrderedMap = std::vector<std::pair<std::string, V>>;

// HeaderValue::Single / HeaderValue::Multi.
using HeaderValue = std::variant<std::string, std::vector<std::string>>;
using HeaderMap = OrderedMap<HeaderValue>;
using CookieMap = OrderedMap<std::string>;

// QueryValue::{Null, Bool, Number, String, Array, Object}.
struct QueryValue;
using QueryMap = OrderedMap<QueryValue>;
struct QueryValue {
    std::variant<std::monostate, bool, double, std::string,
                 std::vector<QueryValue>, QueryMap>
        value;
};

// RawBody::{Empty, Text, Bytes}.
using RawBody =
    std::variant<std::monostate, std::string, std::vector<std::uint8_t>>;

struct UploadedFile {
    std::optional<std::string> fieldname;
    std::optional<std::string> name;
    std::optional<std::string> filename;
    std::optional<std::string> originalname;

    // UploadedFile::named.
    static UploadedFile named(std::string name) {
        UploadedFile file;
        file.name = std::move(name);
        return file;
    }
};

// FilesBag::List / FilesBag::Fields.
using FilesBag = std::variant<std::vector<UploadedFile>,
                              OrderedMap<std::vector<UploadedFile>>>;

struct DecisionCacheConfig {
    std::optional<std::size_t> max;
    std::optional<std::uint64_t> ttl_ms;
};

struct DecodeConfig {
    std::optional<bool> base64;
    std::optional<bool> url;
    std::optional<bool> comments;
};

// WafLoggingOptions without the sink: events go to the console, or to the
// WafEngineOptions logger.
struct WafLoggingOptions {
    std::optional<WafLogLevel> level;
};

// NULL-free RateLimitStoreOptions: unset members take the default.
struct RateLimitStoreOptions {
    std::optional<std::size_t> max_keys;
    std::optional<std::int64_t> idle_ms;
    std::optional<std::uint64_t> prune_every_hits;
};

namespace detail {

inline sys::MiniWafStr str(std::string_view text) {
    return {text.data(), text.size()};
}

inline std::string string(const char* data, std::size_t len) {
    return data ? std::string(data, len) : std::string();
}

inline std::optional<std::string> optional_string(const char* data,
                                                  std::size_t len) {
    if (!data) {
        return std::nullopt;
    }
    return std::string(data, len);
}

inline std::vector<sys::MiniWafStr>
strs(const std::vector<std::string>& texts) {
    std::vector<sys::MiniWafStr> views;
    views.reserve(texts.size());
    for (const auto& text : texts) {
        views.push_back(str(text));
    }
    return views;
}

// Run `call` with an error out-parameter; return its handle, or throw E
// with the error message.
template <class E, class F>
auto check(F&& call) {
    char* error = nullptr;
    auto* handle = call(&error);
    if (handle) {
        return handle;
    }
    std::string message = error ? error : "unknown error";
    sys::mini_waf_string_free(error);
    throw E(message);
}

inline std::string take_string(char* owned) {
    std::string text = owned ? owned : "";
    sys::mini_waf_string_free(owned);
    return text;
}

template <class T, void (*Free)(T*)>
struct Deleter {
    void operator()(T* handle) const { Free(handle); }
};

template <class T, void (*Free)(T*)>
using Handle = std::unique_ptr<T, Deleter<T, Free>>;

}  // namespace detail

class MatchPattern {
public:
    static MatchPattern regex(std::string_view pattern) {
        return MatchPattern(detail::check<RegexError>([&](char** error) {
            return sys::mini_waf_match_pattern_regex(pattern.data(),
                                                     pattern.size(), error);
        }));
    }

    static MatchPattern regex_with_flags(std::string_view pattern,
                                         std::string_view flags) {
        return MatchPattern(detail::check<RegexError>([&](char** error) {
            return sys::mini_waf_match_pattern_regex_with_flags(
                pattern.data(), pattern.size(), flags.data(), flags.size(),
                error);
        }));
    }

    static MatchPattern exact(std::string_view value) {
        return MatchPattern(
            sys::mini_waf_match_pattern_exact(value.data(), value.size()));
    }

    static MatchPattern one_of(const std::vector<std::string>& values) {
        auto views = detail::strs(values);
        return MatchPattern(
            sys::mini_waf_match_pattern_one_of(views.data(), views.size()));
    }

    // Runs on every evaluating thread: `test` must be thread-safe. An
    // exception thrown by `test` counts as no match.
    static MatchPattern predicate(std::function<bool(std::string_view)> test) {
        auto* state =
            new std::function<bool(std::string_view)>(std::move(test));
        return MatchPattern(sys::mini_waf_match_pattern_predicate(
            &call_predicate, state, &drop_predicate));
    }

    bool is_match(std::string_view value) const {
        return sys::mini_waf_match_pattern_is_match(handle_.get(), value.data(),
                                                    value.size());
    }

    const sys::MatchPattern* native() const { return handle_.get(); }

private:
    explicit MatchPattern(sys::MatchPattern* handle) : handle_(handle) {}

    static bool call_predicate(void* state, const char* value,
                               std::size_t len) {
        try {
            auto& test =
                *static_cast<std::function<bool(std::string_view)>*>(state);
            return test(std::string_view(value, len));
        } catch (...) {
            return false;
        }
    }

    static void drop_predicate(void* state) {
        delete static_cast<std::function<bool(std::string_view)>*>(state);
    }

    detail::Handle<sys::MatchPattern, sys::mini_waf_match_pattern_free> handle_;
};

class WafField {
public:
    static WafField Ip() { return parse("ip"); }
    static WafField Method() { return parse("method"); }
    static WafField Path() { return parse("path"); }
    static WafField Url() { return parse("url"); }
    static WafField Body() { return parse("body"); }
    static WafField Files() { return parse("files"); }
    static WafField Query() { return parse("query"); }
    static WafField Headers() { return parse("headers"); }
    static WafField Cookies() { return parse("cookies"); }

    // `query.<name>`
    static WafField query(std::string_view name) {
        return WafField(
            sys::mini_waf_waf_field_query(name.data(), name.size()));
    }

    // `headers.<name>`
    static WafField header(std::string_view name) {
        return WafField(
            sys::mini_waf_waf_field_header(name.data(), name.size()));
    }

    // `cookies.<name>`
    static WafField cookie(std::string_view name) {
        return WafField(
            sys::mini_waf_waf_field_cookie(name.data(), name.size()));
    }

    // FromStr: `"headers.user-agent".parse::<WafField>()`.
    static WafField from_str(std::string_view field) {
        return WafField(detail::check<InvalidField>([&](char** error) {
            return sys::mini_waf_waf_field_from_str(field.data(), field.size(),
                                                    error);
        }));
    }

    // Display: the dotted path form.
    std::string to_string() const {
        return detail::take_string(
            sys::mini_waf_waf_field_to_string(handle_.get()));
    }

    const sys::WafField* native() const { return handle_.get(); }

private:
    explicit WafField(sys::WafField* handle) : handle_(handle) {}

    static WafField parse(const char* field) {
        return WafField(sys::mini_waf_waf_field_from_str(
            field, std::char_traits<char>::length(field), nullptr));
    }

    detail::Handle<sys::WafField, sys::mini_waf_waf_field_free> handle_;
};

class RateLimitSpec {
public:
    RateLimitSpec(std::uint64_t max, std::uint64_t window_ms)
        : max_(max), window_ms_(window_ms) {}

    RateLimitSpec& key_prefix(std::string prefix) & {
        key_prefix_ = std::move(prefix);
        return *this;
    }
    RateLimitSpec&& key_prefix(std::string prefix) && {
        return std::move(key_prefix(std::move(prefix)));
    }

    std::uint64_t max() const { return max_; }
    std::uint64_t window_ms() const { return window_ms_; }
    const std::optional<std::string>& key_prefix() const { return key_prefix_; }

private:
    std::uint64_t max_;
    std::uint64_t window_ms_;
    std::optional<std::string> key_prefix_;
};

class FieldCondition {
public:
    explicit FieldCondition(const WafField& field)
        : handle_(sys::mini_waf_field_condition_new(field.native())) {}

    FieldCondition& matches(const MatchPattern& pattern) & {
        sys::mini_waf_field_condition_matches(handle_.get(), pattern.native());
        return *this;
    }
    FieldCondition&& matches(const MatchPattern& pattern) && {
        return std::move(matches(pattern));
    }

    FieldCondition& equals(std::string_view value) & {
        sys::mini_waf_field_condition_equals(handle_.get(), value.data(),
                                             value.size());
        return *this;
    }
    FieldCondition&& equals(std::string_view value) && {
        return std::move(equals(value));
    }

    FieldCondition& includes(std::string_view needle) & {
        sys::mini_waf_field_condition_includes(handle_.get(), needle.data(),
                                               needle.size());
        return *this;
    }
    FieldCondition&& includes(std::string_view needle) && {
        return std::move(includes(needle));
    }

    FieldCondition& rate_limit(const RateLimitSpec& spec) & {
        sys::RateLimitSpec native{spec.max(), spec.window_ms(), {nullptr, 0}};
        if (spec.key_prefix()) {
            native.key_prefix = detail::str(*spec.key_prefix());
        }
        sys::mini_waf_field_condition_rate_limit(handle_.get(), native);
        return *this;
    }
    FieldCondition&& rate_limit(const RateLimitSpec& spec) && {
        return std::move(rate_limit(spec));
    }

    FieldCondition& requires_any(const std::vector<std::string>& literals) & {
        auto views = detail::strs(literals);
        sys::mini_waf_field_condition_requires(handle_.get(), views.data(),
                                               views.size());
        return *this;
    }
    FieldCondition&& requires_any(const std::vector<std::string>& literals) && {
        return std::move(requires_any(literals));
    }

    const sys::FieldCondition* native() const { return handle_.get(); }

private:
    detail::Handle<sys::FieldCondition, sys::mini_waf_field_condition_free>
        handle_;
};

class WafCondition {
public:
    // WafCondition::Field, the `From<FieldCondition>` conversion.
    WafCondition(const FieldCondition& condition)  // NOLINT: implicit
        : handle_(sys::mini_waf_waf_condition_field(condition.native())) {}

    static WafCondition all(const std::vector<WafCondition>& conditions) {
        auto natives = pointers(conditions);
        return WafCondition(
            sys::mini_waf_waf_condition_all(natives.data(), natives.size()));
    }

    template <class... C>
    static WafCondition all(const C&... conditions) {
        std::vector<WafCondition> temporaries;
        temporaries.reserve(sizeof...(conditions));
        std::vector<const sys::WafCondition*> natives{
            native_of(conditions, temporaries)...};
        return WafCondition(
            sys::mini_waf_waf_condition_all(natives.data(), natives.size()));
    }

    static WafCondition any_of(const std::vector<WafCondition>& conditions) {
        auto natives = pointers(conditions);
        return WafCondition(
            sys::mini_waf_waf_condition_any_of(natives.data(), natives.size()));
    }

    template <class... C>
    static WafCondition any_of(const C&... conditions) {
        std::vector<WafCondition> temporaries;
        temporaries.reserve(sizeof...(conditions));
        std::vector<const sys::WafCondition*> natives{
            native_of(conditions, temporaries)...};
        return WafCondition(
            sys::mini_waf_waf_condition_any_of(natives.data(), natives.size()));
    }

    static WafCondition not_(const WafCondition& condition) {
        return WafCondition(
            sys::mini_waf_waf_condition_not(condition.native()));
    }

    const sys::WafCondition* native() const { return handle_.get(); }

private:
    explicit WafCondition(sys::WafCondition* handle) : handle_(handle) {}

    static std::vector<const sys::WafCondition*>
    pointers(const std::vector<WafCondition>& conditions) {
        std::vector<const sys::WafCondition*> natives;
        natives.reserve(conditions.size());
        for (const auto& condition : conditions) {
            natives.push_back(condition.native());
        }
        return natives;
    }

    static const sys::WafCondition* native_of(const WafCondition& condition,
                                              std::vector<WafCondition>&) {
        return condition.native();
    }

    // A FieldCondition argument is wrapped in a temporary WafCondition.
    static const sys::WafCondition*
    native_of(const FieldCondition& condition,
              std::vector<WafCondition>& temporaries) {
        temporaries.emplace_back(condition);
        return temporaries.back().native();
    }

    detail::Handle<sys::WafCondition, sys::mini_waf_waf_condition_free> handle_;
};

class WafRule {
public:
    WafRule(std::string_view id, const WafCondition& when, WafAction action)
        : rule_(
              sys::mini_waf_waf_rule_new(id.data(), id.size(), when.native(),
                                         static_cast<sys::WafAction>(action))),
          owned_(true) {}

    WafRule(const WafRule& other)
        : rule_(sys::mini_waf_waf_rule_clone(other.rule_)), owned_(true) {}
    WafRule(WafRule&& other) noexcept
        : rule_(std::exchange(other.rule_, nullptr)), owned_(other.owned_) {}
    WafRule& operator=(WafRule other) noexcept {
        std::swap(rule_, other.rule_);
        std::swap(owned_, other.owned_);
        return *this;
    }
    ~WafRule() {
        if (owned_) {
            sys::mini_waf_waf_rule_free(rule_);
        }
    }

    WafRule& reason(std::string_view reason) & {
        sys::mini_waf_waf_rule_reason(mutable_rule(), reason.data(),
                                      reason.size());
        return *this;
    }
    WafRule&& reason(std::string_view reason) && {
        return std::move(this->reason(reason));
    }

    WafRule& enabled(bool enabled) & {
        sys::mini_waf_waf_rule_enabled(mutable_rule(), enabled);
        return *this;
    }
    WafRule&& enabled(bool enabled) && {
        return std::move(this->enabled(enabled));
    }

    WafRule& priority(std::int64_t priority) & {
        sys::mini_waf_waf_rule_priority(mutable_rule(), priority);
        return *this;
    }
    WafRule&& priority(std::int64_t priority) && {
        return std::move(this->priority(priority));
    }

    WafRule& min_level(ProtectionLevel level) & {
        sys::mini_waf_waf_rule_min_level(
            mutable_rule(), static_cast<sys::ProtectionLevel>(level));
        return *this;
    }
    WafRule&& min_level(ProtectionLevel level) && {
        return std::move(min_level(level));
    }

    std::string id() const {
        std::size_t len = 0;
        const char* id = sys::mini_waf_waf_rule_get_id(rule_, &len);
        return detail::string(id, len);
    }

    WafAction action() const {
        return static_cast<WafAction>(sys::mini_waf_waf_rule_get_action(rule_));
    }

    std::optional<std::string> reason() const {
        std::size_t len = 0;
        const char* reason = sys::mini_waf_waf_rule_get_reason(rule_, &len);
        return detail::optional_string(reason, len);
    }

    std::optional<bool> enabled() const {
        bool enabled = false;
        if (!sys::mini_waf_waf_rule_get_enabled(rule_, &enabled)) {
            return std::nullopt;
        }
        return enabled;
    }

    std::optional<std::int64_t> priority() const {
        std::int64_t priority = 0;
        if (!sys::mini_waf_waf_rule_get_priority(rule_, &priority)) {
            return std::nullopt;
        }
        return priority;
    }

    std::optional<ProtectionLevel> min_level() const {
        sys::ProtectionLevel level = sys::PROTECTION_LEVEL_LOW;
        if (!sys::mini_waf_waf_rule_get_min_level(rule_, &level)) {
            return std::nullopt;
        }
        return static_cast<ProtectionLevel>(level);
    }

    const sys::WafRule* native() const { return rule_; }

    // A view of a rule owned elsewhere (by an instance): valid while that
    // owner lives. Copy it to keep it longer.
    static WafRule borrowed(const sys::WafRule* rule) {
        return WafRule(const_cast<sys::WafRule*>(rule), false);
    }

    // Take ownership of a library-allocated rule.
    static WafRule owned(sys::WafRule* rule) { return WafRule(rule, true); }

private:
    WafRule(sys::WafRule* rule, bool owned) : rule_(rule), owned_(owned) {}

    sys::WafRule* mutable_rule() {
        if (!owned_) {
            rule_ = sys::mini_waf_waf_rule_clone(rule_);
            owned_ = true;
        }
        return rule_;
    }

    sys::WafRule* rule_;
    bool owned_;
};

// Parse a JSON rules document (an array, or {"rules": [...]}).
inline std::vector<WafRule> parse_rules_from_json(std::string_view input) {
    std::size_t count = 0;
    sys::WafRule** rules = detail::check<RuleParseError>([&](char** error) {
        return sys::mini_waf_parse_rules_from_json(input.data(), input.size(),
                                                   &count, error);
    });
    std::vector<WafRule> owned;
    owned.reserve(count);
    for (std::size_t index = 0; index < count; index++) {
        owned.push_back(
            WafRule::owned(sys::mini_waf_waf_rule_clone(rules[index])));
    }
    sys::mini_waf_waf_rule_array_free(rules, count);
    return owned;
}

class WafConfig {
public:
    WafConfig() : handle_(sys::mini_waf_waf_config_new()) {}

    WafConfig& level(ProtectionLevel level) & {
        sys::mini_waf_waf_config_level(
            handle_.get(), static_cast<sys::ProtectionLevel>(level));
        return *this;
    }
    WafConfig&& level(ProtectionLevel level) && {
        return std::move(this->level(level));
    }

    WafConfig& rules(const std::vector<WafRule>& rules) & {
        std::vector<const sys::WafRule*> natives;
        natives.reserve(rules.size());
        for (const auto& rule : rules) {
            natives.push_back(rule.native());
        }
        sys::mini_waf_waf_config_rules(handle_.get(), natives.data(),
                                       natives.size());
        return *this;
    }
    WafConfig&& rules(const std::vector<WafRule>& rules) && {
        return std::move(this->rules(rules));
    }

    WafConfig& presets(const std::vector<WafPresetName>& presets) & {
        std::vector<sys::WafPresetName> natives;
        natives.reserve(presets.size());
        for (auto preset : presets) {
            natives.push_back(static_cast<sys::WafPresetName>(preset));
        }
        sys::mini_waf_waf_config_presets(handle_.get(), natives.data(),
                                         natives.size());
        return *this;
    }
    WafConfig&& presets(const std::vector<WafPresetName>& presets) && {
        return std::move(this->presets(presets));
    }

    WafConfig& enabled_rule_ids(const std::vector<std::string>& ids) & {
        auto views = detail::strs(ids);
        sys::mini_waf_waf_config_enabled_rule_ids(handle_.get(), views.data(),
                                                  views.size());
        return *this;
    }
    WafConfig&& enabled_rule_ids(const std::vector<std::string>& ids) && {
        return std::move(enabled_rule_ids(ids));
    }

    WafConfig& disabled_rule_ids(const std::vector<std::string>& ids) & {
        auto views = detail::strs(ids);
        sys::mini_waf_waf_config_disabled_rule_ids(handle_.get(), views.data(),
                                                   views.size());
        return *this;
    }
    WafConfig&& disabled_rule_ids(const std::vector<std::string>& ids) && {
        return std::move(disabled_rule_ids(ids));
    }

    WafConfig& block_status_code(std::uint16_t status_code) & {
        sys::mini_waf_waf_config_block_status_code(handle_.get(), status_code);
        return *this;
    }
    WafConfig&& block_status_code(std::uint16_t status_code) && {
        return std::move(block_status_code(status_code));
    }

    WafConfig& block_body(std::string_view body) & {
        sys::mini_waf_waf_config_block_body(handle_.get(), body.data(),
                                            body.size());
        return *this;
    }
    WafConfig&& block_body(std::string_view body) && {
        return std::move(block_body(body));
    }

    WafConfig& logging(bool enabled) & {
        sys::mini_waf_waf_config_logging(handle_.get(), enabled);
        return *this;
    }
    WafConfig&& logging(bool enabled) && { return std::move(logging(enabled)); }

    WafConfig& logging(const WafLoggingOptions& options) & {
        sys::WafLogLevel level = sys::WAF_LOG_LEVEL_INFO;
        if (options.level) {
            level = static_cast<sys::WafLogLevel>(*options.level);
        }
        sys::WafLoggingOptions native{options.level ? &level : nullptr};
        sys::mini_waf_waf_config_logging_options(handle_.get(), native);
        return *this;
    }
    WafConfig&& logging(const WafLoggingOptions& options) && {
        return std::move(logging(options));
    }

    WafConfig& max_field_length(std::size_t length) & {
        sys::mini_waf_waf_config_max_field_length(handle_.get(), length);
        return *this;
    }
    WafConfig&& max_field_length(std::size_t length) && {
        return std::move(max_field_length(length));
    }

    WafConfig& max_rate_limit_keys(std::size_t keys) & {
        sys::mini_waf_waf_config_max_rate_limit_keys(handle_.get(), keys);
        return *this;
    }
    WafConfig&& max_rate_limit_keys(std::size_t keys) && {
        return std::move(max_rate_limit_keys(keys));
    }

    WafConfig& decision_cache(const DecisionCacheConfig& cache) & {
        sys::DecisionCacheConfig native{
            cache.max ? &*cache.max : nullptr,
            cache.ttl_ms ? &*cache.ttl_ms : nullptr,
        };
        sys::mini_waf_waf_config_decision_cache(handle_.get(), native);
        return *this;
    }
    WafConfig&& decision_cache(const DecisionCacheConfig& cache) && {
        return std::move(decision_cache(cache));
    }

    WafConfig& decode(const DecodeConfig& decode) & {
        sys::DecodeConfig native{
            decode.base64 ? &*decode.base64 : nullptr,
            decode.url ? &*decode.url : nullptr,
            decode.comments ? &*decode.comments : nullptr,
        };
        sys::mini_waf_waf_config_decode(handle_.get(), native);
        return *this;
    }
    WafConfig&& decode(const DecodeConfig& decode) && {
        return std::move(this->decode(decode));
    }

    const sys::WafConfig* native() const { return handle_.get(); }

private:
    detail::Handle<sys::WafConfig, sys::mini_waf_waf_config_free> handle_;
};

// Outcome of evaluating one request. Rules are views borrowed from the
// instance, as in Rust: copy them to outlive it.
struct WafEvaluationResult {
    WafDecision decision = WafDecision::Allow;
    // The `allow` rule that short-circuited, or the `block` rule that won.
    std::optional<WafRule> matched_rule;
    std::optional<std::string> reason;
    // Rules with action `log` that matched during evaluation.
    std::vector<WafRule> logged_rules;
};

// The framework-agnostic request view the engine evaluates. `get_ip` must
// return the normalized address (see normalize_client_ip).
class WafHttpContext {
public:
    virtual ~WafHttpContext() = default;

    virtual std::string framework() const = 0;
    virtual std::string get_method() const = 0;
    virtual std::string get_url() const = 0;
    virtual std::string get_path() const = 0;
    virtual std::string get_ip() const = 0;
    virtual std::string get_protocol() const = 0;
    virtual std::uint16_t get_local_port() const = 0;
    virtual std::optional<std::string>
    get_header(std::string_view name) const = 0;
    virtual HeaderMap get_headers() const = 0;
    virtual QueryMap get_query() const = 0;
    virtual CookieMap get_cookies() const = 0;
    virtual std::string get_raw_body() const = 0;
    virtual std::vector<UploadedFile> get_files() const = 0;
    virtual void set_response_header(std::string_view name,
                                     std::string_view value) = 0;
    virtual void remove_response_header(std::string_view name) = 0;
    virtual bool is_blocked() const = 0;
    virtual void drop(std::optional<std::uint16_t> status_code,
                      std::optional<std::string_view> body) = 0;
};

namespace detail {

inline void set(sys::MiniWafString* out, std::string_view text) {
    sys::mini_waf_string_set(out, text.data(), text.size());
}

inline void fill_headers(sys::HeaderMap* out, const HeaderMap& headers) {
    for (const auto& [name, value] : headers) {
        std::vector<sys::MiniWafStr> values;
        if (const auto* single = std::get_if<std::string>(&value)) {
            values.push_back(str(*single));
        } else {
            values = strs(std::get<std::vector<std::string>>(value));
        }
        sys::mini_waf_header_map_insert(out, name.data(), name.size(),
                                        values.data(), values.size());
    }
}

inline void fill_query(sys::QueryMap* out, const QueryMap& query);

using QueryValueHandle =
    Handle<sys::QueryValue, sys::mini_waf_query_value_free>;

inline QueryValueHandle native_query_value(const QueryValue& value) {
    const auto& inner = value.value;
    if (const auto* flag = std::get_if<bool>(&inner)) {
        return QueryValueHandle(sys::mini_waf_query_value_bool(*flag));
    }
    if (const auto* number = std::get_if<double>(&inner)) {
        return QueryValueHandle(sys::mini_waf_query_value_number(*number));
    }
    if (const auto* text = std::get_if<std::string>(&inner)) {
        return QueryValueHandle(
            sys::mini_waf_query_value_string(text->data(), text->size()));
    }
    if (const auto* items = std::get_if<std::vector<QueryValue>>(&inner)) {
        std::vector<QueryValueHandle> handles;
        std::vector<const sys::QueryValue*> natives;
        for (const auto& item : *items) {
            handles.push_back(native_query_value(item));
            natives.push_back(handles.back().get());
        }
        return QueryValueHandle(
            sys::mini_waf_query_value_array(natives.data(), natives.size()));
    }
    if (const auto* map = std::get_if<QueryMap>(&inner)) {
        Handle<sys::QueryMap, sys::mini_waf_query_map_free> native(
            sys::mini_waf_query_map_new());
        fill_query(native.get(), *map);
        return QueryValueHandle(sys::mini_waf_query_value_object(native.get()));
    }
    return QueryValueHandle(sys::mini_waf_query_value_null());
}

inline void fill_query(sys::QueryMap* out, const QueryMap& query) {
    for (const auto& [key, value] : query) {
        auto native = native_query_value(value);
        sys::mini_waf_query_map_insert(out, key.data(), key.size(),
                                       native.get());
    }
}

inline void fill_cookies(sys::CookieMap* out, const CookieMap& cookies) {
    for (const auto& [name, value] : cookies) {
        sys::mini_waf_cookie_map_insert(out, name.data(), name.size(),
                                        value.data(), value.size());
    }
}

inline sys::MiniWafStr optional_str(const std::optional<std::string>& text) {
    return text ? str(*text) : sys::MiniWafStr{nullptr, 0};
}

inline std::vector<sys::UploadedFile>
native_files(const std::vector<UploadedFile>& files) {
    std::vector<sys::UploadedFile> natives;
    natives.reserve(files.size());
    for (const auto& file : files) {
        natives.push_back({optional_str(file.fieldname),
                           optional_str(file.name), optional_str(file.filename),
                           optional_str(file.originalname)});
    }
    return natives;
}

inline void fill_files(sys::FilesBag* out, const FilesBag& bag) {
    if (const auto* list = std::get_if<std::vector<UploadedFile>>(&bag)) {
        auto natives = native_files(*list);
        sys::mini_waf_files_bag_list(out, natives.data(), natives.size());
        return;
    }
    for (const auto& [field, files] :
         std::get<OrderedMap<std::vector<UploadedFile>>>(bag)) {
        auto natives = native_files(files);
        sys::mini_waf_files_bag_fields_insert(out, field.data(), field.size(),
                                              natives.data(), natives.size());
    }
}

inline void fill_body(sys::RawBody* out, const RawBody& body) {
    if (const auto* text = std::get_if<std::string>(&body)) {
        sys::mini_waf_raw_body_text(out, text->data(), text->size());
    } else if (const auto* bytes =
                   std::get_if<std::vector<std::uint8_t>>(&body)) {
        sys::mini_waf_raw_body_bytes(
            out, reinterpret_cast<const char*>(bytes->data()), bytes->size());
    }
}

// Runs `body`, parking any exception in `error` instead of letting it
// unwind into the library. After a failure, later callbacks do nothing.
template <class F>
auto guard(std::exception_ptr& error, F&& body) -> decltype(body()) {
    using R = decltype(body());
    if (!error) {
        try {
            return body();
        } catch (...) {
            error = std::current_exception();
        }
    }
    if constexpr (!std::is_void_v<R>) {
        return R{};
    }
}

struct ContextFrame {
    WafHttpContext* ctx;
    std::exception_ptr error;
};

inline ContextFrame& frame(void* self) {
    return *static_cast<ContextFrame*>(self);
}

inline sys::WafHttpContext context_table(ContextFrame* state) {
    sys::WafHttpContext table{};
    table.self = state;
    table.framework = [](void* self, sys::MiniWafString* out) {
        auto& f = frame(self);
        guard(f.error, [&] { set(out, f.ctx->framework()); });
    };
    table.get_method = [](void* self, sys::MiniWafString* out) {
        auto& f = frame(self);
        guard(f.error, [&] { set(out, f.ctx->get_method()); });
    };
    table.get_url = [](void* self, sys::MiniWafString* out) {
        auto& f = frame(self);
        guard(f.error, [&] { set(out, f.ctx->get_url()); });
    };
    table.get_path = [](void* self, sys::MiniWafString* out) {
        auto& f = frame(self);
        guard(f.error, [&] { set(out, f.ctx->get_path()); });
    };
    table.get_ip = [](void* self, sys::MiniWafString* out) {
        auto& f = frame(self);
        guard(f.error, [&] { set(out, f.ctx->get_ip()); });
    };
    table.get_protocol = [](void* self, sys::MiniWafString* out) {
        auto& f = frame(self);
        guard(f.error, [&] { set(out, f.ctx->get_protocol()); });
    };
    table.get_local_port = [](void* self) -> std::uint16_t {
        auto& f = frame(self);
        return guard(f.error, [&] { return f.ctx->get_local_port(); });
    };
    table.get_header = [](void* self, const char* name, std::size_t len,
                          sys::MiniWafString* out) -> bool {
        auto& f = frame(self);
        return guard(f.error, [&] {
            auto value = f.ctx->get_header(std::string_view(name, len));
            if (value) {
                set(out, *value);
            }
            return value.has_value();
        });
    };
    table.get_headers = [](void* self, sys::HeaderMap* out) {
        auto& f = frame(self);
        guard(f.error, [&] { fill_headers(out, f.ctx->get_headers()); });
    };
    table.get_query = [](void* self, sys::QueryMap* out) {
        auto& f = frame(self);
        guard(f.error, [&] { fill_query(out, f.ctx->get_query()); });
    };
    table.get_cookies = [](void* self, sys::CookieMap* out) {
        auto& f = frame(self);
        guard(f.error, [&] { fill_cookies(out, f.ctx->get_cookies()); });
    };
    table.get_raw_body = [](void* self, sys::MiniWafString* out) {
        auto& f = frame(self);
        guard(f.error, [&] { set(out, f.ctx->get_raw_body()); });
    };
    table.get_files = [](void* self, sys::FilesBag* out) {
        auto& f = frame(self);
        guard(f.error, [&] { fill_files(out, FilesBag(f.ctx->get_files())); });
    };
    table.set_response_header = [](void* self, const char* name,
                                   std::size_t name_len, const char* value,
                                   std::size_t value_len) {
        auto& f = frame(self);
        guard(f.error, [&] {
            f.ctx->set_response_header(std::string_view(name, name_len),
                                       std::string_view(value, value_len));
        });
    };
    table.remove_response_header = [](void* self, const char* name,
                                      std::size_t len) {
        auto& f = frame(self);
        guard(f.error, [&] {
            f.ctx->remove_response_header(std::string_view(name, len));
        });
    };
    table.is_blocked = [](void* self) -> bool {
        auto& f = frame(self);
        return guard(f.error, [&] { return f.ctx->is_blocked(); });
    };
    table.drop = [](void* self, const std::uint16_t* status_code,
                    const char* body, std::size_t body_len) {
        auto& f = frame(self);
        guard(f.error, [&] {
            std::optional<std::uint16_t> status;
            if (status_code) {
                status = *status_code;
            }
            std::optional<std::string_view> text;
            if (body) {
                text = std::string_view(body, body_len);
            }
            f.ctx->drop(status, text);
        });
    };
    return table;
}

}  // namespace detail

// The request / response mappers create_adapter turns into an adapter.
// Required: get_method, get_url, get_ip, get_headers, get_raw_body,
// set_response_header and drop; the others default as in Rust.
template <class TRequest, class TResponse>
class CustomAdapterHandlers {
public:
    using TextHandler = std::function<std::string(const TRequest&)>;
    using LocalPortHandler =
        std::function<std::uint16_t(const TRequest&, const TResponse&)>;
    using HeaderHandler = std::function<std::optional<std::string>(
        const TRequest&, std::string_view)>;
    using HeadersHandler = std::function<HeaderMap(const TRequest&)>;
    using QueryHandler = std::function<QueryMap(const TRequest&)>;
    using CookiesHandler = std::function<CookieMap(const TRequest&)>;
    using RawBodyHandler = std::function<RawBody(const TRequest&)>;
    using FilesHandler = std::function<FilesBag(const TRequest&)>;
    using SetHeaderHandler =
        std::function<void(TResponse&, std::string_view, std::string_view)>;
    using RemoveHeaderHandler =
        std::function<void(TResponse&, std::string_view)>;
    using DropHandler = std::function<void(const TRequest&, TResponse&,
                                           std::uint16_t, std::string_view)>;

    explicit CustomAdapterHandlers(std::string name) : name_(std::move(name)) {}

#define MINI_WAF_HANDLER(setter, type)                                         \
    CustomAdapterHandlers& setter(type handler) & {                            \
        setter##_ = std::move(handler);                                        \
        return *this;                                                          \
    }                                                                          \
    CustomAdapterHandlers&& setter(type handler) && {                          \
        return std::move(this->setter(std::move(handler)));                    \
    }

    MINI_WAF_HANDLER(get_method, TextHandler)
    MINI_WAF_HANDLER(get_url, TextHandler)
    MINI_WAF_HANDLER(get_path, TextHandler)
    MINI_WAF_HANDLER(get_ip, TextHandler)
    MINI_WAF_HANDLER(get_protocol, TextHandler)
    MINI_WAF_HANDLER(get_local_port, LocalPortHandler)
    MINI_WAF_HANDLER(get_header, HeaderHandler)
    MINI_WAF_HANDLER(get_headers, HeadersHandler)
    MINI_WAF_HANDLER(get_query, QueryHandler)
    MINI_WAF_HANDLER(get_cookies, CookiesHandler)
    MINI_WAF_HANDLER(get_raw_body, RawBodyHandler)
    MINI_WAF_HANDLER(get_files, FilesHandler)
    MINI_WAF_HANDLER(set_response_header, SetHeaderHandler)
    MINI_WAF_HANDLER(remove_response_header, RemoveHeaderHandler)
    MINI_WAF_HANDLER(drop, DropHandler)
#undef MINI_WAF_HANDLER

private:
    template <class Req, class Res>
    friend class CustomAdapter;

    std::string name_;
    TextHandler get_method_;
    TextHandler get_url_;
    TextHandler get_path_;
    TextHandler get_ip_;
    TextHandler get_protocol_;
    LocalPortHandler get_local_port_;
    HeaderHandler get_header_;
    HeadersHandler get_headers_;
    QueryHandler get_query_;
    CookiesHandler get_cookies_;
    RawBodyHandler get_raw_body_;
    FilesHandler get_files_;
    SetHeaderHandler set_response_header_;
    RemoveHeaderHandler remove_response_header_;
    DropHandler drop_;
};

// The adapter create_adapter builds. Thread-safe if the handlers are.
template <class TRequest, class TResponse>
class CustomAdapter {
public:
    const std::string& name() const { return handlers_->name_; }

    const sys::CustomAdapter* native() const { return handle_.get(); }

    // What the library passes back to every handler during `protect`.
    struct Frame {
        const CustomAdapterHandlers<TRequest, TResponse>* handlers;
        const TRequest* request;
        TResponse* response;
        std::exception_ptr error;
    };

private:
    using Handlers = CustomAdapterHandlers<TRequest, TResponse>;
    using TextHandler = typename Handlers::TextHandler;

    template <class Req, class Res>
    friend CustomAdapter<Req, Res>
    create_adapter(CustomAdapterHandlers<Req, Res> handlers);

    explicit CustomAdapter(Handlers handlers)
        : handlers_(std::make_shared<Handlers>(std::move(handlers))) {
        detail::Handle<sys::CustomAdapterHandlers,
                       sys::mini_waf_custom_adapter_handlers_free>
            native(sys::mini_waf_custom_adapter_handlers_new(
                handlers_->name_.data(), handlers_->name_.size()));
        register_handlers(native.get());
        handle_.reset(detail::check<AdapterBuildError>([&](char** error) {
            return sys::mini_waf_create_adapter(native.get(), error);
        }));
    }

    static const Frame& frame(const void* pointer) {
        return *static_cast<const Frame*>(pointer);
    }

    static Frame& frame(void* pointer) { return *static_cast<Frame*>(pointer); }

    template <TextHandler Handlers::* Member>
    static void text(const void* pointer, sys::MiniWafString* out) {
        auto& f = frame(const_cast<void*>(pointer));
        detail::guard(f.error, [&] {
            detail::set(out, (f.handlers->*Member)(*f.request));
        });
    }

    void register_handlers(sys::CustomAdapterHandlers* native) const {
        const Handlers& h = *handlers_;
        if (h.get_method_) {
            sys::mini_waf_custom_adapter_handlers_get_method(
                native, &text<&Handlers::get_method_>);
        }
        if (h.get_url_) {
            sys::mini_waf_custom_adapter_handlers_get_url(
                native, &text<&Handlers::get_url_>);
        }
        if (h.get_path_) {
            sys::mini_waf_custom_adapter_handlers_get_path(
                native, &text<&Handlers::get_path_>);
        }
        if (h.get_ip_) {
            sys::mini_waf_custom_adapter_handlers_get_ip(
                native, &text<&Handlers::get_ip_>);
        }
        if (h.get_protocol_) {
            sys::mini_waf_custom_adapter_handlers_get_protocol(
                native, &text<&Handlers::get_protocol_>);
        }
        if (h.get_local_port_) {
            sys::mini_waf_custom_adapter_handlers_get_local_port(
                native, [](const void* pointer, const void*) -> std::uint16_t {
                    auto& f = frame(const_cast<void*>(pointer));
                    return detail::guard(f.error, [&] {
                        return f.handlers->get_local_port_(*f.request,
                                                           *f.response);
                    });
                });
        }
        if (h.get_header_) {
            sys::mini_waf_custom_adapter_handlers_get_header(
                native,
                [](const void* pointer, const char* name, std::size_t len,
                   sys::MiniWafString* out) -> bool {
                    auto& f = frame(const_cast<void*>(pointer));
                    return detail::guard(f.error, [&] {
                        auto value = f.handlers->get_header_(
                            *f.request, std::string_view(name, len));
                        if (value) {
                            detail::set(out, *value);
                        }
                        return value.has_value();
                    });
                });
        }
        if (h.get_headers_) {
            sys::mini_waf_custom_adapter_handlers_get_headers(
                native, [](const void* pointer, sys::HeaderMap* out) {
                    auto& f = frame(const_cast<void*>(pointer));
                    detail::guard(f.error, [&] {
                        detail::fill_headers(
                            out, f.handlers->get_headers_(*f.request));
                    });
                });
        }
        if (h.get_query_) {
            sys::mini_waf_custom_adapter_handlers_get_query(
                native, [](const void* pointer, sys::QueryMap* out) {
                    auto& f = frame(const_cast<void*>(pointer));
                    detail::guard(f.error, [&] {
                        detail::fill_query(out,
                                           f.handlers->get_query_(*f.request));
                    });
                });
        }
        if (h.get_cookies_) {
            sys::mini_waf_custom_adapter_handlers_get_cookies(
                native, [](const void* pointer, sys::CookieMap* out) {
                    auto& f = frame(const_cast<void*>(pointer));
                    detail::guard(f.error, [&] {
                        detail::fill_cookies(
                            out, f.handlers->get_cookies_(*f.request));
                    });
                });
        }
        if (h.get_raw_body_) {
            sys::mini_waf_custom_adapter_handlers_get_raw_body(
                native, [](const void* pointer, sys::RawBody* out) {
                    auto& f = frame(const_cast<void*>(pointer));
                    detail::guard(f.error, [&] {
                        detail::fill_body(
                            out, f.handlers->get_raw_body_(*f.request));
                    });
                });
        }
        if (h.get_files_) {
            sys::mini_waf_custom_adapter_handlers_get_files(
                native, [](const void* pointer, sys::FilesBag* out) {
                    auto& f = frame(const_cast<void*>(pointer));
                    detail::guard(f.error, [&] {
                        detail::fill_files(out,
                                           f.handlers->get_files_(*f.request));
                    });
                });
        }
        if (h.set_response_header_) {
            sys::mini_waf_custom_adapter_handlers_set_response_header(
                native,
                [](void* pointer, const char* name, std::size_t name_len,
                   const char* value, std::size_t value_len) {
                    auto& f = frame(pointer);
                    detail::guard(f.error, [&] {
                        f.handlers->set_response_header_(
                            *f.response, std::string_view(name, name_len),
                            std::string_view(value, value_len));
                    });
                });
        }
        if (h.remove_response_header_) {
            sys::mini_waf_custom_adapter_handlers_remove_response_header(
                native, [](void* pointer, const char* name, std::size_t len) {
                    auto& f = frame(pointer);
                    detail::guard(f.error, [&] {
                        f.handlers->remove_response_header_(
                            *f.response, std::string_view(name, len));
                    });
                });
        }
        if (h.drop_) {
            sys::mini_waf_custom_adapter_handlers_drop(
                native, [](const void* pointer, void*, std::uint16_t status,
                           const char* body, std::size_t len) {
                    auto& f = frame(const_cast<void*>(pointer));
                    detail::guard(f.error, [&] {
                        f.handlers->drop_(*f.request, *f.response, status,
                                          std::string_view(body, len));
                    });
                });
        }
    }

    std::shared_ptr<const Handlers> handlers_;
    detail::Handle<sys::CustomAdapter, sys::mini_waf_custom_adapter_free>
        handle_;

    friend class MiniWafInstance;
};

// Build a WAF adapter from typed request / response mappers; throws
// AdapterBuildError listing every missing required handler.
template <class TRequest, class TResponse>
CustomAdapter<TRequest, TResponse>
create_adapter(CustomAdapterHandlers<TRequest, TResponse> handlers) {
    return CustomAdapter<TRequest, TResponse>(std::move(handlers));
}

// Receives log events while config logging is on, filtered by its level
// (Error: blocked; Info: + audit; Debug: + connection). Called on the
// evaluating thread, possibly from several at once, before handle /
// protect returns; an exception it throws comes out of that call. `ctx` is
// read-only and, like `rule`, valid only during the call.
class WafLogger {
public:
    virtual ~WafLogger() = default;

    virtual void blocked(const WafHttpContext& ctx, const WafRule& rule) = 0;
    virtual void audit(const WafHttpContext& ctx, const WafRule& rule) = 0;
    virtual void connection(const WafHttpContext& ctx) = 0;
};

// Rate-limit buckets an engine counts in. Give one to several instances
// (WafEngineOptions) so they share counters, such as a rebuilt instance
// taking over from the one it replaces.
class RateLimitStore {
public:
    explicit RateLimitStore(const RateLimitStoreOptions& options = {})
        : RateLimitStore(sys::mini_waf_rate_limit_store_new({
              options.max_keys ? &*options.max_keys : nullptr,
              options.idle_ms ? &*options.idle_ms : nullptr,
              options.prune_every_hits ? &*options.prune_every_hits : nullptr,
          })) {}

    const sys::RateLimitStore* native() const { return handle_.get(); }

private:
    friend class MiniWafInstance;

    explicit RateLimitStore(sys::RateLimitStore* handle)
        : handle_(handle, sys::mini_waf_rate_limit_store_free) {}

    std::shared_ptr<sys::RateLimitStore> handle_;
};

// Engine-level injectables for create_mini_waf.
struct WafEngineOptions {
    // A shared store (default: a new one per instance).
    std::optional<RateLimitStore> rate_limit_store;
    // The logging sink while config logging is on (default: the console).
    std::shared_ptr<WafLogger> logger;
};

namespace detail {

// The error slot of the evaluation running on this thread, where logger
// callbacks park their exceptions for handle / protect to rethrow.
inline std::exception_ptr*& current_error() {
    thread_local std::exception_ptr* slot = nullptr;
    return slot;
}

class ErrorScope {
public:
    explicit ErrorScope(std::exception_ptr& error)
        : previous_(std::exchange(current_error(), &error)) {}
    ~ErrorScope() { current_error() = previous_; }
    ErrorScope(const ErrorScope&) = delete;
    ErrorScope& operator=(const ErrorScope&) = delete;

private:
    std::exception_ptr* previous_;
};

inline std::string string(sys::MiniWafStr text) {
    return string(text.data, text.len);
}

inline HeaderMap read_headers(const sys::HeaderMap* map) {
    HeaderMap headers;
    sys::MiniWafStr name{};
    bool multi = false;
    std::size_t count = 0;
    for (std::size_t index = 0;
         sys::mini_waf_header_map_get_at(map, index, &name, &multi, &count);
         index++) {
        std::vector<std::string> values;
        for (std::size_t value_index = 0; value_index < count; value_index++) {
            sys::MiniWafStr value{};
            sys::mini_waf_header_map_get_value_at(map, index, value_index,
                                                  &value);
            values.push_back(string(value));
        }
        if (multi) {
            headers.emplace_back(string(name), std::move(values));
        } else {
            headers.emplace_back(string(name), std::move(values.at(0)));
        }
    }
    return headers;
}

inline QueryMap read_query(const sys::QueryMap* map);

inline QueryValue read_query_value(const sys::QueryValue* value) {
    switch (sys::mini_waf_query_value_kind(value)) {
    case sys::QUERY_VALUE_KIND_BOOL:
        return {sys::mini_waf_query_value_get_bool(value)};
    case sys::QUERY_VALUE_KIND_NUMBER:
        return {sys::mini_waf_query_value_get_number(value)};
    case sys::QUERY_VALUE_KIND_STRING: {
        sys::MiniWafStr text{};
        sys::mini_waf_query_value_get_string(value, &text);
        return {string(text)};
    }
    case sys::QUERY_VALUE_KIND_ARRAY: {
        std::vector<QueryValue> items;
        for (std::size_t index = 0;
             index < sys::mini_waf_query_value_array_len(value); index++) {
            items.push_back(read_query_value(
                sys::mini_waf_query_value_array_get(value, index)));
        }
        return {std::move(items)};
    }
    case sys::QUERY_VALUE_KIND_OBJECT:
        return {read_query(sys::mini_waf_query_value_get_object(value))};
    default:
        return {};
    }
}

inline QueryMap read_query(const sys::QueryMap* map) {
    QueryMap query;
    sys::MiniWafStr key{};
    for (std::size_t index = 0; index < sys::mini_waf_query_map_len(map);
         index++) {
        const sys::QueryValue* value =
            sys::mini_waf_query_map_get_at(map, index, &key);
        query.emplace_back(string(key), read_query_value(value));
    }
    return query;
}

inline CookieMap read_cookies(const sys::CookieMap* map) {
    CookieMap cookies;
    sys::MiniWafStr name{};
    sys::MiniWafStr value{};
    for (std::size_t index = 0;
         sys::mini_waf_cookie_map_get_at(map, index, &name, &value); index++) {
        cookies.emplace_back(string(name), string(value));
    }
    return cookies;
}

inline std::optional<std::string> optional_string(sys::MiniWafStr text) {
    return optional_string(text.data, text.len);
}

// The request of a log event: a read-only WafHttpContext over the engine's.
class ContextRef final : public WafHttpContext {
public:
    explicit ContextRef(const sys::WafHttpContextRef* ctx) : ctx_(ctx) {}

    std::string framework() const override {
        return text(sys::mini_waf_waf_http_context_ref_framework);
    }
    std::string get_method() const override {
        return text(sys::mini_waf_waf_http_context_ref_get_method);
    }
    std::string get_url() const override {
        return text(sys::mini_waf_waf_http_context_ref_get_url);
    }
    std::string get_path() const override {
        return text(sys::mini_waf_waf_http_context_ref_get_path);
    }
    std::string get_ip() const override {
        return text(sys::mini_waf_waf_http_context_ref_get_ip);
    }
    std::string get_protocol() const override {
        return text(sys::mini_waf_waf_http_context_ref_get_protocol);
    }
    std::uint16_t get_local_port() const override {
        return sys::mini_waf_waf_http_context_ref_get_local_port(ctx_);
    }
    std::optional<std::string>
    get_header(std::string_view name) const override {
        std::size_t len = 0;
        const char* value = sys::mini_waf_waf_http_context_ref_get_header(
            ctx_, name.data(), name.size(), &len);
        return optional_string(value, len);
    }
    HeaderMap get_headers() const override {
        return read_headers(
            sys::mini_waf_waf_http_context_ref_get_headers(ctx_));
    }
    QueryMap get_query() const override {
        return read_query(sys::mini_waf_waf_http_context_ref_get_query(ctx_));
    }
    CookieMap get_cookies() const override {
        return read_cookies(
            sys::mini_waf_waf_http_context_ref_get_cookies(ctx_));
    }
    std::string get_raw_body() const override {
        return text(sys::mini_waf_waf_http_context_ref_get_raw_body);
    }
    std::vector<UploadedFile> get_files() const override {
        std::size_t count = 0;
        const sys::UploadedFile* files =
            sys::mini_waf_waf_http_context_ref_get_files(ctx_, &count);
        std::vector<UploadedFile> converted;
        for (std::size_t index = 0; index < count; index++) {
            converted.push_back({optional_string(files[index].fieldname),
                                 optional_string(files[index].name),
                                 optional_string(files[index].filename),
                                 optional_string(files[index].originalname)});
        }
        return converted;
    }
    void set_response_header(std::string_view, std::string_view) override {
        read_only();
    }
    void remove_response_header(std::string_view) override { read_only(); }
    bool is_blocked() const override {
        return sys::mini_waf_waf_http_context_ref_is_blocked(ctx_);
    }
    void drop(std::optional<std::uint16_t>,
              std::optional<std::string_view>) override {
        read_only();
    }

private:
    using TextGetter = const char* (*)(const sys::WafHttpContextRef*,
                                       std::size_t*);

    std::string text(TextGetter getter) const {
        std::size_t len = 0;
        const char* data = getter(ctx_, &len);
        return string(data, len);
    }

    [[noreturn]] static void read_only() {
        throw std::logic_error("mini-waf: a logged request is read-only");
    }

    const sys::WafHttpContextRef* ctx_;
};

// The WafLogger callbacks; `user_data` is a heap std::shared_ptr<WafLogger>.
struct LoggerTrampolines {
    using Sink = std::shared_ptr<WafLogger>;

    template <class F>
    static void run(F&& body) {
        std::exception_ptr* error = current_error();
        if (error) {
            guard(*error, std::forward<F>(body));
            return;
        }
        try {
            body();
        } catch (...) {
            // No evaluation to report to: nothing sane to do but drop it.
        }
    }

    static void blocked(void* user_data, const sys::WafHttpContextRef* ctx,
                        const sys::WafRule* rule) {
        run([&] {
            (*static_cast<Sink*>(user_data))
                ->blocked(ContextRef(ctx), WafRule::borrowed(rule));
        });
    }

    static void audit(void* user_data, const sys::WafHttpContextRef* ctx,
                      const sys::WafRule* rule) {
        run([&] {
            (*static_cast<Sink*>(user_data))
                ->audit(ContextRef(ctx), WafRule::borrowed(rule));
        });
    }

    static void connection(void* user_data, const sys::WafHttpContextRef* ctx) {
        run([&] {
            (*static_cast<Sink*>(user_data))->connection(ContextRef(ctx));
        });
    }

    static void drop(void* user_data) { delete static_cast<Sink*>(user_data); }
};

}  // namespace detail

// A WAF instance: presets and rules resolved and compiled once. Thread-safe.
class MiniWafInstance {
public:
    // The active rules, in evaluation order (views valid while this lives).
    std::vector<WafRule> rules() const {
        std::size_t count = 0;
        const sys::WafRule* const* rules =
            sys::mini_waf_mini_waf_instance_rules(handle_.get(), &count);
        std::vector<WafRule> views;
        views.reserve(count);
        for (std::size_t index = 0; index < count; index++) {
            views.push_back(WafRule::borrowed(rules[index]));
        }
        return views;
    }

    // The store the instance counts in, to share with its successor.
    RateLimitStore rate_limit_store() const {
        return RateLimitStore(
            sys::mini_waf_mini_waf_instance_rate_limit_store(handle_.get()));
    }

    // Evaluate a request through its context. On block, calls ctx.drop()
    // with the configured status and body.
    WafEvaluationResult handle(WafHttpContext& ctx) const {
        detail::ContextFrame frame{&ctx, nullptr};
        detail::ErrorScope scope(frame.error);
        sys::WafHttpContext table = detail::context_table(&frame);
        return finish(
            sys::mini_waf_mini_waf_instance_handle(handle_.get(), &table),
            frame.error);
    }

    // Run the engine against an adapter + native request / response.
    template <class TRequest, class TResponse>
    WafEvaluationResult
    protect(const CustomAdapter<TRequest, TResponse>& adapter,
            const TRequest& request, TResponse& response) const {
        typename CustomAdapter<TRequest, TResponse>::Frame frame{
            adapter.handlers_.get(), &request, &response, nullptr};
        detail::ErrorScope scope(frame.error);
        return finish(sys::mini_waf_mini_waf_instance_protect(
                          handle_.get(), adapter.native(), &frame, &frame),
                      frame.error);
    }

private:
    friend MiniWafInstance create_mini_waf(const WafConfig& config,
                                           const WafEngineOptions& options);

    explicit MiniWafInstance(sys::MiniWafInstance* handle) : handle_(handle) {}

    static WafEvaluationResult finish(sys::WafEvaluationResult* native,
                                      const std::exception_ptr& error) {
        detail::Handle<sys::WafEvaluationResult,
                       sys::mini_waf_waf_evaluation_result_free>
            result(native);
        if (error) {
            std::rethrow_exception(error);
        }
        if (!result) {
            throw std::runtime_error("mini-waf: evaluation failed");
        }
        WafEvaluationResult converted;
        converted.decision = static_cast<WafDecision>(
            sys::mini_waf_waf_evaluation_result_get_decision(result.get()));
        if (const sys::WafRule* matched =
                sys::mini_waf_waf_evaluation_result_get_matched_rule(
                    result.get())) {
            converted.matched_rule = WafRule::borrowed(matched);
        }
        std::size_t len = 0;
        const char* reason =
            sys::mini_waf_waf_evaluation_result_get_reason(result.get(), &len);
        converted.reason = detail::optional_string(reason, len);
        std::size_t count = 0;
        const sys::WafRule* const* logged =
            sys::mini_waf_waf_evaluation_result_get_logged_rules(result.get(),
                                                                 &count);
        for (std::size_t index = 0; index < count; index++) {
            converted.logged_rules.push_back(WafRule::borrowed(logged[index]));
        }
        return converted;
    }

    detail::Handle<sys::MiniWafInstance, sys::mini_waf_mini_waf_instance_free>
        handle_;
};

// Build a WAF instance: the main entry point. `options` carries
// engine-level injectables, such as a logger or a shared rate-limit store.
inline MiniWafInstance create_mini_waf(const WafConfig& config,
                                       const WafEngineOptions& options = {}) {
    detail::Handle<sys::WafEngineOptions, sys::mini_waf_waf_engine_options_free>
        native(sys::mini_waf_waf_engine_options_new());
    if (options.logger) {
        sys::WafLogger logger{
            new detail::LoggerTrampolines::Sink(options.logger),
            &detail::LoggerTrampolines::blocked,
            &detail::LoggerTrampolines::audit,
            &detail::LoggerTrampolines::connection,
            &detail::LoggerTrampolines::drop,
        };
        sys::mini_waf_waf_engine_options_logger(native.get(), logger);
    }
    if (options.rate_limit_store) {
        sys::mini_waf_waf_engine_options_rate_limit_store(
            native.get(), options.rate_limit_store->native());
    }
    return MiniWafInstance(sys::mini_waf_create_mini_waf_with_options(
        config.native(), native.get()));
}

inline std::string normalize_client_ip(std::string_view raw) {
    return detail::take_string(
        sys::mini_waf_normalize_client_ip(raw.data(), raw.size()));
}

inline std::string pick_client_ip_from_xff(std::string_view forwarded_for) {
    return detail::take_string(sys::mini_waf_pick_client_ip_from_xff(
        forwarded_for.data(), forwarded_for.size()));
}

inline bool is_host_ip_literal(std::string_view host_header) {
    return sys::mini_waf_is_host_ip_literal(host_header.data(),
                                            host_header.size());
}

}  // namespace mini_waf

#endif  // MINI_WAF_HPP
