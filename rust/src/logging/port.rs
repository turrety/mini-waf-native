//! Logging port. Side effects live behind [`WafLogger`], so the matching and
//! decision core stays free of I/O while logging is off (the default).

use std::fmt;
use std::sync::Arc;

use crate::domain::context::WafHttpContext;
use crate::domain::rules::WafRule;

/// Where log events go. Implementations must be thread-safe: one engine
/// serves every request.
pub trait WafLogger: Send + Sync {
    fn blocked(&self, ctx: &dyn WafHttpContext, rule: &WafRule);
    fn audit(&self, ctx: &dyn WafHttpContext, rule: &WafRule);
    fn connection(&self, ctx: &dyn WafHttpContext);
}

struct SilentLogger;

impl WafLogger for SilentLogger {
    fn blocked(&self, _ctx: &dyn WafHttpContext, _rule: &WafRule) {}
    fn audit(&self, _ctx: &dyn WafHttpContext, _rule: &WafRule) {}
    fn connection(&self, _ctx: &dyn WafHttpContext) {}
}

/// No-op logger — zero I/O, zero formatting.
pub fn silent_logger() -> Arc<dyn WafLogger> {
    Arc::new(SilentLogger)
}

/// Verbosity when logging is enabled: `Error` = blocks only, `Info` = blocks
/// + audit, `Debug` = + connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum WafLogLevel {
    Error,
    #[default]
    Info,
    Debug,
}

impl WafLogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            WafLogLevel::Error => "error",
            WafLogLevel::Info => "info",
            WafLogLevel::Debug => "debug",
        }
    }
}

/// Whether an arbitrary string is a valid [`WafLogLevel`].
pub fn is_waf_log_level(value: &str) -> bool {
    matches!(value, "error" | "info" | "debug")
}

/// True when the configured level is at least as verbose as `minimum`.
pub fn is_log_level_active(
    configured: WafLogLevel,
    minimum: WafLogLevel,
) -> bool {
    configured >= minimum
}

/// Structured logging options.
#[derive(Clone, Default)]
pub struct WafLoggingOptions {
    /// Default `Info`.
    pub level: Option<WafLogLevel>,
    /// Injectable sink. Default: plain console.
    pub sink: Option<Arc<dyn WafLogger>>,
}

impl fmt::Debug for WafLoggingOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WafLoggingOptions")
            .field("level", &self.level)
            .field("sink", &self.sink.as_ref().map(|_| "WafLogger"))
            .finish()
    }
}

/// `WafConfig::logging`: a boolean (`false` off, `true` console at `Info`) or
/// [`WafLoggingOptions`].
#[derive(Clone, Debug)]
pub enum WafLoggingSetting {
    Enabled(bool),
    Options(WafLoggingOptions),
}

impl Default for WafLoggingSetting {
    fn default() -> Self {
        WafLoggingSetting::Enabled(false)
    }
}

impl From<bool> for WafLoggingSetting {
    fn from(enabled: bool) -> Self {
        WafLoggingSetting::Enabled(enabled)
    }
}

impl From<WafLoggingOptions> for WafLoggingSetting {
    fn from(options: WafLoggingOptions) -> Self {
        WafLoggingSetting::Options(options)
    }
}

/// Logging after defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedLogging {
    pub enabled: bool,
    pub level: WafLogLevel,
}

/// Resolve `WafConfig::logging` into a stable enabled / level pair. Default:
/// disabled.
pub fn resolve_logging(setting: Option<&WafLoggingSetting>) -> ResolvedLogging {
    match setting {
        None | Some(WafLoggingSetting::Enabled(false)) => ResolvedLogging {
            enabled: false,
            level: WafLogLevel::Info,
        },
        Some(WafLoggingSetting::Enabled(true)) => ResolvedLogging {
            enabled: true,
            level: WafLogLevel::Info,
        },
        Some(WafLoggingSetting::Options(options)) => ResolvedLogging {
            enabled: true,
            level: options.level.unwrap_or_default(),
        },
    }
}

/// Pick the sink: `options_logger` > `logging.sink` > `fallback`.
pub fn pick_logger_sink(
    setting: Option<&WafLoggingSetting>,
    options_logger: Option<Arc<dyn WafLogger>>,
    fallback: Arc<dyn WafLogger>,
) -> Arc<dyn WafLogger> {
    if let Some(logger) = options_logger {
        return logger;
    }
    match setting {
        Some(WafLoggingSetting::Options(WafLoggingOptions {
            sink: Some(sink),
            ..
        })) => sink.clone(),
        _ => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_settings() {
        assert!(!resolve_logging(None).enabled);
        assert!(!resolve_logging(Some(&false.into())).enabled);
        assert_eq!(
            resolve_logging(Some(&true.into())),
            ResolvedLogging {
                enabled: true,
                level: WafLogLevel::Info
            }
        );
        let debug = WafLoggingSetting::Options(WafLoggingOptions {
            level: Some(WafLogLevel::Debug),
            sink: None,
        });
        assert_eq!(resolve_logging(Some(&debug)).level, WafLogLevel::Debug);
    }

    #[test]
    fn levels() {
        assert!(is_log_level_active(WafLogLevel::Debug, WafLogLevel::Info));
        assert!(!is_log_level_active(WafLogLevel::Error, WafLogLevel::Info));
        assert!(is_waf_log_level("debug") && !is_waf_log_level("trace"));
    }
}
