//! Logging: the [`WafLogger`] port and its console implementation.

pub(crate) mod logger;
pub(crate) mod port;

pub use logger::{
    ConsoleLoggerOptions,
    create_console_logger,
};
pub use port::{
    ResolvedLogging,
    WafLogLevel,
    WafLogger,
    WafLoggingOptions,
    WafLoggingSetting,
    is_log_level_active,
    is_waf_log_level,
    pick_logger_sink,
    resolve_logging,
    silent_logger,
};
