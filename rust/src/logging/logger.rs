//! Plain-console implementation of the [`WafLogger`] port.

use std::sync::Arc;
use std::sync::atomic::{
    AtomicU64,
    Ordering,
};

use crate::domain::context::WafHttpContext;
use crate::domain::rules::WafRule;
use crate::logging::port::{
    WafLogger,
    silent_logger,
};
use crate::utils::time::{
    format_utc,
    now_ms,
};

/// Options of [`create_console_logger`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ConsoleLoggerOptions {
    /// When `false`, returns [`silent_logger`]. Default: `true`.
    pub enabled: Option<bool>,
}

struct ConsoleLogger;

fn event_code() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let bump = COUNTER.fetch_add(0x9E37_79B9, Ordering::Relaxed);
    format!(
        "0x{:x}",
        now_ms().unsigned_abs().wrapping_add(bump % 1_000_000_000)
    )
}

fn format_blocked(ctx: &dyn WafHttpContext, rule: &WafRule) -> String {
    format!(
        concat!(
            "-> Mini-WAF blocked a request\n",
            "   IP: {} at {}\n",
            "   Rule: {}\n",
            "   Reason: {}\n",
            "   Method: {}\n",
            "   Path: {}\n",
            "   Event: {}",
        ),
        ctx.get_ip(),
        format_utc(now_ms()),
        rule.id,
        rule.reason.as_deref().unwrap_or(&rule.id),
        ctx.get_method(),
        ctx.get_path(),
        event_code()
    )
}

fn format_audit(ctx: &dyn WafHttpContext, rule: &WafRule) -> String {
    format!(
        concat!(
            "-> Mini-WAF audit event\n",
            "   IP: {} at {}\n",
            "   Rule: {}\n",
            "   Reason: {}\n",
            "   Method: {}\n",
            "   Event: {}",
        ),
        ctx.get_ip(),
        format_utc(now_ms()),
        rule.id,
        rule.reason.as_deref().unwrap_or(&rule.id),
        ctx.get_method(),
        event_code()
    )
}

fn format_connection(ctx: &dyn WafHttpContext) -> String {
    format!(
        "[{}] [{} {}] [INFO] connection from [{}] ua=[{}].",
        format_utc(now_ms()),
        ctx.get_protocol().to_uppercase(),
        ctx.get_method(),
        ctx.get_ip(),
        ctx.get_header("user-agent").unwrap_or_default()
    )
}

impl WafLogger for ConsoleLogger {
    fn blocked(&self, ctx: &dyn WafHttpContext, rule: &WafRule) {
        println!("{}", format_blocked(ctx, rule));
    }

    fn audit(&self, ctx: &dyn WafHttpContext, rule: &WafRule) {
        println!("{}", format_audit(ctx, rule));
    }

    fn connection(&self, ctx: &dyn WafHttpContext) {
        println!("{}", format_connection(ctx));
    }
}

/// Plain-console logger (standard output, no color, no file I/O). Prefer
/// leaving `WafConfig::logging` off in production.
pub fn create_console_logger(
    options: ConsoleLoggerOptions,
) -> Arc<dyn WafLogger> {
    if options.enabled == Some(false) {
        return silent_logger();
    }
    Arc::new(ConsoleLogger)
}
