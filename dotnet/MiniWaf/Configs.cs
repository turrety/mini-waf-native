namespace MurylloEx.MiniWaf;

/// <summary>
/// <c>WafConfig.DecisionCache</c>: a short-TTL LRU of allow/block decisions
/// keyed by a request fingerprint. Null members take the default.
/// </summary>
/// <param name="Max">Default 256.</param>
/// <param name="TtlMs">Default 1000 ms.</param>
public sealed record DecisionCacheConfig(
    ulong? Max = null,
    ulong? TtlMs = null
);

/// <summary>
/// <c>WafConfig.Decode</c>: transport decoders. Null members are automatic:
/// off at <c>Low</c> / <c>Balanced</c>, on at <c>High</c> and above.
/// </summary>
public sealed record DecodeConfig(
    bool? Base64 = null,
    bool? Url = null,
    bool? Comments = null
);

/// <summary>
/// Structured logging options. Events go to the console; the injectable sink
/// of the Rust API is not available from .NET.
/// </summary>
/// <param name="Level">Default <c>Info</c>.</param>
public sealed record WafLoggingOptions(WafLogLevel? Level = null);
