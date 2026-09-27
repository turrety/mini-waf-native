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
/// Structured logging options. Events go to the console, or to
/// <see cref="WafEngineOptions.Logger"/>.
/// </summary>
/// <param name="Level">Default <c>Info</c>.</param>
public sealed record WafLoggingOptions(WafLogLevel? Level = null);

/// <summary>
/// <c>RateLimitStoreOptions</c>: null members take the default.
/// </summary>
/// <param name="MaxKeys">
/// Distinct keys retained, evicting the coldest. Default 10000.
/// </param>
/// <param name="IdleMs">Drop keys idle this long. Default 120000 ms.</param>
/// <param name="PruneEveryHits">
/// Full idle prune every N hits, 0 to disable. Default 1024.
/// </param>
public sealed record RateLimitStoreOptions(
    ulong? MaxKeys = null,
    long? IdleMs = null,
    ulong? PruneEveryHits = null
);

/// <summary>
/// Engine-level injectables for
/// <see cref="MiniWaf.CreateMiniWaf(WafConfig, WafEngineOptions)"/>.
/// </summary>
/// <param name="RateLimitStore">
/// A shared store. Default: a new one per instance.
/// </param>
/// <param name="Logger">
/// The logging sink while <c>WafConfig.Logging</c> is on. Default: the
/// console.
/// </param>
public sealed record WafEngineOptions(
    RateLimitStore? RateLimitStore = null,
    WafLogger? Logger = null
);
