namespace MurylloEx.MiniWaf;

/// <summary>
/// Everything the engine needs to build its immutable rule list. Every
/// setting is optional; unset ones take the documented defaults.
/// </summary>
public sealed class WafConfig : NativeResource
{
    public WafConfig()
        : base(Api.WafConfigNew(), Api.WafConfigFree) { }

    private WafConfig Set(Action<nint, Arena> change)
    {
        Run(config =>
        {
            using Arena arena = new();
            change(config, arena);
        });
        return this;
    }

    /// <summary>
    /// Only rules with <c>MinLevel &lt;= level</c> are applied. Default:
    /// <c>Balanced</c>.
    /// </summary>
    public WafConfig Level(ProtectionLevel level) =>
        Set((config, _) => Api.WafConfigLevel(config, (int)level));

    /// <summary>Custom rules evaluated after (or instead of) presets.</summary>
    public WafConfig Rules(params WafRule[] rules) =>
        Rules((IReadOnlyList<WafRule>)rules);

    public WafConfig Rules(IReadOnlyList<WafRule> rules) =>
        Set(
            (config, arena) =>
            {
                List<nint> handles =
                [
                    .. rules.Select(rule => rule.With(address => address)),
                ];
                Api.WafConfigRules(
                    config,
                    arena.Pointers(handles),
                    (nuint)handles.Count
                );
                GC.KeepAlive(rules);
            }
        );

    /// <summary>Built-in rule packs to include.</summary>
    public unsafe WafConfig Presets(params WafPresetName[] presets) =>
        Set(
            (config, arena) =>
            {
                nint array = arena.Allocate(
                    (nuint)(presets.Length * sizeof(int))
                );
                for (int index = 0; index < presets.Length; index++)
                {
                    ((int*)array)[index] = (int)presets[index];
                }
                Api.WafConfigPresets(config, array, (nuint)presets.Length);
            }
        );

    /// <summary>
    /// Only these ids remain after presets + custom merge and level filtering.
    /// </summary>
    public WafConfig EnabledRuleIds(params string[] ids) =>
        Set(
            (config, arena) =>
                Api.WafConfigEnabledRuleIds(
                    config,
                    arena.Strs(ids),
                    (nuint)ids.Length
                )
        );

    /// <summary>Drop rules whose id is listed.</summary>
    public WafConfig DisabledRuleIds(params string[] ids) =>
        Set(
            (config, arena) =>
                Api.WafConfigDisabledRuleIds(
                    config,
                    arena.Strs(ids),
                    (nuint)ids.Length
                )
        );

    /// <summary>HTTP status used on block. Default: 403.</summary>
    public WafConfig BlockStatusCode(ushort statusCode) =>
        Set((config, _) => Api.WafConfigBlockStatusCode(config, statusCode));

    /// <summary>
    /// Response body used on block. Default: <c>"Forbidden"</c>.
    /// </summary>
    public WafConfig BlockBody(string body) =>
        Set(
            (config, arena) =>
            {
                nint text = arena.Text(body, out nuint length);
                Api.WafConfigBlockBody(config, text, length);
            }
        );

    /// <summary>
    /// Logging is off by default; <c>true</c> logs to the console at
    /// <c>Info</c>.
    /// </summary>
    public WafConfig Logging(bool enabled) =>
        Set((config, _) => Api.WafConfigLogging(config, enabled));

    public WafConfig Logging(WafLoggingOptions options) =>
        Set(
            (config, arena) =>
                Api.WafConfigLoggingOptions(
                    config,
                    new WafLoggingOptionsNative
                    {
                        Level = arena.Optional(
                            options.Level is { } level ? (int?)level : null
                        ),
                    }
                )
        );

    /// <summary>
    /// Cap length of each scanned field value. Default 8192; 0 is unlimited.
    /// </summary>
    public WafConfig MaxFieldLength(nuint length) =>
        Set((config, _) => Api.WafConfigMaxFieldLength(config, length));

    /// <summary>Cap on distinct rate-limit keys. Default 10000.</summary>
    public WafConfig MaxRateLimitKeys(nuint keys) =>
        Set((config, _) => Api.WafConfigMaxRateLimitKeys(config, keys));

    /// <summary>
    /// Disabled automatically when any active rule uses <c>RateLimit</c>.
    /// </summary>
    public WafConfig DecisionCache(DecisionCacheConfig cache) =>
        Set(
            (config, arena) =>
                Api.WafConfigDecisionCache(
                    config,
                    new DecisionCacheConfigNative
                    {
                        Max = arena.Optional(
                            cache.Max is { } max ? (nuint?)max : null
                        ),
                        TtlMs = arena.Optional(cache.TtlMs),
                    }
                )
        );

    /// <summary>
    /// Transport decoders; automatic (off below <c>High</c>) when unset.
    /// </summary>
    public WafConfig Decode(DecodeConfig decode) =>
        Set(
            (config, arena) =>
                Api.WafConfigDecode(
                    config,
                    new DecodeConfigNative
                    {
                        Base64 = arena.Optional(Flag(decode.Base64)),
                        Url = arena.Optional(Flag(decode.Url)),
                        Comments = arena.Optional(Flag(decode.Comments)),
                    }
                )
        );

    /// <summary>A C <c>bool</c> (one byte).</summary>
    private static byte? Flag(bool? value) =>
        value is { } flag ? (byte)(flag ? 1 : 0) : null;
}
