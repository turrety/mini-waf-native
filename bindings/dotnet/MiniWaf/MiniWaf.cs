namespace MurylloEx.MiniWaf;

/// <summary>
/// The free functions of the <c>mini_waf</c> crate, under their Rust names
/// in PascalCase (<c>create_mini_waf</c> is <see cref="CreateMiniWaf"/>).
/// </summary>
/// <example>
/// <code>
/// using MiniWafInstance waf = MiniWaf.CreateMiniWaf(
///     new WafConfig()
///         .Presets(WafPresetName.Default)
///         .Level(ProtectionLevel.Balanced));
/// </code>
/// </example>
public static class MiniWaf
{
    /// <summary>
    /// Build a WAF instance: the main entry point. Presets and rules are
    /// resolved into a single immutable rule list, filtered by level.
    /// </summary>
    public static MiniWafInstance CreateMiniWaf(WafConfig config) =>
        config.With(nativeConfig => new MiniWafInstance(
            Api.CreateMiniWaf(nativeConfig)
        ));

    /// <summary>
    /// Build a WAF adapter for any framework from typed request / response
    /// mappers; throws <see cref="AdapterBuildError"/> listing every missing
    /// required handler.
    /// </summary>
    public static CustomAdapter<TRequest, TResponse> CreateAdapter<
        TRequest,
        TResponse
    >(CustomAdapterHandlers<TRequest, TResponse> handlers) => new(handlers);

    /// <summary>
    /// Parse a JSON rules document (an array of rules, or
    /// <c>{"rules": [...]}</c>) into rules; throws
    /// <see cref="RuleParseError"/>.
    /// </summary>
    public static unsafe IReadOnlyList<WafRule> ParseRulesFromJson(string input)
    {
        using Arena arena = new();
        nint text = arena.Text(input, out nuint length);
        nuint count = 0;
        nint error = 0;
        nint rules = Api.ParseRulesFromJson(
            text,
            length,
            (nint)(&count),
            (nint)(&error)
        );
        if (rules == 0)
        {
            throw new RuleParseError(
                Text.Take(error) ?? "invalid rules document"
            );
        }
        try
        {
            WafRule[] parsed = new WafRule[(int)count];
            for (int index = 0; index < parsed.Length; index++)
            {
                parsed[index] = WafRule.Take(
                    Api.WafRuleClone(((nint*)rules)[index])
                );
            }
            return parsed;
        }
        finally
        {
            Api.WafRuleArrayFree(rules, count);
        }
    }

    /// <summary>
    /// Normalize a client address: IPv4-mapped IPv6 to IPv4, ports and
    /// brackets stripped.
    /// </summary>
    public static string NormalizeClientIp(string raw) =>
        WithText(raw, Api.NormalizeClientIp);

    /// <summary>
    /// First hop of an <c>X-Forwarded-For</c> value, normalized.
    /// </summary>
    public static string PickClientIpFromXff(string forwardedFor) =>
        WithText(forwardedFor, Api.PickClientIpFromXff);

    /// <summary>
    /// Whether a <c>Host</c> header is a bare IP literal (with optional port).
    /// </summary>
    public static bool IsHostIpLiteral(string hostHeader)
    {
        using Arena arena = new();
        nint text = arena.Text(hostHeader, out nuint length);
        return Api.IsHostIpLiteral(text, length);
    }

    private static string WithText(
        string input,
        Func<nint, nuint, nint> function
    )
    {
        using Arena arena = new();
        nint text = arena.Text(input, out nuint length);
        return Text.Take(function(text, length)) ?? "";
    }
}
