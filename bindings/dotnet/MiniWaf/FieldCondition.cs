namespace MurylloEx.MiniWaf;

/// <summary>
/// Match a single request field. With <c>Matches</c> / <c>Equals</c> /
/// <c>Includes</c> the condition matches when any value satisfies any of
/// them. With only <c>RateLimit</c> it matches once the field's bucket
/// exceeds the limit; combined, the pattern gates the counter.
/// </summary>
/// <remarks>
/// <see cref="Equals(string)"/> is the Rust builder of the same name: it
/// sets the value to compare with and returns this condition.
/// </remarks>
public sealed class FieldCondition : NativeResource
{
    public FieldCondition(WafField field)
        : base(Create(field), Api.FieldConditionFree) { }

    private static nint Create(WafField field)
    {
        using Arena arena = new();
        nint nativeField = field.ToNative(arena);
        try
        {
            return Api.FieldConditionNew(nativeField);
        }
        finally
        {
            Api.WafFieldFree(nativeField);
        }
    }

    /// <summary>
    /// Regex, exact string, list of strings (OR) or predicate.
    /// </summary>
    public FieldCondition Matches(MatchPattern pattern)
    {
        Run(condition =>
            pattern.Run(nativePattern =>
                Api.FieldConditionMatches(condition, nativePattern)
            )
        );
        return this;
    }

    /// <summary>Case-sensitive equality.</summary>
    public FieldCondition Equals(string value)
    {
        Run(condition =>
        {
            using Arena arena = new();
            nint text = arena.Text(value, out nuint length);
            Api.FieldConditionEquals(condition, text, length);
        });
        return this;
    }

    /// <summary>Case-insensitive substring.</summary>
    public FieldCondition Includes(string needle)
    {
        Run(condition =>
        {
            using Arena arena = new();
            nint text = arena.Text(needle, out nuint length);
            Api.FieldConditionIncludes(condition, text, length);
        });
        return this;
    }

    public FieldCondition RateLimit(RateLimitSpec spec)
    {
        Run(condition =>
        {
            using Arena arena = new();
            Api.FieldConditionRateLimit(
                condition,
                new RateLimitSpecNative
                {
                    Max = spec.Max(),
                    WindowMs = spec.WindowMs(),
                    KeyPrefix = arena.Str(spec.KeyPrefix()),
                }
            );
        });
        return this;
    }

    /// <summary>
    /// Cheap prefilter: the value must contain one of these literals before
    /// the pattern runs. List a literal every match contains, or the rule
    /// stops detecting.
    /// </summary>
    public FieldCondition Requires(params string[] literals)
    {
        Run(condition =>
        {
            using Arena arena = new();
            Api.FieldConditionRequires(
                condition,
                arena.Strs(literals),
                (nuint)literals.Length
            );
        });
        return this;
    }

    /// <summary>
    /// <c>WafCondition::Field</c>: this condition as a
    /// <see cref="WafCondition"/>.
    /// </summary>
    public WafCondition Into() => WafCondition.From(this);

    public static implicit operator WafCondition(FieldCondition condition) =>
        condition.Into();
}
