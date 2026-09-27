namespace MurylloEx.MiniWaf;

/// <summary>
/// A rule condition: a field match, or <c>All</c> / <c>AnyOf</c> / <c>Not</c>.
/// </summary>
public sealed class WafCondition : NativeResource
{
    internal WafCondition(nint handle)
        : base(handle, Api.WafConditionFree) { }

    /// <summary>
    /// <c>WafCondition::Field</c>, the <c>From&lt;FieldCondition&gt;</c>
    /// conversion.
    /// </summary>
    public static WafCondition From(FieldCondition condition) =>
        condition.With(field => new WafCondition(Api.WafConditionField(field)));

    /// <summary>Logical AND.</summary>
    public static WafCondition All(params WafCondition[] conditions) =>
        Combine(conditions, Api.WafConditionAll);

    /// <summary>Logical OR.</summary>
    public static WafCondition AnyOf(params WafCondition[] conditions) =>
        Combine(conditions, Api.WafConditionAnyOf);

    /// <summary>Negation.</summary>
    public static WafCondition Not(WafCondition condition) =>
        condition.With(inner => new WafCondition(Api.WafConditionNot(inner)));

    private static WafCondition Combine(
        IReadOnlyList<WafCondition> conditions,
        Func<nint, nuint, nint> combine
    ) =>
        Resources.WithAll(
            conditions,
            handles =>
            {
                using Arena arena = new();
                return new WafCondition(
                    combine(arena.Pointers(handles), (nuint)handles.Count)
                );
            }
        );
}
