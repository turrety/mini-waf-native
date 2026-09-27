namespace MurylloEx.MiniWaf;

/// <summary>
/// One WAF rule. Rules returned by a <see cref="MiniWafInstance"/> are views
/// of the instance's rules, valid until it is disposed; the builder methods
/// turn a view into an independent copy first.
/// </summary>
public sealed class WafRule : IDisposable
{
    private sealed class Owned(nint handle)
        : NativeResource(handle, Api.WafRuleFree);

    private Owned? owned;
    private readonly nint borrowed;
    private readonly NativeResource? owner;

    public WafRule(string id, WafCondition when, WafAction action)
    {
        owned = new Owned(
            when.With(condition =>
            {
                using Arena arena = new();
                nint text = arena.Text(id, out nuint length);
                return Api.WafRuleNew(text, length, condition, (int)action);
            })
        );
    }

    private WafRule(Owned? owned, nint borrowed, NativeResource? owner)
    {
        this.owned = owned;
        this.borrowed = borrowed;
        this.owner = owner;
    }

    /// <summary>A view of a rule owned by <paramref name="owner"/>.</summary>
    internal static WafRule View(nint rule, NativeResource owner) =>
        new(null, rule, owner);

    /// <summary>Take ownership of a library-allocated rule.</summary>
    internal static WafRule Take(nint rule) => new(new Owned(rule), 0, null);

    /// <summary>
    /// Run <paramref name="body"/> with the native rule, keeping its owner
    /// alive.
    /// </summary>
    internal T With<T>(Func<nint, T> body) =>
        owned is { } current
            ? current.With(body)
            : owner!.With(_ => body(borrowed));

    private WafRule Update(Action<nint> change)
    {
        owned ??= new Owned(With(Api.WafRuleClone));
        owned.Run(change);
        return this;
    }

    /// <summary>Human-readable reason used in logs / block responses.</summary>
    public WafRule Reason(string reason) =>
        Update(rule =>
        {
            using Arena arena = new();
            nint text = arena.Text(reason, out nuint length);
            Api.WafRuleReason(rule, text, length);
        });

    /// <summary>Defaults to <c>true</c>.</summary>
    public WafRule Enabled(bool enabled) =>
        Update(rule => Api.WafRuleEnabled(rule, enabled));

    /// <summary>Lower numbers run first. Defaults to 100.</summary>
    public WafRule Priority(long priority) =>
        Update(rule => Api.WafRulePriority(rule, priority));

    /// <summary>
    /// Minimum protection level for this rule to run. Defaults to <c>Low</c>.
    /// </summary>
    public WafRule MinLevel(ProtectionLevel level) =>
        Update(rule => Api.WafRuleMinLevel(rule, (int)level));

    public string Id() =>
        With(rule => Text.Lent(length => Api.WafRuleGetId(rule, length)))!;

    /// <summary>A copy of the rule's condition.</summary>
    public WafCondition When() =>
        With(rule => new WafCondition(
            Api.WafConditionClone(Api.WafRuleGetWhen(rule))
        ));

    public WafAction Action() =>
        With(rule => (WafAction)Api.WafRuleGetAction(rule));

    public string? Reason() =>
        With(rule => Text.Lent(length => Api.WafRuleGetReason(rule, length)));

    public unsafe bool? Enabled() =>
        With<bool?>(rule =>
        {
            byte value = 0;
            return Api.WafRuleGetEnabled(rule, (nint)(&value))
                ? value != 0
                : null;
        });

    public unsafe long? Priority() =>
        With<long?>(rule =>
        {
            long value = 0;
            return Api.WafRuleGetPriority(rule, (nint)(&value)) ? value : null;
        });

    public unsafe ProtectionLevel? MinLevel() =>
        With<ProtectionLevel?>(rule =>
        {
            int value = 0;
            return Api.WafRuleGetMinLevel(rule, (nint)(&value))
                ? (ProtectionLevel)value
                : null;
        });

    public override string ToString() => $"WafRule({Id()})";

    /// <summary>
    /// Free an owned rule now; a view is released with its instance.
    /// </summary>
    public void Dispose() => owned?.Dispose();
}
