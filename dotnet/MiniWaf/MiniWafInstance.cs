namespace MurylloEx.MiniWaf;

/// <summary>
/// A WAF instance: presets and rules resolved, level-filtered, sorted and
/// compiled once. Thread-safe: build it at startup and share it across every
/// request handler.
/// </summary>
public sealed class MiniWafInstance : NativeResource
{
    internal MiniWafInstance(nint handle)
        : base(handle, Api.MiniWafInstanceFree) { }

    /// <summary>The active rules, in evaluation order.</summary>
    public unsafe IReadOnlyList<WafRule> Rules() =>
        With(instance =>
        {
            nuint count = 0;
            nint rules = Api.MiniWafInstanceRules(instance, (nint)(&count));
            return Views(rules, count);
        });

    /// <summary>
    /// Evaluate a request through its context. On block, calls
    /// <see cref="WafHttpContext.Drop"/> with the configured status and body;
    /// rate-limited rules also set <c>X-RateLimit-*</c> response headers.
    /// </summary>
    public WafEvaluationResult Handle(WafHttpContext ctx)
    {
        Upcalls.Frame frame = new(ctx);
        return With(instance =>
            Upcalls.Within(
                frame,
                () =>
                    Result(
                        Api.MiniWafInstanceHandle(
                            instance,
                            Upcalls.ContextTable
                        )
                    )
            )
        );
    }

    /// <summary>
    /// Run the engine against an adapter and a native request / response.
    /// </summary>
    public WafEvaluationResult Protect<TRequest, TResponse>(
        CustomAdapter<TRequest, TResponse> adapter,
        TRequest request,
        TResponse response
    )
    {
        Upcalls.Frame frame = new(adapter.Bind(request, response));
        return With(instance =>
            adapter.With(nativeAdapter =>
                Upcalls.Within(
                    frame,
                    () =>
                        Result(
                            Api.MiniWafInstanceProtect(
                                instance,
                                nativeAdapter,
                                0,
                                0
                            )
                        )
                )
            )
        );
    }

    private unsafe WafEvaluationResult Result(nint result)
    {
        if (result == 0)
        {
            throw new InvalidOperationException("mini-waf: evaluation failed");
        }
        try
        {
            WafDecision decision = (WafDecision)
                Api.WafEvaluationResultGetDecision(result);
            nint matched = Api.WafEvaluationResultGetMatchedRule(result);
            string? reason = Text.Lent(length =>
                Api.WafEvaluationResultGetReason(result, length)
            );
            nuint count = 0;
            nint logged = Api.WafEvaluationResultGetLoggedRules(
                result,
                (nint)(&count)
            );
            return new WafEvaluationResult(
                decision,
                matched == 0 ? null : WafRule.View(matched, this),
                reason,
                Views(logged, count)
            );
        }
        finally
        {
            Api.WafEvaluationResultFree(result);
        }
    }

    private unsafe IReadOnlyList<WafRule> Views(nint rules, nuint count)
    {
        WafRule[] views = new WafRule[(int)count];
        for (int index = 0; index < views.Length; index++)
        {
            views[index] = WafRule.View(((nint*)rules)[index], this);
        }
        return views;
    }
}
