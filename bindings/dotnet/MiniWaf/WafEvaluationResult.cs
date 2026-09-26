namespace MurylloEx.MiniWaf;

/// <summary>
/// Outcome of evaluating one request. Rules are views of the instance's
/// rules, valid until it is disposed.
/// </summary>
/// <param name="Decision">The final verdict.</param>
/// <param name="MatchedRule">
/// The <c>Allow</c> rule that short-circuited, or the <c>Block</c> rule that
/// won.
/// </param>
/// <param name="Reason">The reason of that rule.</param>
/// <param name="LoggedRules">Rules with action <c>Log</c> that matched.</param>
public sealed record WafEvaluationResult(
    WafDecision Decision,
    WafRule? MatchedRule,
    string? Reason,
    IReadOnlyList<WafRule> LoggedRules
);
