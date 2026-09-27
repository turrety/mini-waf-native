package io.github.murylloex.miniwaf;

import java.util.List;
import java.util.Optional;

/**
 * Outcome of evaluating one request. Rules are views of the instance's
 * rules, valid until it is closed.
 *
 * @param decision the final verdict
 * @param matchedRule the {@code allow} rule that short-circuited, or the
 *     {@code block} rule that won
 * @param reason the reason of that rule
 * @param loggedRules rules with action {@code log} that matched
 */
public record WafEvaluationResult(
    WafDecision decision,
    Optional<WafRule> matchedRule,
    Optional<String> reason,
    List<WafRule> loggedRules
) {}
