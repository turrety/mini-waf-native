package io.github.murylloex.miniwaf;

/**
 * A malformed JSON rules document ({@code MiniWaf.parseRulesFromJson}); the
 * message starts with the offending path, such as {@code rules[2].when}.
 */
public final class RuleParseError extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public RuleParseError(String message) {
        super(message);
    }
}
