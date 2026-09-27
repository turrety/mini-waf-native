package io.github.murylloex.miniwaf;

/** An invalid rule regex ({@code MatchPattern.regex}). */
public final class RegexError extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public RegexError(String message) {
        super(message);
    }
}
