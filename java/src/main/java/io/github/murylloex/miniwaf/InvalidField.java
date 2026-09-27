package io.github.murylloex.miniwaf;

/** An unsupported field path ({@code WafField.fromStr}). */
public final class InvalidField extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public InvalidField(String message) {
        super(message);
    }
}
