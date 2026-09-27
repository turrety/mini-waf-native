package io.github.murylloex.miniwaf;

import java.util.Arrays;
import java.util.List;

/**
 * Thrown by {@link MiniWaf#createAdapter} when required handlers are missing.
 */
public final class AdapterBuildError extends RuntimeException {

    private static final long serialVersionUID = 1L;
    private static final String PREFIX =
        "adapter is missing required handlers: ";

    public AdapterBuildError(String message) {
        super(message);
    }

    /**
     * The missing handlers, by their Rust names ({@code get_url}, {@code drop},
     * ...).
     */
    public List<String> missing() {
        String message = getMessage();
        if (!message.startsWith(PREFIX)) {
            return List.of();
        }
        return Arrays.asList(message.substring(PREFIX.length()).split(", "));
    }
}
