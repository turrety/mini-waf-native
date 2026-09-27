package io.github.murylloex.miniwaf;

/** Built-in rule packs. */
public enum WafPresetName {
    /** Every pack below, in one list. */
    DEFAULT,
    SQLI,
    XSS,
    SCANNERS,
    PATH_TRAVERSAL,
    RFI,
    RCE,
    PROTOCOL;

    /** The preset's name in rule files and logs ({@code "path-traversal"}). */
    public String asStr() {
        return name().toLowerCase(java.util.Locale.ROOT).replace('_', '-');
    }
}
