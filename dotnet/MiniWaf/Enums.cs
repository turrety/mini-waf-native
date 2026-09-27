namespace MurylloEx.MiniWaf;

/// <summary>
/// Protection levels control which rules are active: a rule runs when the
/// configured level is at least its <c>MinLevel</c>
/// (<c>Low &lt; Balanced &lt; High &lt; Paranoid</c>).
/// </summary>
public enum ProtectionLevel
{
    /// <summary>High signal, low false positives.</summary>
    Low,

    /// <summary>The default.</summary>
    Balanced,

    /// <summary>Aggressive heuristics and the transport decoders.</summary>
    High,

    /// <summary>Legacy rules with elevated false positives.</summary>
    Paranoid,
}

/// <summary>What a matching rule does.</summary>
public enum WafAction
{
    /// <summary>Stop evaluating and let the request through.</summary>
    Allow,

    /// <summary>Reject the request (the first matching block wins).</summary>
    Block,

    /// <summary>Record the match and keep evaluating.</summary>
    Log,
}

/// <summary>Built-in rule packs.</summary>
public enum WafPresetName
{
    /// <summary>Every pack below, in one list.</summary>
    Default,
    Sqli,
    Xss,
    Scanners,
    PathTraversal,
    Rfi,
    Rce,
    Protocol,
}

/// <summary>Final verdict for a request.</summary>
public enum WafDecision
{
    Allow,
    Block,
}

/// <summary>
/// Verbosity when logging is enabled: <c>Error</c> = blocks only,
/// <c>Info</c> = blocks + audit, <c>Debug</c> = + connections.
/// </summary>
public enum WafLogLevel
{
    Error,
    Info,
    Debug,
}
