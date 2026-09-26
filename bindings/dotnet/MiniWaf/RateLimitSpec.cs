namespace MurylloEx.MiniWaf;

/// <summary>Sliding-window rate limit of a field condition.</summary>
/// <param name="max">
/// Maximum hits inside the window before the condition matches.
/// </param>
/// <param name="windowMs">Sliding window length in milliseconds.</param>
public sealed class RateLimitSpec(ulong max, ulong windowMs)
{
    private string? keyPrefix;

    public ulong Max() => max;

    public ulong WindowMs() => windowMs;

    public string? KeyPrefix() => keyPrefix;

    /// <summary>
    /// Key override. Defaults to the resolved field value (the IP for
    /// <c>Ip</c>).
    /// </summary>
    public RateLimitSpec KeyPrefix(string prefix)
    {
        keyPrefix = prefix;
        return this;
    }
}
