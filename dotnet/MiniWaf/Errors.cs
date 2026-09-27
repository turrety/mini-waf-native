namespace MurylloEx.MiniWaf;

/// <summary>An invalid rule regex (<see cref="MatchPattern.Regex"/>).</summary>
public sealed class RegexError(string message) : Exception(message);

/// <summary>
/// An unsupported field path (<see cref="WafField.FromStr"/>).
/// </summary>
public sealed class InvalidField(string message) : Exception(message);

/// <summary>
/// A malformed JSON rules document (<see cref="MiniWaf.ParseRulesFromJson"/>);
/// the message starts with the offending path, such as <c>rules[2].when</c>.
/// </summary>
public sealed class RuleParseError(string message) : Exception(message);

/// <summary>
/// Thrown by <see cref="MiniWaf.CreateAdapter{TRequest, TResponse}"/> when
/// required handlers are missing.
/// </summary>
public sealed class AdapterBuildError(string message) : Exception(message)
{
    private const string Prefix = "adapter is missing required handlers: ";

    /// <summary>
    /// The missing handlers, by their Rust names (<c>get_url</c>, <c>drop</c>,
    /// ...).
    /// </summary>
    public IReadOnlyList<string> Missing =>
        Message.StartsWith(Prefix, StringComparison.Ordinal)
            ? Message[Prefix.Length..].Split(", ")
            : [];
}
