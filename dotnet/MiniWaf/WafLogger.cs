namespace MurylloEx.MiniWaf;

/// <summary>
/// Receives log events while <c>WafConfig.Logging</c> is on, filtered by its
/// level (<c>Error</c>: blocked; <c>Info</c>: + audit; <c>Debug</c>: +
/// connection).
/// </summary>
/// <remarks>
/// Called on the evaluating thread, possibly from several at once, before
/// <c>Handle</c> / <c>Protect</c> returns; an exception it throws comes out
/// of that call. <c>ctx</c> is read-only and, like <c>rule</c>, valid only
/// during the call.
/// </remarks>
public interface WafLogger
{
    void Blocked(WafHttpContext ctx, WafRule rule);

    void Audit(WafHttpContext ctx, WafRule rule);

    void Connection(WafHttpContext ctx);
}
