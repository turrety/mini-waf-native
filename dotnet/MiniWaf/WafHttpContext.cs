namespace MurylloEx.MiniWaf;

/// <summary>
/// Framework-agnostic HTTP view consumed by the WAF engine
/// (<see cref="MiniWafInstance.Handle"/>).
/// </summary>
/// <remarks>
/// The engine resolves every rule field exclusively through these methods,
/// so an implementation returning the wrong value for <see cref="GetIp"/>
/// silently breaks every <c>ip</c> rule and rate-limit bucket. Most
/// applications use <see cref="MiniWaf.CreateAdapter{TRequest, TResponse}"/>
/// instead.
/// </remarks>
public interface WafHttpContext
{
    /// <summary>Name of the integration, for logs.</summary>
    string Framework();

    string GetMethod();

    /// <summary>Full request target, including the query string.</summary>
    string GetUrl();

    /// <summary>
    /// Path without the query string, as it arrived on the wire (still
    /// percent-encoded).
    /// </summary>
    string GetPath();

    /// <summary>
    /// Normalized client IP (see <see cref="MiniWaf.NormalizeClientIp"/>).
    /// </summary>
    string GetIp();

    string GetProtocol();

    ushort GetLocalPort();

    /// <summary>One header by (lowercase) name.</summary>
    string? GetHeader(string name);

    HeaderMap GetHeaders();

    QueryMap GetQuery();

    CookieMap GetCookies();

    string GetRawBody();

    IReadOnlyList<UploadedFile> GetFiles();

    void SetResponseHeader(string name, string value);

    void RemoveResponseHeader(string name);

    bool IsBlocked();

    /// <summary>
    /// Ends the request with a block response. Defaults: status 403, body
    /// "Forbidden".
    /// </summary>
    void Drop(ushort? statusCode, string? body);
}
