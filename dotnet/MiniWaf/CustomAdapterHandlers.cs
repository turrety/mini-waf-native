namespace MurylloEx.MiniWaf;

/// <summary>
/// The request / response mappers
/// <see cref="MiniWaf.CreateAdapter{TRequest, TResponse}"/> turns into an
/// adapter. Each setter is named after the handler it sets.
/// </summary>
/// <remarks>
/// Required: <c>GetMethod</c>, <c>GetUrl</c>, <c>GetIp</c>,
/// <c>GetHeaders</c>, <c>GetRawBody</c>, <c>SetResponseHeader</c> and
/// <c>Drop</c>. The others default as in Rust: the path is the URL up to
/// <c>?</c>, the protocol <c>"http"</c>, the port 0, a header is looked up
/// in <c>GetHeaders</c>, the query is parsed from the URL, cookies from the
/// <c>Cookie</c> header, no files, and removing a header does nothing.
/// </remarks>
/// <param name="name">Name of the integration, shown in logs.</param>
public sealed class CustomAdapterHandlers<TRequest, TResponse>(string name)
{
    internal string Name { get; } = name;
    internal Func<TRequest, string>? getMethod;
    internal Func<TRequest, string>? getUrl;
    internal Func<TRequest, string>? getPath;
    internal Func<TRequest, string>? getIp;
    internal Func<TRequest, string>? getProtocol;
    internal Func<TRequest, TResponse, ushort>? getLocalPort;
    internal Func<TRequest, string, string?>? getHeader;
    internal Func<TRequest, HeaderMap>? getHeaders;
    internal Func<TRequest, QueryMap>? getQuery;
    internal Func<TRequest, CookieMap>? getCookies;
    internal Func<TRequest, RawBody>? getRawBody;
    internal Func<TRequest, FilesBag>? getFiles;
    internal Action<TResponse, string, string>? setResponseHeader;
    internal Action<TResponse, string>? removeResponseHeader;
    internal Action<TRequest, TResponse, ushort, string>? drop;

    /// <summary>HTTP method.</summary>
    public CustomAdapterHandlers<TRequest, TResponse> GetMethod(
        Func<TRequest, string> handler
    )
    {
        getMethod = handler;
        return this;
    }

    /// <summary>
    /// Full request target including the query string (<c>/a/b?x=1</c>).
    /// </summary>
    public CustomAdapterHandlers<TRequest, TResponse> GetUrl(
        Func<TRequest, string> handler
    )
    {
        getUrl = handler;
        return this;
    }

    /// <summary>
    /// Path as it arrived on the wire (still percent-encoded).
    /// </summary>
    public CustomAdapterHandlers<TRequest, TResponse> GetPath(
        Func<TRequest, string> handler
    )
    {
        getPath = handler;
        return this;
    }

    /// <summary>
    /// Raw client address; it is normalized for you. Behind a proxy, derive
    /// it from <c>X-Forwarded-For</c> with
    /// <see cref="MiniWaf.PickClientIpFromXff"/>.
    /// </summary>
    public CustomAdapterHandlers<TRequest, TResponse> GetIp(
        Func<TRequest, string> handler
    )
    {
        getIp = handler;
        return this;
    }

    /// <summary><c>http</c> / <c>https</c>.</summary>
    public CustomAdapterHandlers<TRequest, TResponse> GetProtocol(
        Func<TRequest, string> handler
    )
    {
        getProtocol = handler;
        return this;
    }

    /// <summary>Port the server accepted the connection on.</summary>
    public CustomAdapterHandlers<TRequest, TResponse> GetLocalPort(
        Func<TRequest, TResponse, ushort> handler
    )
    {
        getLocalPort = handler;
        return this;
    }

    /// <summary>One header by lowercase name.</summary>
    public CustomAdapterHandlers<TRequest, TResponse> GetHeader(
        Func<TRequest, string, string?> handler
    )
    {
        getHeader = handler;
        return this;
    }

    /// <summary>Every header. Lowercase the names.</summary>
    public CustomAdapterHandlers<TRequest, TResponse> GetHeaders(
        Func<TRequest, HeaderMap> handler
    )
    {
        getHeaders = handler;
        return this;
    }

    /// <summary>
    /// Parsed query parameters, when the framework already parses them.
    /// </summary>
    public CustomAdapterHandlers<TRequest, TResponse> GetQuery(
        Func<TRequest, QueryMap> handler
    )
    {
        getQuery = handler;
        return this;
    }

    /// <summary>
    /// Parsed cookies, when the framework already parses them.
    /// </summary>
    public CustomAdapterHandlers<TRequest, TResponse> GetCookies(
        Func<TRequest, CookieMap> handler
    )
    {
        getCookies = handler;
        return this;
    }

    /// <summary>The buffered request body.</summary>
    public CustomAdapterHandlers<TRequest, TResponse> GetRawBody(
        Func<TRequest, RawBody> handler
    )
    {
        getRawBody = handler;
        return this;
    }

    /// <summary>Uploaded files (only their names are inspected).</summary>
    public CustomAdapterHandlers<TRequest, TResponse> GetFiles(
        Func<TRequest, FilesBag> handler
    )
    {
        getFiles = handler;
        return this;
    }

    /// <summary>
    /// Set a response header (used for <c>X-RateLimit-*</c>).
    /// </summary>
    public CustomAdapterHandlers<TRequest, TResponse> SetResponseHeader(
        Action<TResponse, string, string> handler
    )
    {
        setResponseHeader = handler;
        return this;
    }

    /// <summary>Remove a response header.</summary>
    public CustomAdapterHandlers<TRequest, TResponse> RemoveResponseHeader(
        Action<TResponse, string> handler
    )
    {
        removeResponseHeader = handler;
        return this;
    }

    /// <summary>End the request with a block response.</summary>
    public CustomAdapterHandlers<TRequest, TResponse> Drop(
        Action<TRequest, TResponse, ushort, string> handler
    )
    {
        drop = handler;
        return this;
    }
}
