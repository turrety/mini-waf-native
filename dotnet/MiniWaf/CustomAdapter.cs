namespace MurylloEx.MiniWaf;

/// <summary>
/// The adapter <see cref="MiniWaf.CreateAdapter{TRequest, TResponse}"/>
/// builds. It is thread-safe when its handlers are.
/// </summary>
public sealed class CustomAdapter<TRequest, TResponse> : NativeResource
{
    internal CustomAdapterHandlers<TRequest, TResponse> Handlers { get; }

    internal CustomAdapter(CustomAdapterHandlers<TRequest, TResponse> handlers)
        : base(Create(handlers), Api.CustomAdapterFree)
    {
        Handlers = handlers;
    }

    public string Name() => Handlers.Name;

    private static unsafe nint Create(
        CustomAdapterHandlers<TRequest, TResponse> handlers
    )
    {
        using Arena arena = new();
        nint name = arena.Text(handlers.Name, out nuint length);
        nint nativeHandlers = Api.CustomAdapterHandlersNew(name, length);
        try
        {
            Upcalls.Register(
                nativeHandlers,
                handler => IsSet(handlers, handler)
            );
            nint error = 0;
            nint adapter = Api.CreateAdapter(nativeHandlers, (nint)(&error));
            return adapter == 0
                ? throw new AdapterBuildError(
                    Text.Take(error) ?? "invalid adapter"
                )
                : adapter;
        }
        finally
        {
            Api.CustomAdapterHandlersFree(nativeHandlers);
        }
    }

    private static bool IsSet(
        CustomAdapterHandlers<TRequest, TResponse> h,
        Handler handler
    ) =>
        handler switch
        {
            Handler.GetMethod => h.getMethod is not null,
            Handler.GetUrl => h.getUrl is not null,
            Handler.GetPath => h.getPath is not null,
            Handler.GetIp => h.getIp is not null,
            Handler.GetProtocol => h.getProtocol is not null,
            Handler.GetLocalPort => h.getLocalPort is not null,
            Handler.GetHeader => h.getHeader is not null,
            Handler.GetHeaders => h.getHeaders is not null,
            Handler.GetQuery => h.getQuery is not null,
            Handler.GetCookies => h.getCookies is not null,
            Handler.GetRawBody => h.getRawBody is not null,
            Handler.GetFiles => h.getFiles is not null,
            Handler.SetResponseHeader => h.setResponseHeader is not null,
            Handler.RemoveResponseHeader => h.removeResponseHeader is not null,
            _ => h.drop is not null,
        };

    /// <summary>The handlers bound to one request / response pair.</summary>
    internal AdapterCall Bind(TRequest request, TResponse response) =>
        new Call(Handlers, request, response);

    /// <remarks>
    /// The library only calls the handlers that were registered, so the
    /// null-forgiving operators never see a null delegate.
    /// </remarks>
    private sealed class Call(
        CustomAdapterHandlers<TRequest, TResponse> handlers,
        TRequest request,
        TResponse response
    ) : AdapterCall
    {
        public override string GetMethod() => handlers.getMethod!(request);

        public override string GetUrl() => handlers.getUrl!(request);

        public override string GetPath() => handlers.getPath!(request);

        public override string GetIp() => handlers.getIp!(request);

        public override string GetProtocol() => handlers.getProtocol!(request);

        public override ushort GetLocalPort() =>
            handlers.getLocalPort!(request, response);

        public override string? GetHeader(string name) =>
            handlers.getHeader!(request, name);

        public override HeaderMap GetHeaders() => handlers.getHeaders!(request);

        public override QueryMap GetQuery() => handlers.getQuery!(request);

        public override CookieMap GetCookies() => handlers.getCookies!(request);

        public override RawBody GetRawBody() => handlers.getRawBody!(request);

        public override FilesBag GetFiles() => handlers.getFiles!(request);

        public override void SetResponseHeader(string name, string value) =>
            handlers.setResponseHeader!(response, name, value);

        public override void RemoveResponseHeader(string name) =>
            handlers.removeResponseHeader!(response, name);

        public override void Drop(ushort statusCode, string body) =>
            handlers.drop!(request, response, statusCode, body);
    }
}
