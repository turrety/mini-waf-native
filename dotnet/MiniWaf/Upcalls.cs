using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;

namespace MurylloEx.MiniWaf;

/// <summary>
/// The callbacks the library makes while evaluating, and the per-thread
/// frames they read their .NET target from.
/// </summary>
/// <remarks>
/// Evaluation is synchronous: the library calls back on the thread that
/// called <c>Handle</c> / <c>Protect</c>, before it returns. So the target
/// travels in a thread-static frame, not through the native pointers. An
/// exception thrown by .NET code is parked in the frame (it must not unwind
/// through native code) and rethrown once the native call returns.
/// </remarks>
internal static unsafe class Upcalls
{
    /// <summary>One native call in progress on this thread.</summary>
    internal sealed class Frame(object? target, NativeResource? owner = null)
    {
        public object? Target { get; } = target;

        /// <summary>
        /// The instance evaluating, which lends the rules it reports.
        /// </summary>
        public NativeResource? Owner { get; } = owner;

        public ExceptionDispatchInfo? Error { get; set; }
    }

    [ThreadStatic]
    private static Stack<Frame>? frames;

    private static Stack<Frame> Frames => frames ??= new Stack<Frame>();

    /// <summary>
    /// Run <paramref name="body"/> inside <paramref name="frame"/>, rethrowing
    /// what its callbacks threw.
    /// </summary>
    public static T Within<T>(Frame frame, Func<T> body)
    {
        Frames.Push(frame);
        T result;
        try
        {
            result = body();
        }
        finally
        {
            Frames.Pop();
        }
        frame.Error?.Throw();
        return result;
    }

    /// <summary>
    /// Run <paramref name="body"/> in a frame of its own, for predicates it may
    /// call.
    /// </summary>
    public static T Guarded<T>(Func<T> body) => Within(new Frame(null), body);

    /// <summary>
    /// Record <paramref name="error"/> in the innermost frame (the first error
    /// wins).
    /// </summary>
    public static void Fail(Exception error)
    {
        if (Frames.TryPeek(out Frame? frame) && frame.Error is null)
        {
            frame.Error = ExceptionDispatchInfo.Capture(error);
        }
    }

    /// <summary>
    /// A view of <paramref name="rule"/>, lent by the instance evaluating.
    /// </summary>
    public static WafRule Rule(nint rule) =>
        WafRule.View(rule, Frames.Peek().Owner!);

    /// <summary>
    /// The innermost frame's target, or null once a callback in it has failed.
    /// </summary>
    private static T? Live<T>()
        where T : class =>
        Frames.TryPeek(out Frame? frame) && frame.Error is null
            ? frame.Target as T
            : null;

    private static void Call<T>(Action<T> body)
        where T : class
    {
        if (Live<T>() is { } target)
        {
            try
            {
                body(target);
            }
            catch (Exception error)
            {
                Fail(error);
            }
        }
    }

    private static TResult Call<T, TResult>(
        Func<T, TResult> body,
        TResult fallback
    )
        where T : class
    {
        if (Live<T>() is { } target)
        {
            try
            {
                return body(target);
            }
            catch (Exception error)
            {
                Fail(error);
            }
        }
        return fallback;
    }

    private static string Read(nint data, nuint length) =>
        Text.Read(data, length) ?? "";

    /// <summary>
    /// A <c>WafHttpContext</c> struct: <c>self</c> (unused) then the
    /// callbacks, in the order of the C struct. Shared by every call.
    /// </summary>
    public static readonly nint ContextTable = CreateContextTable();

    private static nint CreateContextTable()
    {
        nint[] table =
        [
            0,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&Framework,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&ContextMethod,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&ContextUrl,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&ContextPath,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&ContextIp,
            (nint)
                (delegate* unmanaged[Cdecl]<nint, nint, void>)&ContextProtocol,
            (nint)(delegate* unmanaged[Cdecl]<nint, ushort>)&ContextLocalPort,
            (nint)
                (delegate* unmanaged[Cdecl]<nint, nint, nuint, nint, byte>)
                    &ContextHeader,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&ContextHeaders,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&ContextQuery,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&ContextCookies,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&ContextRawBody,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&ContextFiles,
            (nint)
                (delegate* unmanaged[Cdecl]<
                    nint,
                    nint,
                    nuint,
                    nint,
                    nuint,
                    void>)
                    &ContextSetResponseHeader,
            (nint)
                (delegate* unmanaged[Cdecl]<nint, nint, nuint, void>)
                    &ContextRemoveResponseHeader,
            (nint)(delegate* unmanaged[Cdecl]<nint, byte>)&ContextIsBlocked,
            (nint)
                (delegate* unmanaged[Cdecl]<nint, nint, nint, nuint, void>)
                    &ContextDrop,
        ];
        nint block = (nint)
            NativeMemory.Alloc((nuint)(table.Length * sizeof(nint)));
        table.CopyTo(new Span<nint>((void*)block, table.Length));
        return block;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void Framework(nint self, nint @out) =>
        Call<WafHttpContext>(ctx => Fill.String(@out, ctx.Framework()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void ContextMethod(nint self, nint @out) =>
        Call<WafHttpContext>(ctx => Fill.String(@out, ctx.GetMethod()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void ContextUrl(nint self, nint @out) =>
        Call<WafHttpContext>(ctx => Fill.String(@out, ctx.GetUrl()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void ContextPath(nint self, nint @out) =>
        Call<WafHttpContext>(ctx => Fill.String(@out, ctx.GetPath()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void ContextIp(nint self, nint @out) =>
        Call<WafHttpContext>(ctx => Fill.String(@out, ctx.GetIp()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void ContextProtocol(nint self, nint @out) =>
        Call<WafHttpContext>(ctx => Fill.String(@out, ctx.GetProtocol()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static ushort ContextLocalPort(nint self) =>
        Call<WafHttpContext, ushort>(ctx => ctx.GetLocalPort(), 0);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static byte ContextHeader(
        nint self,
        nint name,
        nuint nameLen,
        nint @out
    ) =>
        Call<WafHttpContext, byte>(
            ctx => Header(@out, ctx.GetHeader(Read(name, nameLen))),
            0
        );

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void ContextHeaders(nint self, nint @out) =>
        Call<WafHttpContext>(ctx => Fill.Headers(@out, ctx.GetHeaders()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void ContextQuery(nint self, nint @out) =>
        Call<WafHttpContext>(ctx => Fill.Query(@out, ctx.GetQuery()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void ContextCookies(nint self, nint @out) =>
        Call<WafHttpContext>(ctx => Fill.Cookies(@out, ctx.GetCookies()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void ContextRawBody(nint self, nint @out) =>
        Call<WafHttpContext>(ctx => Fill.String(@out, ctx.GetRawBody()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void ContextFiles(nint self, nint @out) =>
        Call<WafHttpContext>(ctx =>
            Fill.Files(@out, new FilesBag.List(ctx.GetFiles()))
        );

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void ContextSetResponseHeader(
        nint self,
        nint name,
        nuint nameLen,
        nint value,
        nuint valueLen
    ) =>
        Call<WafHttpContext>(ctx =>
            ctx.SetResponseHeader(Read(name, nameLen), Read(value, valueLen))
        );

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void ContextRemoveResponseHeader(
        nint self,
        nint name,
        nuint nameLen
    ) =>
        Call<WafHttpContext>(ctx =>
            ctx.RemoveResponseHeader(Read(name, nameLen))
        );

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static byte ContextIsBlocked(nint self) =>
        Call<WafHttpContext, byte>(
            ctx => ctx.IsBlocked() ? (byte)1 : (byte)0,
            0
        );

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void ContextDrop(
        nint self,
        nint statusCode,
        nint body,
        nuint bodyLen
    ) =>
        Call<WafHttpContext>(ctx =>
            ctx.Drop(
                statusCode == 0 ? null : *(ushort*)statusCode,
                Text.Read(body, bodyLen)
            )
        );

    /// <summary>
    /// Write a found header and report whether there was one.
    /// </summary>
    private static byte Header(nint @out, string? value)
    {
        if (value is null)
        {
            return 0;
        }
        Fill.String(@out, value);
        return 1;
    }

    /// <summary>
    /// Register on the native <c>CustomAdapterHandlers</c> the callback of
    /// every handler <paramref name="has"/> reports as set.
    /// </summary>
    public static void Register(nint handlers, Func<Handler, bool> has)
    {
        void Set(bool present, Action<nint, nint> setter, nint callback)
        {
            if (present)
            {
                setter(handlers, callback);
            }
        }

        Set(
            has(Handler.GetMethod),
            Api.CustomAdapterHandlersGetMethod,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&AdapterMethod
        );
        Set(
            has(Handler.GetUrl),
            Api.CustomAdapterHandlersGetUrl,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&AdapterUrl
        );
        Set(
            has(Handler.GetPath),
            Api.CustomAdapterHandlersGetPath,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&AdapterPath
        );
        Set(
            has(Handler.GetIp),
            Api.CustomAdapterHandlersGetIp,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&AdapterIp
        );
        Set(
            has(Handler.GetProtocol),
            Api.CustomAdapterHandlersGetProtocol,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&AdapterProtocol
        );
        Set(
            has(Handler.GetLocalPort),
            Api.CustomAdapterHandlersGetLocalPort,
            (nint)
                (delegate* unmanaged[Cdecl]<nint, nint, ushort>)
                    &AdapterLocalPort
        );
        Set(
            has(Handler.GetHeader),
            Api.CustomAdapterHandlersGetHeader,
            (nint)
                (delegate* unmanaged[Cdecl]<nint, nint, nuint, nint, byte>)
                    &AdapterHeader
        );
        Set(
            has(Handler.GetHeaders),
            Api.CustomAdapterHandlersGetHeaders,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&AdapterHeaders
        );
        Set(
            has(Handler.GetQuery),
            Api.CustomAdapterHandlersGetQuery,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&AdapterQuery
        );
        Set(
            has(Handler.GetCookies),
            Api.CustomAdapterHandlersGetCookies,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&AdapterCookies
        );
        Set(
            has(Handler.GetRawBody),
            Api.CustomAdapterHandlersGetRawBody,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&AdapterRawBody
        );
        Set(
            has(Handler.GetFiles),
            Api.CustomAdapterHandlersGetFiles,
            (nint)(delegate* unmanaged[Cdecl]<nint, nint, void>)&AdapterFiles
        );
        Set(
            has(Handler.SetResponseHeader),
            Api.CustomAdapterHandlersSetResponseHeader,
            (nint)
                (delegate* unmanaged[Cdecl]<
                    nint,
                    nint,
                    nuint,
                    nint,
                    nuint,
                    void>)
                    &AdapterSetResponseHeader
        );
        Set(
            has(Handler.RemoveResponseHeader),
            Api.CustomAdapterHandlersRemoveResponseHeader,
            (nint)
                (delegate* unmanaged[Cdecl]<nint, nint, nuint, void>)
                    &AdapterRemoveResponseHeader
        );
        Set(
            has(Handler.Drop),
            Api.CustomAdapterHandlersDrop,
            (nint)
                (delegate* unmanaged[Cdecl]<
                    nint,
                    nint,
                    ushort,
                    nint,
                    nuint,
                    void>)
                    &AdapterDrop
        );
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void AdapterMethod(nint request, nint @out) =>
        Call<AdapterCall>(call => Fill.String(@out, call.GetMethod()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void AdapterUrl(nint request, nint @out) =>
        Call<AdapterCall>(call => Fill.String(@out, call.GetUrl()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void AdapterPath(nint request, nint @out) =>
        Call<AdapterCall>(call => Fill.String(@out, call.GetPath()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void AdapterIp(nint request, nint @out) =>
        Call<AdapterCall>(call => Fill.String(@out, call.GetIp()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void AdapterProtocol(nint request, nint @out) =>
        Call<AdapterCall>(call => Fill.String(@out, call.GetProtocol()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static ushort AdapterLocalPort(nint request, nint response) =>
        Call<AdapterCall, ushort>(call => call.GetLocalPort(), 0);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static byte AdapterHeader(
        nint request,
        nint name,
        nuint nameLen,
        nint @out
    ) =>
        Call<AdapterCall, byte>(
            call => Header(@out, call.GetHeader(Read(name, nameLen))),
            0
        );

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void AdapterHeaders(nint request, nint @out) =>
        Call<AdapterCall>(call => Fill.Headers(@out, call.GetHeaders()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void AdapterQuery(nint request, nint @out) =>
        Call<AdapterCall>(call => Fill.Query(@out, call.GetQuery()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void AdapterCookies(nint request, nint @out) =>
        Call<AdapterCall>(call => Fill.Cookies(@out, call.GetCookies()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void AdapterRawBody(nint request, nint @out) =>
        Call<AdapterCall>(call => Fill.Body(@out, call.GetRawBody()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void AdapterFiles(nint request, nint @out) =>
        Call<AdapterCall>(call => Fill.Files(@out, call.GetFiles()));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void AdapterSetResponseHeader(
        nint response,
        nint name,
        nuint nameLen,
        nint value,
        nuint valueLen
    ) =>
        Call<AdapterCall>(call =>
            call.SetResponseHeader(Read(name, nameLen), Read(value, valueLen))
        );

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void AdapterRemoveResponseHeader(
        nint response,
        nint name,
        nuint nameLen
    ) =>
        Call<AdapterCall>(call =>
            call.RemoveResponseHeader(Read(name, nameLen))
        );

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void AdapterDrop(
        nint request,
        nint response,
        ushort statusCode,
        nint body,
        nuint bodyLen
    ) => Call<AdapterCall>(call => call.Drop(statusCode, Read(body, bodyLen)));
}

/// <summary>
/// The handlers of <see cref="CustomAdapterHandlers{TRequest, TResponse}"/>.
/// </summary>
internal enum Handler
{
    GetMethod,
    GetUrl,
    GetPath,
    GetIp,
    GetProtocol,
    GetLocalPort,
    GetHeader,
    GetHeaders,
    GetQuery,
    GetCookies,
    GetRawBody,
    GetFiles,
    SetResponseHeader,
    RemoveResponseHeader,
    Drop,
}

/// <summary>
/// The handlers of an adapter bound to one request / response pair, without
/// their type parameters, so the static callbacks can reach them.
/// </summary>
internal abstract class AdapterCall
{
    public abstract string GetMethod();
    public abstract string GetUrl();
    public abstract string GetPath();
    public abstract string GetIp();
    public abstract string GetProtocol();
    public abstract ushort GetLocalPort();
    public abstract string? GetHeader(string name);
    public abstract HeaderMap GetHeaders();
    public abstract QueryMap GetQuery();
    public abstract CookieMap GetCookies();
    public abstract RawBody GetRawBody();
    public abstract FilesBag GetFiles();
    public abstract void SetResponseHeader(string name, string value);
    public abstract void RemoveResponseHeader(string name);
    public abstract void Drop(ushort statusCode, string body);
}
