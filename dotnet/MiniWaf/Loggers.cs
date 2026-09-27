using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace MurylloEx.MiniWaf;

/// <summary>
/// The .NET loggers behind <see cref="WafEngineOptions.Logger"/>: the
/// library holds an id as <c>user_data</c> and calls back with it.
/// </summary>
internal static unsafe class Loggers
{
    private static readonly ConcurrentDictionary<nint, WafLogger> Registry =
        new();
    private static long nextId;

    /// <summary>
    /// A native <c>WafLogger</c> over <paramref name="logger"/>.
    /// </summary>
    public static WafLoggerNative Register(WafLogger logger)
    {
        nint id = (nint)Interlocked.Increment(ref nextId);
        Registry[id] = logger;
        return new WafLoggerNative
        {
            UserData = id,
            Blocked = (nint)
                (delegate* unmanaged[Cdecl]<nint, nint, nint, void>)&OnBlocked,
            Audit = (nint)
                (delegate* unmanaged[Cdecl]<nint, nint, nint, void>)&OnAudit,
            Connection = (nint)
                (delegate* unmanaged[Cdecl]<nint, nint, void>)&OnConnection,
            Drop = (nint)(delegate* unmanaged[Cdecl]<nint, void>)&OnDrop,
        };
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnBlocked(nint userData, nint ctx, nint rule) =>
        Event(
            userData,
            logger => logger.Blocked(new ContextRef(ctx), Upcalls.Rule(rule))
        );

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnAudit(nint userData, nint ctx, nint rule) =>
        Event(
            userData,
            logger => logger.Audit(new ContextRef(ctx), Upcalls.Rule(rule))
        );

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnConnection(nint userData, nint ctx) =>
        Event(userData, logger => logger.Connection(new ContextRef(ctx)));

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnDrop(nint userData) =>
        Registry.TryRemove(userData, out _);

    private static void Event(nint userData, Action<WafLogger> body)
    {
        if (!Registry.TryGetValue(userData, out WafLogger? logger))
        {
            return;
        }
        try
        {
            body(logger);
        }
        catch (Exception error)
        {
            Upcalls.Fail(error);
        }
    }
}
