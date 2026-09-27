using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace MurylloEx.MiniWaf;

internal static partial class Api
{
    /// <summary>
    /// Look the library up in the directory named by the
    /// <c>MINI_WAF_LIBRARY_PATH</c> environment variable first, then with
    /// the default probing (application directory, <c>LD_LIBRARY_PATH</c>,
    /// <c>PATH</c>, ...).
    /// </summary>
    static Api()
    {
        NativeLibrary.SetDllImportResolver(typeof(Api).Assembly, Resolve);
    }

    private static nint Resolve(
        string name,
        Assembly assembly,
        DllImportSearchPath? searchPath
    )
    {
        string? directory = Environment.GetEnvironmentVariable(
            "MINI_WAF_LIBRARY_PATH"
        );
        if (name != Library || string.IsNullOrEmpty(directory))
        {
            return 0;
        }
        string file =
            OperatingSystem.IsWindows() ? "mini_waf.dll"
            : OperatingSystem.IsMacOS() ? "libmini_waf.dylib"
            : "libmini_waf.so";
        string path = Path.Combine(directory, file);
        return File.Exists(path) ? NativeLibrary.Load(path) : 0;
    }
}

/// <summary><c>MiniWafStr</c>: borrowed text.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct MiniWafStr
{
    public nint Data;
    public nuint Len;
}

[StructLayout(LayoutKind.Sequential)]
internal struct RateLimitSpecNative
{
    public ulong Max;
    public ulong WindowMs;
    public MiniWafStr KeyPrefix;
}

[StructLayout(LayoutKind.Sequential)]
internal struct DecisionCacheConfigNative
{
    public nint Max;
    public nint TtlMs;
}

[StructLayout(LayoutKind.Sequential)]
internal struct DecodeConfigNative
{
    public nint Base64;
    public nint Url;
    public nint Comments;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WafLoggingOptionsNative
{
    public nint Level;
}

/// <summary><c>WafLogger</c>: the callbacks of a logger sink.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct WafLoggerNative
{
    public nint UserData;
    public nint Blocked;
    public nint Audit;
    public nint Connection;
    public nint Drop;
}

[StructLayout(LayoutKind.Sequential)]
internal struct RateLimitStoreOptionsNative
{
    public nint MaxKeys;
    public nint IdleMs;
    public nint PruneEveryHits;
}

[StructLayout(LayoutKind.Sequential)]
internal struct UploadedFileNative
{
    public MiniWafStr Fieldname;
    public MiniWafStr Name;
    public MiniWafStr Filename;
    public MiniWafStr Originalname;
}

/// <summary>
/// Unmanaged memory for the arguments of one native call, freed together
/// on dispose (like a Java <c>Arena</c>).
/// </summary>
internal sealed unsafe class Arena : IDisposable
{
    private readonly List<nint> blocks = [];

    public nint Allocate(nuint size)
    {
        nint block = (nint)NativeMemory.AllocZeroed(Math.Max(size, 1));
        blocks.Add(block);
        return block;
    }

    /// <summary>
    /// NUL-terminated UTF-8 of <paramref name="text"/>; never <c>NULL</c>.
    /// </summary>
    public nint Text(string text, out nuint length)
    {
        int count = Encoding.UTF8.GetByteCount(text);
        nint block = Allocate((nuint)count + 1);
        Encoding.UTF8.GetBytes(text, new Span<byte>((void*)block, count));
        length = (nuint)count;
        return block;
    }

    public MiniWafStr Str(string? text)
    {
        if (text is null)
        {
            return default;
        }
        nint data = Text(text, out nuint length);
        return new MiniWafStr { Data = data, Len = length };
    }

    public nint Strs(IReadOnlyList<string> values)
    {
        nint array = Allocate((nuint)(values.Count * sizeof(MiniWafStr)));
        for (int index = 0; index < values.Count; index++)
        {
            ((MiniWafStr*)array)[index] = Str(values[index]);
        }
        return array;
    }

    public nint Value<T>(T value)
        where T : unmanaged
    {
        nint block = Allocate((nuint)sizeof(T));
        *(T*)block = value;
        return block;
    }

    public nint Optional<T>(T? value)
        where T : unmanaged => value is { } present ? Value(present) : 0;

    public nint Pointers(IReadOnlyList<nint> pointers)
    {
        nint array = Allocate((nuint)(pointers.Count * sizeof(nint)));
        for (int index = 0; index < pointers.Count; index++)
        {
            ((nint*)array)[index] = pointers[index];
        }
        return array;
    }

    public void Dispose()
    {
        foreach (nint block in blocks)
        {
            NativeMemory.Free((void*)block);
        }
        blocks.Clear();
    }
}

internal static unsafe class Text
{
    /// <summary>
    /// UTF-8 at <paramref name="data"/>; null for <c>NULL</c>.
    /// </summary>
    public static string? Read(nint data, nuint length) =>
        data == 0
            ? null
            : Encoding.UTF8.GetString((byte*)data, checked((int)length));

    /// <summary>A string the library allocated, freed after reading.</summary>
    public static string? Take(nint owned)
    {
        if (owned == 0)
        {
            return null;
        }
        try
        {
            return Marshal.PtrToStringUTF8(owned);
        }
        finally
        {
            Api.StringFree(owned);
        }
    }

    /// <summary>
    /// Call a getter lending text with a length out-parameter.
    /// </summary>
    public static string? Lent(Func<nint, nint> getter)
    {
        nuint length = 0;
        nint data = getter((nint)(&length));
        return Read(data, length);
    }
}
