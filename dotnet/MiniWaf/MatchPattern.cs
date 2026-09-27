using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace MurylloEx.MiniWaf;

/// <summary>
/// Match target of <see cref="FieldCondition.Matches"/>: literal, regex,
/// string list, or predicate.
/// </summary>
public sealed class MatchPattern : NativeResource
{
    private MatchPattern(nint handle)
        : base(handle, Api.MatchPatternFree) { }

    /// <summary>Compile a regex pattern with no flags.</summary>
    public static MatchPattern Regex(string pattern) =>
        RegexWithFlags(pattern, "");

    /// <summary>
    /// Compile a regex pattern with JavaScript-style flags (<c>"i"</c>,
    /// <c>"im"</c>, ...). The dialect is linear-time: no look-around, no
    /// backreferences.
    /// </summary>
    public static unsafe MatchPattern RegexWithFlags(
        string pattern,
        string flags
    )
    {
        using Arena arena = new();
        nint text = arena.Text(pattern, out nuint length);
        nint flagText = arena.Text(flags, out nuint flagsLength);
        nint error = 0;
        nint handle = Api.MatchPatternRegexWithFlags(
            text,
            length,
            flagText,
            flagsLength,
            (nint)(&error)
        );
        return handle == 0
            ? throw new RegexError(Text.Take(error) ?? "invalid regex")
            : new MatchPattern(handle);
    }

    /// <summary>Case-sensitive exact equality.</summary>
    public static MatchPattern Exact(string value)
    {
        using Arena arena = new();
        nint text = arena.Text(value, out nuint length);
        return new MatchPattern(Api.MatchPatternExact(text, length));
    }

    /// <summary>Exact equality with any of the listed strings.</summary>
    public static MatchPattern OneOf(params string[] values)
    {
        using Arena arena = new();
        return new MatchPattern(
            Api.MatchPatternOneOf(arena.Strs(values), (nuint)values.Length)
        );
    }

    /// <summary>
    /// An arbitrary predicate. It runs on every evaluating thread, so it
    /// must be thread-safe; an exception it throws counts as no match and is
    /// rethrown by the evaluation.
    /// </summary>
    public static unsafe MatchPattern Predicate(Func<string, bool> test)
    {
        nint userData = Predicates.Register(test);
        delegate* unmanaged[Cdecl]<nint, nint, nuint, byte> call =
            &Predicates.Test;
        delegate* unmanaged[Cdecl]<nint, void> drop = &Predicates.Drop;
        return new MatchPattern(
            Api.MatchPatternPredicate((nint)call, userData, (nint)drop)
        );
    }

    /// <summary>Test a candidate value.</summary>
    public bool IsMatch(string value) =>
        With(pattern =>
            Upcalls.Guarded(() =>
            {
                using Arena arena = new();
                nint text = arena.Text(value, out nuint length);
                return Api.MatchPatternIsMatch(pattern, text, length);
            })
        );
}

/// <summary>
/// The .NET predicates behind <see cref="MatchPattern.Predicate"/>: the
/// library holds an id as <c>user_data</c> and calls back with it.
/// </summary>
internal static class Predicates
{
    private static readonly ConcurrentDictionary<
        nint,
        Func<string, bool>
    > Registry = new();
    private static long nextId;

    public static nint Register(Func<string, bool> test)
    {
        nint id = (nint)Interlocked.Increment(ref nextId);
        Registry[id] = test;
        return id;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    public static byte Test(nint userData, nint value, nuint length)
    {
        try
        {
            return
                Registry.TryGetValue(userData, out var test)
                && test(Text.Read(value, length)!)
                ? (byte)1
                : (byte)0;
        }
        catch (Exception error)
        {
            Upcalls.Fail(error);
            return 0;
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    public static void Drop(nint userData) =>
        Registry.TryRemove(userData, out _);
}
