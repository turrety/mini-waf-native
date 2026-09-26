using System.Collections;

namespace MurylloEx.MiniWaf;

/// <summary>
/// String-keyed pairs in insertion order, like the Rust <c>OrderedMap</c>:
/// inserting an existing key replaces its value in place.
/// </summary>
public class OrderedMap<TValue> : IEnumerable<KeyValuePair<string, TValue>>
{
    private readonly List<KeyValuePair<string, TValue>> entries = [];

    public int Len() => entries.Count;

    public bool IsEmpty() => entries.Count == 0;

    public TValue? Get(string key)
    {
        int index = IndexOf(key);
        return index < 0 ? default : entries[index].Value;
    }

    public void Insert(string key, TValue value)
    {
        int index = IndexOf(key);
        if (index < 0)
        {
            entries.Add(new(key, value));
        }
        else
        {
            entries[index] = new(key, value);
        }
    }

    public TValue? Remove(string key)
    {
        int index = IndexOf(key);
        if (index < 0)
        {
            return default;
        }
        TValue value = entries[index].Value;
        entries.RemoveAt(index);
        return value;
    }

    public IEnumerable<string> Keys() => entries.Select(entry => entry.Key);

    public IEnumerable<TValue> Values() => entries.Select(entry => entry.Value);

    /// <summary>
    /// Collection-initializer support: the same as <see cref="Insert"/>.
    /// </summary>
    public void Add(string key, TValue value) => Insert(key, value);

    public IEnumerator<KeyValuePair<string, TValue>> GetEnumerator() =>
        entries.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    private int IndexOf(string key) =>
        entries.FindIndex(entry => entry.Key == key);
}

/// <summary>
/// One header value; repeated headers (<c>Set-Cookie</c>,
/// <c>X-Forwarded-For</c>) may arrive as several.
/// </summary>
public abstract record HeaderValue
{
    private HeaderValue() { }

    public sealed record Single(string Value) : HeaderValue;

    public sealed record Multi(IReadOnlyList<string> Values) : HeaderValue;

    public static implicit operator HeaderValue(string value) =>
        new Single(value);

    public static HeaderValue From(IReadOnlyList<string> values) =>
        new Multi(values);
}

/// <summary>
/// Request headers. Keys should be lowercase, as HTTP/2 and most frameworks
/// already do; <c>headers.&lt;name&gt;</c> rules look names up lowercased.
/// </summary>
public sealed class HeaderMap : OrderedMap<HeaderValue>;

/// <summary>Parsed cookies (<c>name → value</c>).</summary>
public sealed class CookieMap : OrderedMap<string>;

/// <summary>Query parameters (<c>name → value</c>).</summary>
public sealed class QueryMap : OrderedMap<QueryValue>;

/// <summary>
/// A query-string value. Frameworks with "extended" parsers turn
/// <c>?filter[status]=open</c> into a nested object and
/// <c>?a[]=1&amp;a[]=2</c> into an array, so the model is recursive.
/// </summary>
public abstract record QueryValue
{
    private QueryValue() { }

    public sealed record Null : QueryValue;

    public sealed record Bool(bool Value) : QueryValue;

    public sealed record Number(double Value) : QueryValue;

    public sealed record String(string Value) : QueryValue;

    public sealed record Array(IReadOnlyList<QueryValue> Values) : QueryValue;

    public sealed record Object(QueryMap Map) : QueryValue;

    public static implicit operator QueryValue(string value) =>
        new String(value);
}

/// <summary>
/// A request body in whatever shape the framework produced it.
/// </summary>
public abstract record RawBody
{
    private RawBody() { }

    public sealed record Empty : RawBody;

    public sealed record Text(string Value) : RawBody;

    /// <summary>Bytes, decoded as UTF-8 (lossily) for inspection.</summary>
    public sealed record Bytes(ReadOnlyMemory<byte> Value) : RawBody;

    public static implicit operator RawBody(string? text) =>
        text is null ? new Empty() : new Text(text);

    public static implicit operator RawBody(byte[]? bytes) =>
        bytes is null ? new Empty() : new Bytes(bytes);
}

/// <summary>
/// An uploaded file as the multipart layer describes it. Only the name is
/// inspected (by the dangerous-upload rules), never the content.
/// </summary>
public sealed record UploadedFile(
    string? Fieldname = null,
    string? Name = null,
    string? Filename = null,
    string? Originalname = null
)
{
    /// <summary>A file known only by its client-side name.</summary>
    public static UploadedFile Named(string name) => new(Name: name);
}

/// <summary>
/// Uploaded files as multipart layers hand them over: a flat list, or a map
/// of form field to files.
/// </summary>
public abstract record FilesBag
{
    private FilesBag() { }

    public sealed record List(IReadOnlyList<UploadedFile> Files) : FilesBag;

    public sealed record Fields(OrderedMap<IReadOnlyList<UploadedFile>> Map)
        : FilesBag;

    public static implicit operator FilesBag(UploadedFile[] files) =>
        new List(files);

    public static implicit operator FilesBag(List<UploadedFile> files) =>
        new List(files);
}
