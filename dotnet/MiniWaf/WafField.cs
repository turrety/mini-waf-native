namespace MurylloEx.MiniWaf;

/// <summary>
/// Supported request fields. Nested accessors use dotted paths in their
/// string form (<c>query.id</c>, <c>headers.user-agent</c>).
/// </summary>
/// <remarks>
/// Multi-value fields (<c>Query</c>, <c>Headers</c>, <c>Cookies</c>,
/// <c>Files</c>) yield every value, and a condition matches when any of them
/// does.
/// </remarks>
public sealed record WafField
{
    private enum Kind
    {
        Unit,
        QueryParam,
        Header,
        Cookie,
    }

    private readonly Kind kind;
    private readonly string name;

    private WafField(Kind kind, string name)
    {
        this.kind = kind;
        this.name = name;
    }

    public static readonly WafField Ip = new(Kind.Unit, "ip");
    public static readonly WafField Method = new(Kind.Unit, "method");
    public static readonly WafField Path = new(Kind.Unit, "path");
    public static readonly WafField Url = new(Kind.Unit, "url");
    public static readonly WafField Body = new(Kind.Unit, "body");
    public static readonly WafField Files = new(Kind.Unit, "files");
    public static readonly WafField Query = new(Kind.Unit, "query");
    public static readonly WafField Headers = new(Kind.Unit, "headers");
    public static readonly WafField Cookies = new(Kind.Unit, "cookies");

    /// <summary><c>query.&lt;name&gt;</c></summary>
    public static WafField QueryParam(string name) =>
        new(Kind.QueryParam, name);

    /// <summary>
    /// <c>headers.&lt;name&gt;</c>; the name is matched lowercased.
    /// </summary>
    public static WafField Header(string name) => new(Kind.Header, name);

    /// <summary><c>cookies.&lt;name&gt;</c></summary>
    public static WafField Cookie(string name) => new(Kind.Cookie, name);

    /// <summary>
    /// Parse the dotted path form; throws <see cref="InvalidField"/> when
    /// unsupported.
    /// </summary>
    public static unsafe WafField FromStr(string field)
    {
        using Arena arena = new();
        nint text = arena.Text(field, out nuint length);
        nint error = 0;
        nint handle = Api.WafFieldFromStr(text, length, (nint)(&error));
        if (handle == 0)
        {
            throw new InvalidField(Text.Take(error) ?? "unsupported field");
        }
        try
        {
            return Parsed(Text.Take(Api.WafFieldToString(handle))!);
        }
        finally
        {
            Api.WafFieldFree(handle);
        }
    }

    private static WafField Parsed(string path)
    {
        int dot = path.IndexOf('.');
        if (dot < 0)
        {
            return new WafField(Kind.Unit, path);
        }
        string name = path[(dot + 1)..];
        return path[..dot] switch
        {
            "query" => QueryParam(name),
            "headers" => Header(name),
            _ => Cookie(name),
        };
    }

    /// <summary>A native <c>WafField</c> handle; the caller frees it.</summary>
    internal nint ToNative(Arena arena)
    {
        nint text = arena.Text(name, out nuint length);
        return kind switch
        {
            Kind.Unit => Api.WafFieldFromStr(text, length, 0),
            Kind.QueryParam => Api.WafFieldQuery(text, length),
            Kind.Header => Api.WafFieldHeader(text, length),
            _ => Api.WafFieldCookie(text, length),
        };
    }

    /// <summary>The dotted path form.</summary>
    public override string ToString() =>
        kind switch
        {
            Kind.Unit => name,
            Kind.QueryParam => "query." + name,
            Kind.Header => "headers." + name,
            _ => "cookies." + name,
        };
}
