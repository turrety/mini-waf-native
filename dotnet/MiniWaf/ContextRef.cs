namespace MurylloEx.MiniWaf;

/// <summary>
/// The request of a log event: a read-only <see cref="WafHttpContext"/> over
/// the engine's, valid while the logger callback runs.
/// </summary>
internal sealed unsafe class ContextRef(nint ctx) : WafHttpContext
{
    private string Lend(Func<nint, nint, nint> getter) =>
        Text.Lent(length => getter(ctx, length)) ?? "";

    public string Framework() => Lend(Api.WafHttpContextRefFramework);

    public string GetMethod() => Lend(Api.WafHttpContextRefGetMethod);

    public string GetUrl() => Lend(Api.WafHttpContextRefGetUrl);

    public string GetPath() => Lend(Api.WafHttpContextRefGetPath);

    public string GetIp() => Lend(Api.WafHttpContextRefGetIp);

    public string GetProtocol() => Lend(Api.WafHttpContextRefGetProtocol);

    public ushort GetLocalPort() => Api.WafHttpContextRefGetLocalPort(ctx);

    public string? GetHeader(string name)
    {
        using Arena arena = new();
        nint text = arena.Text(name, out nuint length);
        return Text.Lent(valueLength =>
            Api.WafHttpContextRefGetHeader(ctx, text, length, valueLength)
        );
    }

    public HeaderMap GetHeaders()
    {
        nint map = Api.WafHttpContextRefGetHeaders(ctx);
        HeaderMap headers = new();
        MiniWafStr name;
        byte multi;
        nuint count;
        for (
            nuint index = 0;
            Api.HeaderMapGetAt(
                map,
                index,
                (nint)(&name),
                (nint)(&multi),
                (nint)(&count)
            );
            index++
        )
        {
            List<string> values = [];
            for (nuint item = 0; item < count; item++)
            {
                MiniWafStr value;
                Api.HeaderMapGetValueAt(map, index, item, (nint)(&value));
                values.Add(Read(value)!);
            }
            headers.Insert(
                Read(name)!,
                multi != 0 ? HeaderValue.From(values) : values[0]
            );
        }
        return headers;
    }

    public QueryMap GetQuery() => Query(Api.WafHttpContextRefGetQuery(ctx));

    private static QueryMap Query(nint map)
    {
        QueryMap query = new();
        nuint count = Api.QueryMapLen(map);
        for (nuint index = 0; index < count; index++)
        {
            MiniWafStr key;
            nint value = Api.QueryMapGetAt(map, index, (nint)(&key));
            query.Insert(Read(key)!, Value(value));
        }
        return query;
    }

    private static QueryValue Value(nint value)
    {
        switch (Api.QueryValueKind(value))
        {
            case 1:
                return new QueryValue.Bool(Api.QueryValueGetBool(value));
            case 2:
                return new QueryValue.Number(Api.QueryValueGetNumber(value));
            case 3:
                MiniWafStr text;
                Api.QueryValueGetString(value, (nint)(&text));
                return new QueryValue.String(Read(text)!);
            case 4:
                nuint count = Api.QueryValueArrayLen(value);
                List<QueryValue> items = [];
                for (nuint index = 0; index < count; index++)
                {
                    items.Add(Value(Api.QueryValueArrayGet(value, index)));
                }
                return new QueryValue.Array(items);
            case 5:
                return new QueryValue.Object(
                    Query(Api.QueryValueGetObject(value))
                );
            default:
                return new QueryValue.Null();
        }
    }

    public CookieMap GetCookies()
    {
        nint map = Api.WafHttpContextRefGetCookies(ctx);
        CookieMap cookies = new();
        MiniWafStr name;
        MiniWafStr value;
        for (
            nuint index = 0;
            Api.CookieMapGetAt(map, index, (nint)(&name), (nint)(&value));
            index++
        )
        {
            cookies.Insert(Read(name)!, Read(value)!);
        }
        return cookies;
    }

    public string GetRawBody() => Lend(Api.WafHttpContextRefGetRawBody);

    public IReadOnlyList<UploadedFile> GetFiles()
    {
        nuint count = 0;
        UploadedFileNative* files = (UploadedFileNative*)
            Api.WafHttpContextRefGetFiles(ctx, (nint)(&count));
        UploadedFile[] converted = new UploadedFile[(int)count];
        for (int index = 0; index < converted.Length; index++)
        {
            UploadedFileNative file = files[index];
            converted[index] = new UploadedFile(
                Read(file.Fieldname),
                Read(file.Name),
                Read(file.Filename),
                Read(file.Originalname)
            );
        }
        return converted;
    }

    public void SetResponseHeader(string name, string value) =>
        throw ReadOnly();

    public void RemoveResponseHeader(string name) => throw ReadOnly();

    public bool IsBlocked() => Api.WafHttpContextRefIsBlocked(ctx);

    public void Drop(ushort? statusCode, string? body) => throw ReadOnly();

    private static string? Read(MiniWafStr text) =>
        Text.Read(text.Data, text.Len);

    private static NotSupportedException ReadOnly() =>
        new("a logged request is read-only");
}
