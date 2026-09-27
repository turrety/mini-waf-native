namespace MurylloEx.MiniWaf;

/// <summary>
/// Write .NET values into the native out-parameters of callbacks.
/// </summary>
internal static unsafe class Fill
{
    public static void String(nint @out, string? value)
    {
        if (value is null)
        {
            return;
        }
        using Arena arena = new();
        nint text = arena.Text(value, out nuint length);
        Api.StringSet(@out, text, length);
    }

    public static void Headers(nint @out, HeaderMap? headers)
    {
        if (headers is null)
        {
            return;
        }
        using Arena arena = new();
        foreach ((string key, HeaderValue header) in headers)
        {
            IReadOnlyList<string> values = header switch
            {
                HeaderValue.Single single => [single.Value],
                HeaderValue.Multi multi => multi.Values,
                _ => [],
            };
            nint name = arena.Text(key, out nuint length);
            Api.HeaderMapInsert(
                @out,
                name,
                length,
                arena.Strs(values),
                (nuint)values.Count
            );
        }
    }

    public static void Query(nint @out, QueryMap? query)
    {
        if (query is null)
        {
            return;
        }
        using Arena arena = new();
        foreach ((string key, QueryValue entry) in query)
        {
            nint name = arena.Text(key, out nuint length);
            nint value = QueryValue(entry);
            try
            {
                Api.QueryMapInsert(@out, name, length, value);
            }
            finally
            {
                Api.QueryValueFree(value);
            }
        }
    }

    /// <summary>A native <c>QueryValue</c>; the caller frees it.</summary>
    private static nint QueryValue(QueryValue value)
    {
        switch (value)
        {
            case QueryValue.Bool flag:
                return Api.QueryValueBool(flag.Value);
            case QueryValue.Number number:
                return Api.QueryValueNumber(number.Value);
            case QueryValue.String text:
            {
                using Arena arena = new();
                nint bytes = arena.Text(text.Value, out nuint length);
                return Api.QueryValueString(bytes, length);
            }
            case QueryValue.Array array:
                return QueryArray(array.Values);
            case QueryValue.Object @object:
            {
                nint map = Api.QueryMapNew();
                try
                {
                    Query(map, @object.Map);
                    return Api.QueryValueObject(map);
                }
                finally
                {
                    Api.QueryMapFree(map);
                }
            }
            default:
                return Api.QueryValueNull();
        }
    }

    private static nint QueryArray(IReadOnlyList<QueryValue> values)
    {
        List<nint> items = [.. values.Select(QueryValue)];
        try
        {
            using Arena arena = new();
            return Api.QueryValueArray(
                arena.Pointers(items),
                (nuint)items.Count
            );
        }
        finally
        {
            items.ForEach(Api.QueryValueFree);
        }
    }

    public static void Cookies(nint @out, CookieMap? cookies)
    {
        if (cookies is null)
        {
            return;
        }
        using Arena arena = new();
        foreach ((string key, string value) in cookies)
        {
            nint name = arena.Text(key, out nuint nameLength);
            nint text = arena.Text(value, out nuint valueLength);
            Api.CookieMapInsert(@out, name, nameLength, text, valueLength);
        }
    }

    public static void Body(nint @out, RawBody? body)
    {
        switch (body)
        {
            case RawBody.Text text:
            {
                using Arena arena = new();
                nint bytes = arena.Text(text.Value, out nuint length);
                Api.RawBodyText(@out, bytes, length);
                break;
            }
            case RawBody.Bytes bytes:
                fixed (byte* data = bytes.Value.Span)
                {
                    Api.RawBodyBytes(
                        @out,
                        (nint)data,
                        (nuint)bytes.Value.Length
                    );
                }
                break;
        }
    }

    public static void Files(nint @out, FilesBag? bag)
    {
        using Arena arena = new();
        switch (bag)
        {
            case FilesBag.List list:
                Api.FilesBagList(
                    @out,
                    UploadedFiles(arena, list.Files),
                    (nuint)list.Files.Count
                );
                break;
            case FilesBag.Fields fields:
                foreach (
                    (
                        string key,
                        IReadOnlyList<UploadedFile> files
                    ) in fields.Map
                )
                {
                    nint name = arena.Text(key, out nuint length);
                    Api.FilesBagFieldsInsert(
                        @out,
                        name,
                        length,
                        UploadedFiles(arena, files),
                        (nuint)files.Count
                    );
                }
                break;
        }
    }

    private static nint UploadedFiles(
        Arena arena,
        IReadOnlyList<UploadedFile> files
    )
    {
        nint array = arena.Allocate(
            (nuint)(files.Count * sizeof(UploadedFileNative))
        );
        for (int index = 0; index < files.Count; index++)
        {
            UploadedFile file = files[index];
            ((UploadedFileNative*)array)[index] = new UploadedFileNative
            {
                Fieldname = arena.Str(file.Fieldname),
                Name = arena.Str(file.Name),
                Filename = arena.Str(file.Filename),
                Originalname = arena.Str(file.Originalname),
            };
        }
        return array;
    }
}
