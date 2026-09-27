namespace MurylloEx.MiniWaf;

/// <summary>
/// Rate-limit buckets an engine counts in. Give one to several instances
/// (<see cref="WafEngineOptions"/>) so they share counters, such as a rebuilt
/// instance taking over from the one it replaces. Instances using a store
/// keep it alive, so disposing this reference early is safe.
/// </summary>
public sealed class RateLimitStore : NativeResource
{
    public RateLimitStore(RateLimitStoreOptions? options = null)
        : this(Create(options ?? new RateLimitStoreOptions())) { }

    internal RateLimitStore(nint store)
        : base(store, Api.RateLimitStoreFree) { }

    private static nint Create(RateLimitStoreOptions options)
    {
        using Arena arena = new();
        return Api.RateLimitStoreNew(
            new RateLimitStoreOptionsNative
            {
                MaxKeys = arena.Optional(
                    options.MaxKeys is { } max ? (nuint?)max : null
                ),
                IdleMs = arena.Optional(options.IdleMs),
                PruneEveryHits = arena.Optional(options.PruneEveryHits),
            }
        );
    }
}
