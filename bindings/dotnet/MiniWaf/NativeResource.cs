using System.Runtime.InteropServices;

namespace MurylloEx.MiniWaf;

/// <summary>A native handle released by its matching <c>*_free</c>.</summary>
internal sealed class OwnedHandle : SafeHandle
{
    private readonly Action<nint> free;

    public OwnedHandle(nint handle, Action<nint> free)
        : base(0, ownsHandle: true)
    {
        if (handle == 0)
        {
            throw new InvalidOperationException(
                "mini-waf returned a null handle"
            );
        }
        this.free = free;
        SetHandle(handle);
    }

    public override bool IsInvalid => handle == 0;

    protected override bool ReleaseHandle()
    {
        free(handle);
        return true;
    }
}

/// <summary>
/// An object owning one native handle, freed by <see cref="Dispose"/> or
/// by finalization.
/// </summary>
public abstract class NativeResource : IDisposable
{
    private readonly OwnedHandle handle;

    private protected NativeResource(nint handle, Action<nint> free)
    {
        this.handle = new OwnedHandle(handle, free);
    }

    /// <summary>
    /// Run <paramref name="body"/> with the handle, which stays valid
    /// meanwhile.
    /// </summary>
    internal T With<T>(Func<nint, T> body)
    {
        bool added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            return body(handle.DangerousGetHandle());
        }
        catch (ObjectDisposedException)
        {
            throw new ObjectDisposedException(GetType().Name);
        }
        finally
        {
            if (added)
            {
                handle.DangerousRelease();
            }
        }
    }

    internal void Run(Action<nint> body) =>
        With(address =>
        {
            body(address);
            return 0;
        });

    /// <summary>
    /// Free the native handle now; later uses throw
    /// <see cref="ObjectDisposedException"/>.
    /// </summary>
    public void Dispose()
    {
        handle.Dispose();
        GC.SuppressFinalize(this);
    }
}

internal static class Resources
{
    /// <summary>
    /// Run <paramref name="body"/> with the handles of every resource, each
    /// kept valid meanwhile.
    /// </summary>
    public static T WithAll<T>(
        IReadOnlyList<NativeResource> resources,
        Func<List<nint>, T> body
    )
    {
        List<nint> handles = new(resources.Count);
        return Pin(0);

        T Pin(int index) =>
            index == resources.Count
                ? body(handles)
                : resources[index]
                    .With(address =>
                    {
                        handles.Add(address);
                        return Pin(index + 1);
                    });
    }
}
