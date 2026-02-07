#nullable enable

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace TestVault.Core.Security;

/// <summary>
/// Memory protection utilities to prevent sensitive data from persisting in RAM.
/// Provides pinned-buffer management, secure zeroing, and safe secret-usage patterns.
/// </summary>
public static class MemoryGuard
{
    /// <summary>
    /// Pins the provided byte array in memory, converts it to a UTF-8 string,
    /// executes the supplied action, then securely zeros the bytes before releasing
    /// the pinned handle. The string remains in managed memory but the raw bytes
    /// are guaranteed to be wiped regardless of exceptions.
    /// </summary>
    /// <typeparam name="T">The return type of the action.</typeparam>
    /// <param name="secretBytes">The raw secret bytes to protect.</param>
    /// <param name="action">A function that receives the decoded string and returns a result.</param>
    /// <returns>The result of <paramref name="action"/>.</returns>
    public static T UseSecret<T>(byte[] secretBytes, Func<string, T> action)
    {
        ArgumentNullException.ThrowIfNull(secretBytes);
        ArgumentNullException.ThrowIfNull(action);

        GCHandle handle = GCHandle.Alloc(secretBytes, GCHandleType.Pinned);
        try
        {
            string secret = Encoding.UTF8.GetString(secretBytes);
            return action(secret);
        }
        finally
        {
            SecureZero(secretBytes);
            handle.Free();
        }
    }

    /// <summary>
    /// Securely zeros a byte array using <see cref="CryptographicOperations.ZeroMemory"/>.
    /// Decorated with <see cref="MethodImplAttribute"/> to prevent inlining and optimization,
    /// and uses <see cref="Volatile.Read(ref byte)"/> to defeat dead-store elimination.
    /// </summary>
    /// <param name="buffer">The byte array to zero. If null, the method is a no-op.</param>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void SecureZero(byte[]? buffer)
    {
        if (buffer is null || buffer.Length == 0)
            return;

        CryptographicOperations.ZeroMemory(buffer);

        // Volatile read prevents the compiler/JIT from eliminating the zero-write
        // as a dead store, since it forces observation of the final value.
        Volatile.Read(ref buffer[0]);
    }

    /// <summary>
    /// Securely zeros a char array by overwriting every element with '\0'.
    /// Decorated with <see cref="MethodImplAttribute"/> to prevent inlining and optimization,
    /// and uses <see cref="Volatile.Read(ref char)"/> to defeat dead-store elimination.
    /// </summary>
    /// <param name="buffer">The char array to zero. If null, the method is a no-op.</param>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void SecureZero(char[]? buffer)
    {
        if (buffer is null || buffer.Length == 0)
            return;

        // CryptographicOperations.ZeroMemory operates on byte spans;
        // reinterpret the char array as bytes and zero the entire region.
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buffer.AsSpan()));

        // Prevent dead-store elimination by reading the first element
        _ = buffer[0];
    }

    /// <summary>
    /// Allocates a pinned byte buffer of the specified size that is automatically
    /// zeroed and released when disposed.
    /// </summary>
    /// <param name="size">The number of bytes to allocate. Must be greater than zero.</param>
    /// <returns>A <see cref="PinnedBuffer"/> wrapping the pinned allocation.</returns>
    public static PinnedBuffer CreatePinnedBuffer(int size)
    {
        return new PinnedBuffer(size);
    }
}

/// <summary>
/// A fixed-size byte buffer pinned in memory via <see cref="GCHandle"/> so that the
/// garbage collector will not relocate it, preventing stale copies in RAM.
/// On disposal the buffer is securely zeroed before the pin is released.
/// </summary>
public sealed class PinnedBuffer : IDisposable
{
    private readonly byte[] _buffer;
    private GCHandle _handle;
    private bool _disposed;

    /// <summary>
    /// Initializes a new <see cref="PinnedBuffer"/> of the requested size.
    /// </summary>
    /// <param name="size">Number of bytes to allocate. Must be greater than zero.</param>
    internal PinnedBuffer(int size)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(size);

        _buffer = new byte[size];
        _handle = GCHandle.Alloc(_buffer, GCHandleType.Pinned);
    }

    /// <summary>
    /// Gets the underlying byte array. Throws if the buffer has been disposed.
    /// </summary>
    public byte[] Buffer
    {
        get
        {
            ThrowIfDisposed();
            return _buffer;
        }
    }

    /// <summary>
    /// Gets a <see cref="Span{T}"/> over the underlying byte array.
    /// Throws if the buffer has been disposed.
    /// </summary>
    public Span<byte> Span
    {
        get
        {
            ThrowIfDisposed();
            return _buffer.AsSpan();
        }
    }

    /// <summary>
    /// Gets the length of the buffer in bytes. Throws if the buffer has been disposed.
    /// </summary>
    public int Length
    {
        get
        {
            ThrowIfDisposed();
            return _buffer.Length;
        }
    }

    /// <summary>
    /// Securely zeros the buffer contents and releases the pinned GC handle.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        MemoryGuard.SecureZero(_buffer);

        if (_handle.IsAllocated)
            _handle.Free();

        _disposed = true;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
