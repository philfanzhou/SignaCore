using SignaCore.Host.Security;

namespace SignaCore.Host.Bootstrap;

/// <summary>
/// Holds the one-time code that gates Bootstrap Configuration Mode.
/// <para>
/// The code is ephemeral operational proof, not a configuration field: it is generated in memory
/// when the process finds no bootstrap file, printed once to standard output, and never persisted —
/// there is no database to persist it to yet, and the file it would be written to is the very file
/// it protects. Restarting the process therefore issues a new code, which is the intended recovery
/// path when an operator loses it.
/// </para>
/// </summary>
internal sealed class BootstrapCodeAuthority
{
    public static TimeSpan DefaultLifetime => TimeSpan.FromHours(1);

    private readonly string _hash;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _saveGate = new(1, 1);
    private int _consumed;

    private BootstrapCodeAuthority(string hash, DateTimeOffset expiresAt, TimeProvider timeProvider)
    {
        _hash = hash;
        ExpiresAt = expiresAt;
        _timeProvider = timeProvider;
    }

    /// <summary>Generates a code, returning the plaintext exactly once for the console banner.</summary>
    public static BootstrapCodeAuthority Create(out string plaintext, TimeProvider? timeProvider = null)
    {
        timeProvider ??= TimeProvider.System;
        plaintext = OneTimeCode.Generate();
        return new BootstrapCodeAuthority(
            OneTimeCode.Hash(plaintext),
            timeProvider.GetUtcNow().Add(DefaultLifetime),
            timeProvider);
    }

    public DateTimeOffset ExpiresAt { get; }

    /// <summary>True once a submission has been accepted; further submissions are refused.</summary>
    public bool IsConsumed => Volatile.Read(ref _consumed) == 1;

    public bool Verify(string? candidate) =>
        !IsConsumed && _timeProvider.GetUtcNow() < ExpiresAt && OneTimeCode.Verify(candidate, _hash);

    /// <summary>
    /// Serializes save attempts so two concurrent requests cannot both verify the same code before
    /// either one consumes it. A failed save releases the lease without consuming the code.
    /// </summary>
    public async ValueTask<IDisposable> AcquireSaveLeaseAsync(CancellationToken cancellationToken)
    {
        await _saveGate.WaitAsync(cancellationToken);
        return new SaveLease(_saveGate);
    }

    /// <summary>
    /// Marks the code used. Called only after the bootstrap file has actually been written, so a
    /// rejected or failed attempt leaves the operator able to try again with the same code.
    /// </summary>
    public void Consume() => Interlocked.Exchange(ref _consumed, 1);

    private sealed class SaveLease(SemaphoreSlim gate) : IDisposable
    {
        private SemaphoreSlim? _gate = gate;

        public void Dispose() => Interlocked.Exchange(ref _gate, null)?.Release();
    }
}
