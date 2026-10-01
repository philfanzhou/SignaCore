using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The server side of one pending prepared logout: the browser holds an opaque correlation id in
/// a scoped HttpOnly cookie, and the store keeps the one-time <c>state</c> value that SignaCore
/// will echo back to the logout-return endpoint. A state is consumed exactly once, expires after
/// the five-minute prepared-logout window, and the store holds at most a bounded number of
/// pending returns. Presentation is compared in constant time, so a mismatch reveals nothing
/// about the stored value's contents.
/// </summary>
internal sealed class LogoutReturnStateStore(TimeProvider? timeProvider = null)
{
    internal static readonly TimeSpan Lifetime = SignaCoreHostedLoginDefaults.LogoutReturnLifetime;
    internal const int Capacity = 1_000;

    private readonly ConcurrentDictionary<string, PendingLogoutReturn> _pending = new();
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    internal int Count => _pending.Count;

    /// <summary>
    /// Stores one fresh <c>state</c> value and returns the opaque correlation id for the
    /// logout-return cookie, or <see langword="null"/> when the store has reached its capacity —
    /// the caller then completes the logout locally instead of waiting for a return.
    /// </summary>
    internal string? Create(string state)
    {
        if (_pending.Count >= Capacity)
        {
            return null;
        }

        Span<byte> entropy = stackalloc byte[32];
        RandomNumberGenerator.Fill(entropy);
        var correlationId = Convert.ToBase64String(entropy).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var now = _time.GetUtcNow();
        _pending[correlationId] = new PendingLogoutReturn(state, now + Lifetime);
        return correlationId;
    }

    /// <summary>
    /// Consumes the pending return for a correlation id, exactly once: the entry is removed
    /// whether the presented state matches or not, so neither replay nor probing can succeed
    /// against a value that was already tried.
    /// </summary>
    internal bool Consume(string? correlationId, string? presentedState)
    {
        if (string.IsNullOrEmpty(correlationId)
            || string.IsNullOrEmpty(presentedState)
            || !_pending.TryRemove(correlationId, out var pending))
        {
            return false;
        }

        if (pending.ExpiresUtc <= _time.GetUtcNow())
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(presentedState),
            System.Text.Encoding.ASCII.GetBytes(pending.State));
    }

    internal void RemoveExpired(CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();
        foreach (var entry in _pending)
        {
            if (entry.Value.ExpiresUtc <= now)
            {
                _pending.TryRemove(entry.Key, out _);
            }
        }
    }

    internal sealed record PendingLogoutReturn(string State, DateTimeOffset ExpiresUtc);
}
