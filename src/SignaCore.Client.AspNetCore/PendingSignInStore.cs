using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The server-side state of a pending sign-in: the authorization request's <c>state</c> maps to
/// its <c>nonce</c>, PKCE verifier, and return address until the callback presents the same
/// value. A state is consumed exactly once, expires after five minutes, and the store holds at
/// most a bounded number of pending sign-ins — a flood of start requests can neither pin memory
/// nor keep old handshakes redeemable.
/// </summary>
internal sealed class PendingSignInStore(TimeProvider? timeProvider = null)
{
    internal static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);
    internal const int Capacity = 1_000;

    private readonly ConcurrentDictionary<string, PendingSignIn> _pending = new();
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    internal int Count => _pending.Count;

    /// <summary>
    /// Creates and stores one pending sign-in and returns its fresh state value, or
    /// <see langword="null"/> when the store has reached its capacity — the caller then fails
    /// closed rather than evicting a live handshake.
    /// </summary>
    internal string? Create(string nonce, string codeVerifier, string returnUrl)
    {
        if (_pending.Count >= Capacity)
        {
            return null;
        }

        Span<byte> entropy = stackalloc byte[32];
        RandomNumberGenerator.Fill(entropy);
        var state = Convert.ToBase64String(entropy).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var now = _time.GetUtcNow();
        _pending[state] = new PendingSignIn(nonce, codeVerifier, returnUrl, now + Lifetime);
        return state;
    }

    /// <summary>
    /// Consumes the pending sign-in for a state, exactly once: the entry is removed whether the
    /// caller then succeeds or fails, so a presented state can never be replayed.
    /// </summary>
    internal PendingSignIn? Consume(string? state)
    {
        if (string.IsNullOrEmpty(state) || !_pending.TryRemove(state, out var pending))
        {
            return null;
        }

        return pending.ExpiresUtc <= _time.GetUtcNow() ? null : pending;
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

    internal sealed record PendingSignIn(
        string Nonce,
        string CodeVerifier,
        string ReturnUrl,
        DateTimeOffset ExpiresUtc);
}
