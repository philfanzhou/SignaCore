using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The server-side state of a pending sign-in: the authorization request's <c>state</c> maps to
/// its <c>nonce</c>, PKCE verifier, return address, and browser-binding hash until the callback
/// presents the same value. A state is consumed exactly once, expires after five minutes, and the
/// store holds at most a bounded number of pending sign-ins — a flood of start requests can
/// neither pin memory nor keep old handshakes redeemable.
/// </summary>
internal sealed class PendingSignInStore(TimeProvider? timeProvider = null)
{
    internal static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);
    internal const int Capacity = 1_000;

    private readonly ConcurrentDictionary<string, PendingSignIn> _pending = new();
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    internal int Count => _pending.Count;

    /// <summary>
    /// Creates and stores one pending sign-in and returns its fresh state value together with
    /// the browser-binding value the caller must set as the binding cookie, or
    /// <see langword="null"/> when the store has reached its capacity — the caller then fails
    /// closed rather than evicting a live handshake.
    /// </summary>
    internal PendingSignInCreation? Create(string nonce, string codeVerifier, string returnUrl)
    {
        if (_pending.Count >= Capacity)
        {
            return null;
        }

        Span<byte> entropy = stackalloc byte[32];
        RandomNumberGenerator.Fill(entropy);
        var state = Convert.ToBase64String(entropy).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        RandomNumberGenerator.Fill(entropy);
        var browserBinding = Convert.ToBase64String(entropy).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var now = _time.GetUtcNow();
        _pending[state] = new PendingSignIn(
            nonce, codeVerifier, returnUrl,
            SHA256.HashData(Encoding.UTF8.GetBytes(browserBinding)), now + Lifetime);
        return new PendingSignInCreation(state, browserBinding);
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

    internal sealed record PendingSignInCreation(string State, string BrowserBinding);

    internal sealed record PendingSignIn(
        string Nonce,
        string CodeVerifier,
        string ReturnUrl,
        byte[] BrowserBindingHash,
        DateTimeOffset ExpiresUtc);
}
