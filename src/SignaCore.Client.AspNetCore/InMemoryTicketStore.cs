using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The default <see cref="ITicketStore"/>: an in-process, capacity-bounded dictionary. Keys are
/// 256-bit random values; an expired ticket is unusable the moment its expiry passes and is
/// reclaimed either on access or by the periodic sweep. A full store refuses new tickets — it
/// never evicts a live session to make room. Process restarts and multiple replicas lose or fail
/// to share sessions; that boundary is the documented non-goal of the first phase (ADR 0007).
/// </summary>
public sealed class InMemoryTicketStore(TimeProvider? timeProvider = null) : ITicketStore
{
    private readonly ConcurrentDictionary<string, SignaCoreSessionTicket> _tickets = new();
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    /// <summary>The number of tickets currently held, including not-yet-swept expired ones.</summary>
    public int Count => _tickets.Count;

    /// <inheritdoc />
    public Task<string?> StoreAsync(SignaCoreSessionTicket ticket, CancellationToken cancellationToken)
    {
        if (_tickets.Count >= Capacity)
        {
            return Task.FromResult<string?>(null);
        }

        var key = NewKey();
        if (!_tickets.TryAdd(key, ticket))
        {
            return Task.FromResult<string?>(null);
        }

        return Task.FromResult<string?>(key);

        static string NewKey()
        {
            Span<byte> entropy = stackalloc byte[32];
            RandomNumberGenerator.Fill(entropy);
            return Convert.ToBase64String(entropy).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }

    /// <inheritdoc />
    /// <remarks>The in-memory override is atomic: one capacity check, then the new key is added
    /// and the old key removed in the same swap — a concurrent reader can never observe both the
    /// old and the new session as live, and a refused replacement changes nothing.</remarks>
    public Task<string?> ReplaceAsync(
        string? oldKey,
        SignaCoreSessionTicket ticket,
        CancellationToken cancellationToken)
    {
        if (_tickets.Count >= Capacity)
        {
            return Task.FromResult<string?>(null);
        }

        var key = NewKey();
        if (!_tickets.TryAdd(key, ticket))
        {
            return Task.FromResult<string?>(null);
        }

        // An absent or expired old key is not an error: the replacement degrades to a plain store.
        if (!string.IsNullOrEmpty(oldKey))
        {
            _tickets.TryRemove(oldKey, out _);
        }

        return Task.FromResult<string?>(key);

        static string NewKey()
        {
            Span<byte> entropy = stackalloc byte[32];
            RandomNumberGenerator.Fill(entropy);
            return Convert.ToBase64String(entropy).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }

    /// <inheritdoc />
    public Task<SignaCoreSessionTicket?> RetrieveAsync(string key, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(key) || !_tickets.TryGetValue(key, out var ticket))
        {
            return Task.FromResult<SignaCoreSessionTicket?>(null);
        }

        if (IsExpired(ticket))
        {
            _tickets.TryRemove(key, out _);
            return Task.FromResult<SignaCoreSessionTicket?>(null);
        }

        return Task.FromResult<SignaCoreSessionTicket?>(ticket);
    }

    /// <inheritdoc />
    public Task RemoveAsync(string key, CancellationToken cancellationToken)
    {
        _tickets.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public int RemoveExpired(CancellationToken cancellationToken)
    {
        var removed = 0;
        foreach (var entry in _tickets)
        {
            if (IsExpired(entry.Value) && _tickets.TryRemove(entry.Key, out _))
            {
                removed++;
            }
        }

        return removed;
    }

    /// <summary>The store's capacity; enforced by <see cref="SignaCoreHostedLoginOptions.TicketCapacity"/>
    /// through the registration, with a hard-coded fallback bound.</summary>
    internal int Capacity { get; init; } = 10_000;

    private bool IsExpired(SignaCoreSessionTicket ticket) => ticket.ExpiresUtc <= _time.GetUtcNow();
}
