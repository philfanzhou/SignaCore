using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace SignaCore.ReferenceBff;

/// <summary>
/// The server-side session store of the reference BFF (<c>DF-07</c>). The browser only ever holds
/// the opaque key this store returns; every token — id token, access token, and the protected
/// properties — stays here on the server and never round-trips through the cookie.
///
/// This is deliberately an in-process store: it is a single-instance reference implementation, not
/// a distributed session product component. Process restarts and multi-replica deployments lose or
/// fail to share sessions; that boundary is the sample's explicit non-goal.
/// </summary>
public sealed class MemoryTicketStore(TimeProvider? timeProvider = null) : ITicketStore
{
    private readonly ConcurrentDictionary<string, AuthenticationTicket> _tickets = new();
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    /// <summary>The number of tickets currently held, including not-yet-swept expired ones.</summary>
    public int Count => _tickets.Count;

    public Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var key = Guid.NewGuid().ToString("N");
        _tickets[key] = ticket;
        return Task.FromResult(key);
    }

    public Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        if (!_tickets.TryGetValue(key, out var ticket))
        {
            return Task.FromResult<AuthenticationTicket?>(null);
        }

        // An expired ticket is unusparable and reclaimed on the spot rather than left to linger
        // until the periodic sweep reaches it.
        if (IsExpired(ticket))
        {
            _tickets.TryRemove(key, out _);
            return Task.FromResult<AuthenticationTicket?>(null);
        }

        return Task.FromResult<AuthenticationTicket?>(ticket);
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        _tickets[key] = ticket;
        return Task.CompletedTask;
    }

    public Task RemoveAsync(string key)
    {
        _tickets.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Drops every ticket whose <see cref="AuthenticationProperties.ExpiresUtc"/> has passed, so
    /// expired sessions are reclaimed even when no request ever presents their key again. Returns
    /// the number removed.
    /// </summary>
    public int RemoveExpired()
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

    private bool IsExpired(AuthenticationTicket ticket) =>
        ticket.Properties.ExpiresUtc is { } expiresUtc && expiresUtc <= _time.GetUtcNow();
}
