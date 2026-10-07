using System.Security.Claims;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// One server-side session. The browser only ever holds the opaque key that references it; the
/// principal and both tokens stay server-side for the ticket's whole life.
/// </summary>
public sealed record SignaCoreSessionTicket(
    ClaimsPrincipal Principal,
    DateTimeOffset IssuedUtc,
    DateTimeOffset ExpiresUtc,
    string AccessToken,
    string IdToken);

/// <summary>
/// The server-side session store of the hosted-login integration. The default is an in-process,
/// capacity-bounded, expiry-swept implementation; multi-instance deployments replace it with a
/// shared store through their own registration.
/// </summary>
public interface ITicketStore
{
    /// <summary>
    /// Stores one ticket and returns its opaque, unguessable key, or <see langword="null"/> when
    /// the store refuses the ticket (capacity reached) — the caller then fails closed.
    /// </summary>
    Task<string?> StoreAsync(SignaCoreSessionTicket ticket, CancellationToken cancellationToken);

    /// <summary>Returns the ticket for a key, or <see langword="null"/> for an unknown or expired
    /// key; an expired ticket is reclaimed on the spot.</summary>
    Task<SignaCoreSessionTicket?> RetrieveAsync(string key, CancellationToken cancellationToken);

    /// <summary>Removes the ticket for a key; an unknown key is not an error.</summary>
    Task RemoveAsync(string key, CancellationToken cancellationToken);

    /// <summary>
    /// Stores one ticket and revokes a previous session key in a single replacement: the store
    /// either takes the new ticket and drops <paramref name="oldKey"/> together, or refuses the
    /// whole operation (capacity reached) and touches nothing — a full store never sacrifices the
    /// previous session. A null, empty, unknown, or already-expired <paramref name="oldKey"/> is
    /// equivalent to <see cref="StoreAsync"/>, never an error. Called by the sign-in callback
    /// with the browser's previous session cookie, so a fresh sign-in atomically ends the session
    /// it replaces. The default implementation is <see cref="StoreAsync"/> followed by
    /// <see cref="RemoveAsync"/> — correct, but not atomic; custom multi-instance stores that
    /// need the atomic guarantee (audit rows included, written in the same transaction as the
    /// swap) must override this method.
    /// </summary>
    /// <returns>The new ticket's opaque key, or <see langword="null"/> when the store refused the
    /// replacement — the caller then fails closed.</returns>
    async Task<string?> ReplaceAsync(
        string? oldKey,
        SignaCoreSessionTicket ticket,
        CancellationToken cancellationToken)
    {
        var key = await StoreAsync(ticket, cancellationToken);
        if (key is null)
        {
            return null;
        }

        if (!string.IsNullOrEmpty(oldKey))
        {
            await RemoveAsync(oldKey, cancellationToken);
        }

        return key;
    }

    /// <summary>
    /// Drops every ticket whose <see cref="SignaCoreSessionTicket.ExpiresUtc"/> has passed and
    /// returns the number removed, so expired sessions are reclaimed even when no request ever
    /// presents their key again.
    /// </summary>
    int RemoveExpired(CancellationToken cancellationToken);
}
