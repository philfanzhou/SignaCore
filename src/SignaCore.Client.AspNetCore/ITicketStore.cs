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
    /// Drops every ticket whose <see cref="SignaCoreSessionTicket.ExpiresUtc"/> has passed and
    /// returns the number removed, so expired sessions are reclaimed even when no request ever
    /// presents their key again.
    /// </summary>
    int RemoveExpired(CancellationToken cancellationToken);
}
