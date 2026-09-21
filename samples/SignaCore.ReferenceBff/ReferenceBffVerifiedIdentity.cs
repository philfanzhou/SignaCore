using Microsoft.AspNetCore.Authentication;

namespace SignaCore.ReferenceBff;

/// <summary>
/// The server-side ticket items that carry the identity the OIDC handler actually verified. The
/// values are captured once at sign-in from the validated security token — never from request
/// input, never from the configured authority — and live only inside the server-side ticket
/// store, so a ticket without them cannot be trusted to name an identity at all.
/// </summary>
internal static class ReferenceBffVerifiedIdentity
{
    /// <summary>The ticket item holding the validated token's issuer, byte-for-byte.</summary>
    public const string IssuerItem = "referenceBff.verifiedIssuer";

    /// <summary>The ticket item holding the validated token's single non-empty subject.</summary>
    public const string SubjectItem = "referenceBff.verifiedSubject";

    /// <summary>
    /// Reads the verified identity pair from a ticket's properties. A ticket issued before this
    /// capture existed answers null: the caller must treat it as unable to prove an identity.
    /// </summary>
    public static (string Issuer, string Subject)? Read(AuthenticationProperties? properties)
    {
        if (properties?.Items is not { } items
            || !items.TryGetValue(IssuerItem, out var issuer)
            || !items.TryGetValue(SubjectItem, out var subject)
            || string.IsNullOrEmpty(issuer)
            || string.IsNullOrEmpty(subject))
        {
            return null;
        }

        return (issuer, subject);
    }
}
