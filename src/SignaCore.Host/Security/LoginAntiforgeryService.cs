using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.Tokens;

namespace SignaCore.Host.Security;

/// <summary>
/// One issued login antiforgery pair. <paramref name="CookieValue"/> is written only when
/// <paramref name="ReusedExistingCookie"/> is <c>false</c>; <paramref name="RequestToken"/> always
/// goes into the rendered form. Both are unpadded base64url and stay request-lifetime only — the
/// service keeps no server-side state (<c>PS-19</c>).
/// </summary>
public sealed record LoginAntiforgeryPair(
    string CookieValue,
    string RequestToken,
    bool ReusedExistingCookie);

/// <summary>
/// Issues and validates the principal-independent login antiforgery pair of canonical
/// <c>PS-19</c>. See <see cref="LoginAntiforgeryDefaults"/> for why this is SignaCore-owned
/// rather than ASP.NET Core's <c>IAntiforgery</c>.
/// </summary>
public interface ILoginAntiforgeryService
{
    /// <summary>
    /// Produces the pair for a form render. When <paramref name="existingCookieValue"/> unprotects
    /// to a well-formed secret, that secret is reused and the returned pair reports
    /// <see cref="LoginAntiforgeryPair.ReusedExistingCookie"/> so the caller writes no new cookie
    /// and already-rendered tabs keep validating; otherwise a fresh CSPRNG secret is generated and
    /// the caller must write <see cref="LoginAntiforgeryPair.CookieValue"/>.
    /// </summary>
    LoginAntiforgeryPair IssuePair(string? existingCookieValue);

    /// <summary>
    /// Validates a submitted pair: both values must unprotect under their own sub-purpose and the
    /// recovered secrets must be equal in constant time. Every decode or unprotect failure — a
    /// foreign purpose payload, a swapped or tampered value, malformed base64url — is simply
    /// <c>false</c>; the caller folds it into the single local 400 (<c>SC-19</c>).
    /// </summary>
    bool IsValidPair(string cookieValue, string requestToken);
}

public sealed class LoginAntiforgeryService : ILoginAntiforgeryService
{
    private readonly IDataProtector _cookieProtector;
    private readonly IDataProtector _requestProtector;

    public LoginAntiforgeryService(IDataProtectionProvider dataProtectionProvider)
    {
        // Both protectors derive from the shared provider — the fixed ServiceMantle discriminator
        // with the key ring in the shared encrypted store — and are separated only by sub-purpose,
        // exactly like the identity cookie's single pinned purpose.
        var root = dataProtectionProvider.CreateProtector(
            LoginAntiforgeryDefaults.DataProtectionPurpose);
        _cookieProtector = root.CreateProtector("cookie");
        _requestProtector = root.CreateProtector("request");
    }

    public LoginAntiforgeryPair IssuePair(string? existingCookieValue)
    {
        var existingSecret = TryUnprotect(_cookieProtector, existingCookieValue);
        if (existingSecret is { Length: LoginAntiforgeryDefaults.SecretLength })
        {
            // Multi-tab: the browser already holds a usable cookie secret, so only a fresh request
            // token is derived and no cookie is written.
            return new LoginAntiforgeryPair(
                existingCookieValue!,
                Protect(_requestProtector, existingSecret),
                ReusedExistingCookie: true);
        }

        var secret = new byte[LoginAntiforgeryDefaults.SecretLength];
        RandomNumberGenerator.Fill(secret);
        return new LoginAntiforgeryPair(
            Protect(_cookieProtector, secret),
            Protect(_requestProtector, secret),
            ReusedExistingCookie: false);
    }

    public bool IsValidPair(string cookieValue, string requestToken)
    {
        var cookieSecret = TryUnprotect(_cookieProtector, cookieValue);
        var requestSecret = TryUnprotect(_requestProtector, requestToken);
        if (cookieSecret is null || requestSecret is null)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(cookieSecret, requestSecret);
    }

    private static string Protect(IDataProtector protector, byte[] secret) =>
        Base64UrlEncoder.Encode(protector.Protect(secret));

    private static byte[]? TryUnprotect(IDataProtector protector, string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        try
        {
            return protector.Unprotect(Base64UrlEncoder.DecodeBytes(value));
        }
        catch (Exception exception) when (exception
            is CryptographicException or FormatException or ArgumentException)
        {
            // A value from another purpose, another key ring, or not base64url at all is
            // indistinguishable from a missing one: the pair simply does not validate.
            return null;
        }
    }
}
