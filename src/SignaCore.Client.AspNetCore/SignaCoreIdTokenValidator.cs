using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The verified outcome of one ID token: the validated principal plus the exact <c>iss</c> and
/// <c>sub</c> the validation established. Nothing here is ever written to a response.
/// </summary>
internal sealed record SignaCoreVerifiedIdentity(
    ClaimsPrincipal Principal,
    string Issuer,
    string Subject,
    string? DisplayName);

/// <summary>
/// The strict ID-token validation of the hosted-login contract: RS256 only, through a key the
/// authority's JWKS published (selected by <c>kid</c>); header <c>typ</c> exactly <c>JWT</c>;
/// <c>iss</c> equal to the Discovery issuer; <c>aud</c> equal to the client id; validated
/// lifetime; the <c>nonce</c> equal to the pending sign-in's value; and exactly one non-empty
/// <c>sub</c>. Any other shape fails the sign-in; no identity is inferred or repaired.
/// </summary>
internal sealed class SignaCoreIdTokenValidator(
    IOptionsMonitor<SignaCoreHostedLoginOptions> options,
    TimeProvider timeProvider)
{
    private static readonly JsonWebTokenHandler Handler = new();

    /// <summary>
    /// The historical accepted clock skew of the lifetime validation — thirty seconds. The live
    /// validation reads <see cref="SignaCoreValidationOptions.ClockSkew"/> instead, whose default
    /// is the strict zero; this constant remains only as the documented upper bound the options
    /// validator enforces.
    /// </summary>
    internal static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(30);

    internal async Task<SignaCoreVerifiedIdentity?> ValidateAsync(
        SignaCoreAuthorityConfiguration configuration,
        string idToken,
        string expectedNonce,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var current = options.CurrentValue;
        var skew = current.Validation.ClockSkew;
        var validationParameters = new TokenValidationParameters
        {
            ValidAlgorithms = ["RS256"],
            RequireSignedTokens = true,
            ValidIssuer = configuration.Issuer,
            ValidAudience = current.ClientId!,
            ValidTypes = ["JWT"],
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            IssuerSigningKeys = configuration.SigningKeys,
            ClockSkew = skew
        };

        TokenValidationResult result;
        try
        {
            result = await Handler.ValidateTokenAsync(idToken, validationParameters);
        }
        catch (Exception exception) when (exception is ArgumentException or SecurityTokenException)
        {
            return null;
        }

        if (!result.IsValid
            || result.SecurityToken is not JsonWebToken token
            || result.ClaimsIdentity is not { } validatedIdentity)
        {
            return null;
        }

        // A future issued-at (beyond the configured skew) is not a usable token: no honest
        // authority issues ahead of its own clock, and the claim is how an issuance-time policy
        // would be bypassed. Optional by contract, so an absent iat is not itself a failure.
        if (current.Validation.RejectFutureIssuedAt
            && token.IssuedAt != DateTime.MinValue
            && token.IssuedAt > timeProvider.GetUtcNow().UtcDateTime + skew)
        {
            return null;
        }

        var principal = new ClaimsPrincipal(validatedIdentity);
        var subjectClaims = principal.FindAll("sub").ToList();
        if (subjectClaims.Count != 1 || string.IsNullOrEmpty(subjectClaims[0].Value))
        {
            return null;
        }

        var nonceClaims = principal.FindAll("nonce").ToList();
        if (nonceClaims.Count != 1
            || string.IsNullOrEmpty(nonceClaims[0].Value)
            || !string.Equals(nonceClaims[0].Value, expectedNonce, StringComparison.Ordinal))
        {
            return null;
        }

        var nameClaims = principal.FindAll("name").ToList();
        var displayName = nameClaims.Count == 1 ? nameClaims[0].Value : null;

        return new SignaCoreVerifiedIdentity(
            principal,
            token.Issuer,
            subjectClaims[0].Value,
            displayName);
    }
}
