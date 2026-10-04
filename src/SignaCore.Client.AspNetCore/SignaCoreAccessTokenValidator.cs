using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace SignaCore.Client.AspNetCore;

internal sealed record SignaCoreVerifiedAccessToken(
    ClaimsPrincipal Principal, string Issuer, string Subject, DateTimeOffset ExpiresUtc);

// Internal callback validation for SignaCore PS-13 tokens, not a public Bearer validator.
internal sealed class SignaCoreAccessTokenValidator(
    IOptionsMonitor<SignaCoreHostedLoginOptions> options, TimeProvider timeProvider)
{
    private static readonly JsonWebTokenHandler Handler = new();

    internal async Task<SignaCoreVerifiedAccessToken?> ValidateAsync(
        SignaCoreAuthorityConfiguration configuration, string accessToken,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (accessToken.Length is < 1 or > 8192) return null;
        var segments = accessToken.Split('.');
        if (segments.Length != 3 || segments.Any(segment => segment.Length == 0
            || segment.Any(c => !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9') || c is '-' or '_')))) return null;

        try
        {
            using var header = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(segments[0]));
            using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(segments[1]));
            if (!ReadString(header.RootElement, "alg", out var alg) || alg != "RS256"
                || !ReadString(header.RootElement, "typ", out var typ) || typ != "at+jwt"
                || !ReadString(header.RootElement, "kid", out var kid)
                || !ReadString(payload.RootElement, "iss", out var issuer)
                || !string.Equals(issuer, configuration.Issuer, StringComparison.Ordinal)
                || !ReadString(payload.RootElement, "aud", out var audience)
                || !string.Equals(audience, options.CurrentValue.ClientId, StringComparison.Ordinal)
                || !ReadString(payload.RootElement, "sub", out var subject)
                || !ReadTime(payload.RootElement, "exp", out var expires)
                || !ReadTime(payload.RootElement, "nbf", out var notBefore)
                || !ReadTime(payload.RootElement, "iat", out var issued)) return null;

            var now = timeProvider.GetUtcNow();
            var skew = SignaCoreIdTokenValidator.ClockSkew;
            if (expires <= now || notBefore > expires || notBefore > now + skew || issued > now + skew) return null;
            var keys = configuration.SigningKeys.Where(key =>
                string.Equals(key.KeyId, kid, StringComparison.Ordinal)).ToArray();
            if (keys.Length == 0) return null;

            var result = await Handler.ValidateTokenAsync(accessToken, new TokenValidationParameters
            {
                ValidAlgorithms = ["RS256"], ValidTypes = ["at+jwt"],
                RequireSignedTokens = true, ValidateIssuerSigningKey = true,
                IssuerSigningKeys = keys, TryAllIssuerSigningKeys = false,
                ValidIssuer = issuer, ValidateIssuer = true,
                ValidAudience = audience, ValidateAudience = true,
                ValidateLifetime = true, RequireExpirationTime = true, ClockSkew = skew,
                LifetimeValidator = (_, _, _, _) => expires > timeProvider.GetUtcNow()
                    && notBefore <= timeProvider.GetUtcNow() + skew
                    && issued <= timeProvider.GetUtcNow() + skew
            });
            cancellationToken.ThrowIfCancellationRequested();
            return result.IsValid && result.ClaimsIdentity is { } identity
                ? new(new ClaimsPrincipal(identity), issuer, subject, expires) : null;
        }
        catch (Exception exception) when (exception is JsonException or ArgumentException
            or FormatException or SecurityTokenException)
        {
            return null;
        }
    }

    private static bool ReadSingle(JsonElement root, string name, out JsonElement value)
    {
        value = default;
        if (root.ValueKind != JsonValueKind.Object) return false;
        var matches = root.EnumerateObject().Where(property => property.NameEquals(name)).ToArray();
        if (matches.Length != 1) return false;
        value = matches[0].Value;
        return true;
    }

    private static bool ReadString(JsonElement root, string name, out string value)
    {
        value = string.Empty;
        if (!ReadSingle(root, name, out var element) || element.ValueKind != JsonValueKind.String)
            return false;
        value = element.GetString()!;
        return !string.IsNullOrWhiteSpace(value);
    }

    private static bool ReadTime(JsonElement root, string name, out DateTimeOffset value)
    {
        value = default;
        if (!ReadSingle(root, name, out var element) || element.ValueKind != JsonValueKind.Number
            || !element.TryGetInt64(out var seconds)) return false;
        value = DateTimeOffset.FromUnixTimeSeconds(seconds);
        return true;
    }
}
