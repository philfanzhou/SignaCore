namespace SignaCore.Database.RateLimiting;

/// <summary>
/// The fixed per-window permit budget of every interactive OIDC rate-limit policy. The names
/// match the host's policy names and the <c>oidc_rate_limit_buckets</c> policy check constraint.
/// </summary>
public static class OidcRateLimitBudgets
{
    private static readonly IReadOnlyDictionary<string, int> PermitLimits =
        new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["oidc-authorize"] = IdentityConstants.OidcAuthorizeRateLimitPerMinute,
            ["oidc-login"] = IdentityConstants.OidcLoginRateLimitPerMinute,
            ["oidc-token"] = IdentityConstants.OidcTokenRateLimitPerMinute,
            ["oidc-userinfo"] = IdentityConstants.OidcUserInfoRateLimitPerMinute,
            ["oidc-logout"] = IdentityConstants.OidcLogoutRateLimitPerMinute,
            ["oidc-revoke"] = IdentityConstants.OidcRevokeRateLimitPerMinute
        };

    public static IEnumerable<string> Policies => PermitLimits.Keys;

    public static bool TryGetPermitLimit(string? policy, out int permitLimit) =>
        PermitLimits.TryGetValue(policy ?? string.Empty, out permitLimit);

    /// <summary>Whether <paramref name="value"/> is exactly 64 lowercase hex characters.</summary>
    public static bool IsPartitionDigest(string? value)
    {
        if (value is not { Length: 64 })
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!char.IsAsciiDigit(character) && character is not (>= 'a' and <= 'f'))
            {
                return false;
            }
        }

        return true;
    }
}
