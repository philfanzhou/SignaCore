using System.Security.Cryptography;
using System.Text;

namespace SignaCore.Database;

/// <summary>
/// Converts one-time authorization code values into the one-way value persisted in
/// <c>authorization_codes.code_digest</c>. The representation is deliberately the same versioned
/// <c>sha256:</c> notation <see cref="LoginHandleDigest"/> and <see cref="RefreshTokenDigest"/>
/// use, so the database holds a single digest vocabulary and a future algorithm upgrade stays
/// distinguishable per row. The plaintext code is returned to the caller exactly once at creation
/// and is never persisted, logged, or accepted back in this form (<c>DF-03</c>).
/// </summary>
public static class AuthorizationCodeDigest
{
    public const string Prefix = "sha256:";
    public const int EncodedLength = 71;

    public static string Compute(string authorizationCode)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authorizationCode);
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(authorizationCode));
        return Prefix + Convert.ToHexString(digest).ToLowerInvariant();
    }

    public static bool IsDigest(string value)
    {
        if (!value.StartsWith(Prefix, StringComparison.Ordinal) ||
            value.Length != EncodedLength)
        {
            return false;
        }

        foreach (var character in value.AsSpan(Prefix.Length))
        {
            if (character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))
            {
                return false;
            }
        }

        return true;
    }

    public static string EnsureDigest(string value) => IsDigest(value) ? value : Compute(value);

    /// <summary>
    /// Constant-time comparison of two encoded digests. The database index answers the lookup; this
    /// gate decides whether a fetched row is released to the caller, so the release decision never
    /// depends on a short-circuiting string comparison.
    /// </summary>
    public static bool Matches(string computedDigest, string storedDigest)
    {
        ArgumentNullException.ThrowIfNull(computedDigest);
        ArgumentNullException.ThrowIfNull(storedDigest);

        if (computedDigest.Length != storedDigest.Length)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(computedDigest),
            Encoding.ASCII.GetBytes(storedDigest));
    }
}
