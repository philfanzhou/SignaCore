using System.Security.Cryptography;
using System.Text;

namespace SignaCore.Database;

/// <summary>
/// Converts one-time <c>login_handle</c> values into the one-way value persisted in
/// <c>authorization_requests.handle_digest</c>. The representation is deliberately the same
/// versioned <c>sha256:</c> notation <see cref="RefreshTokenDigest"/> uses, so the database holds a
/// single digest vocabulary and a future algorithm upgrade stays distinguishable per row.
/// The plaintext handle is returned to the caller exactly once at creation and is never persisted,
/// logged, or accepted back in this form (<c>DF-05</c>).
/// </summary>
public static class LoginHandleDigest
{
    public const string Prefix = "sha256:";
    public const int EncodedLength = 71;

    public static string Compute(string loginHandle)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(loginHandle);
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(loginHandle));
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
