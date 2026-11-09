using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace SignaCore.Database;

/// <summary>
/// The shared implementation behind <see cref="LoginHandleDigest"/>, <see cref="RefreshTokenDigest"/>,
/// <see cref="AuthorizationCodeDigest"/>, and the persisted digest of
/// <see cref="ManagementBearerToken"/>. Every persisted one-way secret digest is the versioned
/// <c>sha256:</c>-style notation of one lowercased SHA-256 hex hash, so the database holds a single
/// digest vocabulary and a future algorithm upgrade stays distinguishable per row.
/// </summary>
internal static class Sha256Digest
{
    public const string DefaultPrefix = "sha256:";

    /// <summary>
    /// The versioned digest of <paramref name="value"/>. <paramref name="valueParamName"/> is
    /// captured from the caller's argument expression so the validation guard reports the façade's
    /// public parameter name (<c>authorizationCode</c>, <c>loginHandle</c>, <c>token</c>) rather
    /// than this helper's <c>value</c>.
    /// </summary>
    public static string Compute(
        string prefix,
        string value,
        [CallerArgumentExpression(nameof(value))] string? valueParamName = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, valueParamName);
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return prefix + Convert.ToHexString(digest).ToLowerInvariant();
    }

    public static bool IsDigest(string value, string prefix, int encodedLength)
    {
        if (!value.StartsWith(prefix, StringComparison.Ordinal) ||
            value.Length != encodedLength)
        {
            return false;
        }

        foreach (var character in value.AsSpan(prefix.Length))
        {
            if (character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))
            {
                return false;
            }
        }

        return true;
    }

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
