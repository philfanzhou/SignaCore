using System.Security.Cryptography;
using System.Text;

namespace SignaCore.Database;

/// <summary>
/// Converts bearer refresh-token secrets into the one-way value persisted in the database.
/// The version prefix makes the representation distinguishable from legacy plaintext rows and
/// leaves room for a future digest upgrade without invalidating every active session.
/// </summary>
public static class RefreshTokenDigest
{
    public const string Prefix = "sha256:";
    public const string PublicFamilyPrefix = "sha256-public:";
    public const int EncodedLength = 71;

    public static string Compute(string token)
        => ComputeWithPrefix(token, Prefix);

    /// <summary>
    /// A distinct persisted digest version for newly issued Public interactive families. Older
    /// binaries know only <see cref="Prefix"/> and therefore cannot rotate these credentials
    /// after a rollback. The input remains the same opaque bearer and is never stored.
    /// </summary>
    public static string ComputePublicFamily(string token)
        => ComputeWithPrefix(token, PublicFamilyPrefix);

    private static string ComputeWithPrefix(string token, string prefix)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return prefix + Convert.ToHexString(digest).ToLowerInvariant();
    }

    public static bool IsDigest(string value)
    {
        var prefix = value.StartsWith(PublicFamilyPrefix, StringComparison.Ordinal)
            ? PublicFamilyPrefix : Prefix;
        if (!value.StartsWith(prefix, StringComparison.Ordinal) ||
            value.Length != prefix.Length + 64)
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

    public static string EnsureDigest(string value) => IsDigest(value) ? value : Compute(value);
}
