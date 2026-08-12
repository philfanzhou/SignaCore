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
    public const int EncodedLength = 71;

    public static string Compute(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(token));
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
}
