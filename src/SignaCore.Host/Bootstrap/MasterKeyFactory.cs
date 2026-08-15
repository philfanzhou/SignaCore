using System.Security.Cryptography;

namespace SignaCore.Host.Bootstrap;

/// <summary>
/// Generates the external root key for a new installation.
/// <para>
/// Operators do not invent this value. It is the root of trust for every stored RSA signing private
/// key and every encrypted system setting, so its entropy is not a place to accept a passphrase.
/// </para>
/// </summary>
internal static class MasterKeyFactory
{
    /// <summary>256 bits, matching the derived key size the protectors use.</summary>
    private const int KeySizeBytes = 32;

    /// <summary>
    /// Base64url without padding, so the value survives being copied through shells, YAML, and
    /// environment files without quoting or escaping surprises.
    /// </summary>
    public static string Generate() =>
        Base64UrlEncode(RandomNumberGenerator.GetBytes(KeySizeBytes));

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
