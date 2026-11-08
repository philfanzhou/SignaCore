using System.Security.Cryptography;

namespace SignaCore.Domain.Services;

/// <summary>
/// The shared shape of the opaque one-time credentials this host issues: 256 bits of CSPRNG
/// output rendered as exactly 43 unpadded base64url characters — the canonical handle, code,
/// and refresh-token shape by construction, never by post-hoc filtering.
/// </summary>
internal static class OpaqueToken
{
    public static string Generate()
    {
        Span<byte> entropy = stackalloc byte[32];
        RandomNumberGenerator.Fill(entropy);
        return Convert.ToBase64String(entropy)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    /// <summary>
    /// Exactly <paramref name="length"/> ASCII base64url characters (<c>[A-Za-z0-9_-]</c>) — the
    /// only characters <c>Generate</c> can produce and the exact shape a stored
    /// <c>BASE64URL(SHA256(...))</c> challenge can have.
    /// </summary>
    public static bool IsShape(string? value, int length)
    {
        return value is not null
            && value.Length == length
            && value.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
    }
}
