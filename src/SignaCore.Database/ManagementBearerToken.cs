using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace SignaCore.Database;

/// <summary>
/// The shape and digest of a management bearer credential (#360): <c>scm1.</c> followed by 32
/// random bytes as unpadded base64url, 48 characters in total. Only
/// <c>sha256:</c> + lowercase hex of the complete versioned credential is persisted in
/// <c>management_bearer_sessions.token_digest</c>; the plaintext is returned to the caller once
/// at issuance and never stored or logged.
/// </summary>
public static class ManagementBearerToken
{
    public const string Prefix = "scm1.";
    public const int SecretBytes = 32;
    public const int Length = 48;
    public const string DigestPrefix = "sha256:";
    public const int DigestLength = 71;

    public static string Generate()
    {
        Span<byte> secret = stackalloc byte[SecretBytes];
        RandomNumberGenerator.Fill(secret);
        try
        {
            return Prefix + Base64Url.EncodeToString(secret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <summary>
    /// Whether <paramref name="value"/> is exactly one canonical credential: the ordinal prefix, and
    /// a body that decodes to exactly 32 bytes and re-encodes to the identical text. Padding,
    /// whitespace, non-canonical trailing bits, and a stored digest all fail.
    /// </summary>
    public static bool IsWellFormed(string? value)
    {
        if (value is not { Length: Length } || !value.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        // The status-returning overload reports foreign characters, padding, whitespace, and
        // non-zero trailing bits as invalid data instead of throwing; the re-encoding comparison
        // keeps canonical form the acceptance rule regardless of decoder leniency.
        var body = value.AsSpan(Prefix.Length);
        Span<byte> secret = stackalloc byte[SecretBytes + 3];
        Span<char> canonical = stackalloc char[Length - Prefix.Length];
        try
        {
            return Base64Url.DecodeFromChars(body, secret, out var consumed, out var written) == OperationStatus.Done
                && consumed == body.Length
                && written == SecretBytes
                && Base64Url.TryEncodeToChars(secret[..SecretBytes], canonical, out var encoded)
                && body.SequenceEqual(canonical[..encoded]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <summary>The persisted digest of a well-formed credential.</summary>
    public static string ComputeDigest(string token)
    {
        if (!IsWellFormed(token))
        {
            throw new ArgumentException("The value is not a management bearer credential.", nameof(token));
        }

        return DigestPrefix + Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(token)));
    }
}
