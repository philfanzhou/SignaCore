using System.Security.Cryptography;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The shared shape of the opaque random values this package generates (session keys, pending
/// sign-in states and browser bindings, logout correlation ids): 256 bits of CSPRNG output
/// rendered as exactly 43 unpadded base64url characters.
/// </summary>
internal static class OpaqueToken
{
    internal static string Generate()
    {
        Span<byte> entropy = stackalloc byte[32];
        RandomNumberGenerator.Fill(entropy);
        return Convert.ToBase64String(entropy).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
