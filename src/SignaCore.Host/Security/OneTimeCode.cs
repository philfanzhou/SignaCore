using System.Security.Cryptography;
using System.Text;

namespace SignaCore.Host.Security;

/// <summary>
/// Generation, hashing, and constant-time verification of the one-time codes that gate the two
/// unauthenticated write surfaces: bootstrap configuration and first-run setup.
/// <para>
/// An unprotected "first visitor wins" flow is forbidden for both, because either page is reachable
/// by anyone who can reach the service at all, and SignaCore is deliberately agnostic about whether
/// that is the public Internet, a private network, or a container network. The plaintext is printed
/// once to standard output and only its hash is retained.
/// </para>
/// </summary>
internal static class OneTimeCode
{
    /// <summary>
    /// Thirty independent selections from a 32-character alphabet yield 150 bits of entropy.
    /// </summary>
    private const int CodeSizeBytes = 30;

    public static string Generate()
    {
        // Base32-style alphabet without look-alike characters, so an operator can retype the code
        // from a terminal without ambiguity.
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        var bytes = RandomNumberGenerator.GetBytes(CodeSizeBytes);
        var builder = new StringBuilder(CodeSizeBytes + CodeSizeBytes / 4);

        for (var index = 0; index < bytes.Length; index++)
        {
            if (index > 0 && index % 5 == 0)
            {
                builder.Append('-');
            }

            builder.Append(alphabet[bytes[index] % alphabet.Length]);
        }

        return builder.ToString();
    }

    public static string Hash(string code) =>
        Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(Normalize(code))));

    /// <summary>Constant-time comparison, so a wrong code leaks no prefix information.</summary>
    public static bool Verify(string? candidate, string? expectedHash)
    {
        if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(expectedHash))
        {
            return false;
        }

        byte[] expected;
        try
        {
            expected = Convert.FromBase64String(expectedHash);
        }
        catch (FormatException)
        {
            return false;
        }

        var actual = SHA256.HashData(Encoding.UTF8.GetBytes(Normalize(candidate)));
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>
    /// Accepts the code however the operator retyped it: case, whitespace, and the display hyphens
    /// are not part of the secret.
    /// </summary>
    private static string Normalize(string code)
    {
        var builder = new StringBuilder(code.Length);
        foreach (var character in code)
        {
            if (char.IsLetterOrDigit(character))
            {
                builder.Append(char.ToUpperInvariant(character));
            }
        }

        return builder.ToString();
    }
}
