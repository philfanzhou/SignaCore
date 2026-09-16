using System.Security.Cryptography;
using SignaCore.Database;

namespace SignaCore.Domain.Services;

/// <summary>
/// A per-process BCrypt hash of a random secret, used as the constant decoy workload of
/// <see cref="Validators.PasswordValidator"/>: every request that reaches the validator with a
/// non-empty username and password performs exactly one BCrypt verification — against the stored
/// hash when the credential exists and the account is usable, and against this decoy otherwise —
/// so the login failure timing no longer reveals whether the account exists, is disabled, or is
/// locked.
/// <para>
/// The value is generated once per process from 32 bytes of CSPRNG output, is never persisted,
/// logged, or exposed, and deliberately does not override <see cref="object.ToString"/>. It is
/// produced directly through BCrypt rather than <see cref="IPasswordHasher.HashPassword"/> so a
/// strictly mocked hasher needs no expectation for the generation.
/// </para>
/// </summary>
public sealed class PasswordDecoyHash
{
    private readonly Lazy<string> _value;

    public PasswordDecoyHash(PasswordHasherOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _value = new Lazy<string>(
            () => BCrypt.Net.BCrypt.HashPassword(GenerateSeed(), options.WorkFactor),
            LazyThreadSafetyMode.ExecutionAndPublication);
    }

    /// <summary>The process-wide decoy hash; the first reader pays the one-time generation cost.</summary>
    public string Value => _value.Value;

    private static string GenerateSeed()
    {
        Span<byte> entropy = stackalloc byte[32];
        RandomNumberGenerator.Fill(entropy);
        return Convert.ToBase64String(entropy);
    }
}
