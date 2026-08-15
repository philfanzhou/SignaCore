using SignaCore.Host.Security;

namespace SignaCore.Host.Installation;

/// <summary>
/// The one-time proof that whoever is completing first-run setup can inspect the deployment.
/// <para>
/// Unlike the bootstrap code, this one has to survive a restart — the operator may not reach the
/// setup page during the first minute the container is up — so its hash and expiry are stored on the
/// <c>installation_state</c> row. It is ephemeral state, not an application setting, so it never
/// appears in the bootstrap file, and the plaintext is printed once to standard output.
/// </para>
/// </summary>
internal static class SetupCode
{
    public static TimeSpan DefaultLifetime => TimeSpan.FromHours(24);

    public static string Generate() => OneTimeCode.Generate();

    public static string Hash(string code) => OneTimeCode.Hash(code);

    public static bool Verify(string? candidate, string? expectedHash) =>
        OneTimeCode.Verify(candidate, expectedHash);
}
