using ServiceMantle.Bootstrap;
using SignaCore.Host.Installation;
using SignaCore.Host.Startup;

namespace SignaCore.Host.Bootstrap;

/// <summary>The outcome of the startup credential provisioning decision.</summary>
internal enum BootstrapCredentialStartupOutcome
{
    /// <summary>A fresh credential was issued and printed once; run Bootstrap Configuration Mode.</summary>
    Provisioned,

    /// <summary>
    /// A bootstrap file appeared between the startup load and the reissue; continue as a
    /// configured instance instead of entering Bootstrap Configuration Mode.
    /// </summary>
    AlreadyConfigured,

    /// <summary>
    /// The credential record is unusable, or another process won the exclusive creation and holds
    /// the only plaintext. Startup fails without printing a credential.
    /// </summary>
    Failed
}

/// <summary>
/// The provisioning decision plus, when provisioned, the store the mode host registers for the
/// shared creation entry and the read-only probe.
/// </summary>
/// <param name="Outcome">The decision.</param>
/// <param name="Store">The store to register; null unless provisioned.</param>
internal sealed record BootstrapCredentialStartup(
    BootstrapCredentialStartupOutcome Outcome,
    BootstrapCredentialFileStore? Store)
{
    public static BootstrapCredentialStartup Provisioned(BootstrapCredentialFileStore store) =>
        new(BootstrapCredentialStartupOutcome.Provisioned, store);

    public static BootstrapCredentialStartup AlreadyConfigured() =>
        new(BootstrapCredentialStartupOutcome.AlreadyConfigured, null);

    public static BootstrapCredentialStartup Failed() =>
        new(BootstrapCredentialStartupOutcome.Failed, null);
}

/// <summary>
/// Reissues and prints the one-time bootstrap credential every Bootstrap-mode start needs.
/// </summary>
/// <remarks>
/// The record lives beside the bootstrap file, so an explicit bootstrap file location also moves
/// the credential record and two instances with separate bootstrap files never share a record.
/// The plaintext appears exactly once, on standard output, and only on the provisioned path; the
/// fixed failure notice names the record path and never a credential.
/// </remarks>
internal static class BootstrapCredentialProvisioner
{
    public static async Task<BootstrapCredentialStartup> ProvisionAsync(string bootstrapFilePath)
    {
        var store = CreateStore(bootstrapFilePath);
        var outcome = await ProvisionAsync(
            store,
            store.FilePath,
            bootstrapFilePath);
        return outcome == BootstrapCredentialStartupOutcome.Provisioned
            ? BootstrapCredentialStartup.Provisioned(store)
            : outcome is BootstrapCredentialStartupOutcome.AlreadyConfigured
                ? BootstrapCredentialStartup.AlreadyConfigured()
                : BootstrapCredentialStartup.Failed();
    }

    /// <summary>
    /// The decision over a caller-supplied reissuer, so the closed rejection outcomes can be
    /// observed without winning a real exclusive-creation race.
    /// </summary>
    internal static async Task<BootstrapCredentialStartupOutcome> ProvisionAsync(
        IBootstrapCredentialReissuer reissuer,
        string credentialRecordPath,
        string bootstrapFilePath)
    {
        ArgumentNullException.ThrowIfNull(reissuer);

        var reissue = await reissuer.ReissueAsync(BootstrapCredentialLifetime.Default);

        if (reissue.IsProvisioned)
        {
            StartupBanner.WriteBootstrapCredential(
                reissue.Credential!.Reveal(),
                bootstrapFilePath,
                reissue.ExpiresAtUtc!.Value);
            return BootstrapCredentialStartupOutcome.Provisioned;
        }

        if (reissue.ErrorCode == WellKnownBootstrapCredentialErrorCodes.BootstrapConfigured)
        {
            return BootstrapCredentialStartupOutcome.AlreadyConfigured;
        }

        // 'unavailable' and 'already_exists' both stop here: the record is never repaired or
        // overwritten, and no credential plaintext exists in this process to print.
        StartupBanner.WriteBootstrapCredentialUnavailable(credentialRecordPath);
        return BootstrapCredentialStartupOutcome.Failed;
    }

    /// <summary>
    /// The store over the credential record that sits beside the bootstrap file. With the default
    /// bootstrap location this is exactly the shared store's own default record path.
    /// </summary>
    public static BootstrapCredentialFileStore CreateStore(string bootstrapFilePath)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(bootstrapFilePath));
        var recordPath = string.IsNullOrEmpty(directory)
            ? null
            : Path.Combine(directory, $"{InstallationStores.ServiceIdValue}.bootstrap-credential.json");
        return new BootstrapCredentialFileStore(
            InstallationStores.ServiceId,
            recordPath,
            bootstrapFilePath);
    }
}
