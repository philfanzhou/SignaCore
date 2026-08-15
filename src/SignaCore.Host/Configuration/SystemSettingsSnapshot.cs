namespace SignaCore.Host.Configuration;

/// <summary>
/// One coherent view of <c>system_settings</c>. Snapshots are validated as a whole before they are
/// activated, so a partially valid configuration never becomes the running configuration.
/// </summary>
/// <param name="Version">The <c>configuration_version</c> this snapshot was read at.</param>
/// <param name="Values">Decrypted setting values keyed by setting key.</param>
/// <param name="ConfigurationEntries">
/// The same settings expanded into ASP.NET Core configuration keys, ready to be layered onto
/// <c>IConfiguration</c>.
/// </param>
internal sealed record SystemSettingsSnapshot(
    int Version,
    IReadOnlyDictionary<string, string> Values,
    IReadOnlyDictionary<string, string?> ConfigurationEntries)
{
    public string? Get(string key) => Values.TryGetValue(key, out var value) ? value : null;
}

/// <summary>
/// Raised when the stored settings cannot produce a usable snapshot. The message lists the offending
/// keys but never their values, because the offending key may well be a secret.
/// </summary>
internal sealed class SettingsSnapshotException : Exception
{
    public SettingsSnapshotException(string message, IReadOnlyList<string> keys)
        : base(message)
    {
        Keys = keys;
    }

    public SettingsSnapshotException(string message, IReadOnlyList<string> keys, Exception innerException)
        : base(message, innerException)
    {
        Keys = keys;
    }

    public IReadOnlyList<string> Keys { get; }
}
