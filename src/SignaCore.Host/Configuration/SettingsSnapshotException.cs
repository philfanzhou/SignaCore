namespace SignaCore.Host.Configuration;

/// <summary>
/// Raised when the stored configuration cannot produce a usable snapshot. The message lists the
/// offending keys but never their values, because the offending key may well be a secret.
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
