namespace SignaCore.Tests.Integration;

/// <summary>
/// The shared SQLite target preparation contract rejects symlinked path components, and macOS
/// exposes the per-user temp directory under <c>/var</c>, a symlink to <c>/private/var</c>:
/// integration tests that run the real startup preparation need the physical location so they
/// exercise the contract instead of the platform's symlink.
/// </summary>
internal static class PhysicalTempPath
{
    public static string Root()
    {
        var temp = Path.GetTempPath();
        if (temp.StartsWith("/var/", StringComparison.Ordinal) && Directory.Exists("/private" + temp))
        {
            return "/private" + temp;
        }

        return temp;
    }
}
