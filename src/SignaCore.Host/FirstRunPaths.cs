namespace SignaCore.Host;

/// <summary>
/// Route paths of the first-run surfaces that exist before an installation is complete.
/// </summary>
internal static class FirstRunPaths
{
    /// <summary>
    /// The SPA route Setup Mode serves while the installation is pending. Once installation
    /// completes and the process restarts, the normal host redirects this path to the console
    /// instead.
    /// </summary>
    public const string Setup = "/setup";

    /// <summary>
    /// The SPA route Bootstrap Configuration Mode serves while no bootstrap file exists. After the
    /// file is published and the process restarts, the normal host redirects this path to the
    /// console instead.
    /// </summary>
    public const string Bootstrap = "/bootstrap";
}
