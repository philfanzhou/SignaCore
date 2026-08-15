namespace SignaCore.Host.Startup;

/// <summary>
/// Console output for bootstrap configuration and first-run setup. The plaintext codes are printed
/// exactly once, to standard output, and are never written to the structured log pipeline — they
/// must not end up in Loki, a log archive, or an audit payload.
/// </summary>
internal static class StartupBanner
{
    public static void WriteBootstrapCode(
        string code,
        string bootstrapFilePath,
        DateTimeOffset expiresAt)
    {
        var lines = new[]
        {
            string.Empty,
            "==============================================================",
            " SignaCore bootstrap configuration",
            "--------------------------------------------------------------",
            " No bootstrap file was found at:",
            $"     {bootstrapFilePath}",
            string.Empty,
            " Open /bootstrap in a browser and enter the one-time code:",
            string.Empty,
            $"     {code}",
            string.Empty,
            $" The code expires at {expiresAt:yyyy-MM-dd HH:mm:ss} UTC.",
            " The code lives only in this process. Restarting SignaCore issues",
            " a new one, which is how to recover if this output is lost.",
            "=============================================================="
        };

        foreach (var line in lines)
        {
            Console.Out.WriteLine(line);
        }

        Console.Out.Flush();
    }

    public static void WriteBootstrapModeNotice()
    {
        Console.Out.WriteLine(
            "SignaCore is running in Bootstrap Configuration Mode. Only /bootstrap, /api/bootstrap/*, " +
            "and health endpoints are available; every other API returns " +
            "503 bootstrap_configuration_required.");
        Console.Out.Flush();
    }

    public static void WriteSetupCode(string code, DateTimeOffset expiresAt)
    {
        var lines = new[]
        {
            string.Empty,
            "==============================================================",
            " SignaCore first-run setup",
            "--------------------------------------------------------------",
            " This database has not been initialized yet.",
            " Open /setup in a browser and enter the one-time setup code:",
            string.Empty,
            $"     {code}",
            string.Empty,
            $" The code expires at {expiresAt:yyyy-MM-dd HH:mm:ss} UTC.",
            " It is shown only once. To issue a new one, run:",
            "     dotnet SignaCore.Host.dll --rotate-setup-code",
            "=============================================================="
        };

        foreach (var line in lines)
        {
            Console.Out.WriteLine(line);
        }

        Console.Out.Flush();
    }

    public static void WriteSetupModeNotice()
    {
        Console.Out.WriteLine(
            "SignaCore is running in Setup Mode. Only /setup, /api/setup/*, and health endpoints " +
            "are available; every other API returns 503 installation_required.");
        Console.Out.Flush();
    }

    /// <summary>
    /// Manually launched processes have no supervisor to restart them, so say so explicitly rather
    /// than exiting silently after setup succeeds.
    /// </summary>
    public static void WriteRestartInstruction()
    {
        Console.Out.WriteLine(
            "Configuration saved. SignaCore is stopping so it can restart into the next phase. " +
            "If no supervisor (Docker restart policy, systemd, Kubernetes) manages this process, " +
            "start SignaCore again.");
        Console.Out.Flush();
    }
}
