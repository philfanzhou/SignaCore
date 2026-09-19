namespace SignaCore.Host.Startup;

/// <summary>
/// Console output for bootstrap configuration and first-run setup. The plaintext codes are printed
/// exactly once, to standard output, and are never written to the structured log pipeline — they
/// must not end up in Loki, a log archive, or an audit payload.
/// </summary>
internal static class StartupBanner
{
    public static void WriteBootstrapCredential(
        string credential,
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
            " Open /bootstrap in a browser and supply this credential exactly once:",
            "one-time bootstrap credential:",
            credential,
            string.Empty,
            $" The credential expires at {expiresAt:yyyy-MM-dd HH:mm:ss} UTC.",
            " It is shown only here. Restarting SignaCore issues a new credential",
            " and invalidates this one, which is how to recover if this output is lost.",
            "=============================================================="
        };

        foreach (var line in lines)
        {
            Console.Out.WriteLine(line);
        }

        Console.Out.Flush();
    }

    /// <summary>
    /// The fixed startup failure shown when the one-time bootstrap credential could not be
    /// (re)issued: the credential record is unusable, or another process won its creation. The
    /// record is never repaired or overwritten from here.
    /// </summary>
    public static void WriteBootstrapCredentialUnavailable(string credentialRecordPath)
    {
        var lines = new[]
        {
            string.Empty,
            "==============================================================",
            " SignaCore bootstrap configuration",
            "--------------------------------------------------------------",
            " The one-time bootstrap credential could not be issued.",
            $" Inspect or remove the credential record at:",
            $"     {credentialRecordPath}",
            " No credential plaintext is printed. SignaCore will not start without one.",
            "=============================================================="
        };

        foreach (var line in lines)
        {
            Console.Out.WriteLine(line);
        }

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
