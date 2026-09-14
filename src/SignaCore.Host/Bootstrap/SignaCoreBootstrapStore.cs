using Microsoft.Extensions.Hosting;
using ServiceMantle;
using ServiceMantle.Bootstrap;
using ServiceMantle.Database.PostgreSql;
using ServiceMantle.Database.Sqlite;
using SignaCore.Database;
using SignaCore.Host.Installation;

namespace SignaCore.Host.Bootstrap;

/// <summary>
/// Reads the deployment bootstrap through the shared ServiceMantle bootstrap file store and maps
/// it onto SignaCore's database options.
/// </summary>
/// <remarks>
/// The file lifecycle (locate, parse, validate the schema, read atomically) belongs to
/// <see cref="BootstrapFileStore"/>; SignaCore keeps only what has no shared equivalent: the local
/// database-target rules applied to a loaded candidate and the Development appsettings fallback.
/// An absent file is not an error (Bootstrap Configuration Mode); a present but invalid one is
/// fatal, and failure messages identify paths and rules but never the connection string or the
/// master key.
/// </remarks>
internal static class SignaCoreBootstrapStore
{
    /// <summary>Optional host-level override of the bootstrap file location.</summary>
    public const string FilePathConfigurationKey = "Bootstrap:FilePath";

    public static string ResolveFilePath(IConfiguration configuration)
    {
        var configured = configuration[FilePathConfigurationKey];
        return BootstrapFileStore.ResolveFilePath(
            InstallationStores.ServiceId,
            string.IsNullOrWhiteSpace(configured) ? null : configured.Trim());
    }

    /// <summary>
    /// The store with both supported providers registered, for pre-composition reads and test
    /// setup. The DI-registered store (through <c>AddSignaCoreServiceMantle</c>) is equivalent.
    /// </summary>
    public static BootstrapFileStore Create(IConfiguration configuration) =>
        new(
            InstallationStores.ServiceId,
            CreateProviderRegistry(),
            ResolveFilePath(configuration));

    public static BootstrapDatabaseProviderRegistry CreateProviderRegistry() => new(
    [
        new PostgreSqlBootstrapDatabaseProvider(),
        new SqliteBootstrapDatabaseProvider()
    ]);

    /// <summary>
    /// Returns the validated bootstrap, or <c>null</c> when no bootstrap source exists at all. A
    /// <c>null</c> result is the signal to run Bootstrap Configuration Mode; anything malformed
    /// still throws.
    /// </summary>
    public static BootstrapConfiguration? TryLoad(
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        var store = Create(configuration);
        BootstrapConfiguration? loaded;
        try
        {
            loaded = store.TryLoad();
        }
        catch (ServiceMantle.Bootstrap.BootstrapException exception)
        {
            // The shared message already names only the path and the failing rule.
            throw new BootstrapException(exception.Message, exception);
        }

        if (loaded is null)
        {
            return environment.IsDevelopment()
                ? TryLoadDevelopmentFallback(configuration)
                : null;
        }

        return ValidateDatabaseTarget(store.FilePath, loaded);
    }

    /// <summary>
    /// Loads the bootstrap and fails when it is absent. Used by operator commands that cannot do
    /// anything useful without an already-configured database.
    /// </summary>
    public static BootstrapConfiguration Load(IConfiguration configuration, IHostEnvironment environment)
    {
        return TryLoad(configuration, environment)
            ?? throw new BootstrapException(
                $"The SignaCore bootstrap file was not found at '{ResolveFilePath(configuration)}'. " +
                "Start SignaCore and complete bootstrap configuration first.");
    }

    /// <summary>
    /// The local database-target rules SignaCore applies to every loaded candidate: the supported
    /// provider set, the PostgreSQL minimum version, the SQLite shape, and the host/database
    /// requirements. The shared store validates the file schema; these rules stay with the
    /// consumer because they decide what this process can actually open.
    /// </summary>
    public static BootstrapConfiguration ValidateDatabaseTarget(
        string filePath,
        BootstrapConfiguration configuration)
    {
        try
        {
            ToDatabaseOptions(configuration.Database).Validate();
        }
        catch (InvalidOperationException exception)
        {
            throw new BootstrapException(
                $"The database configuration in '{filePath}' is invalid: {exception.Message}",
                exception);
        }

        return configuration;
    }

    public static DatabaseOptions ToDatabaseOptions(BootstrapDatabaseConfiguration database) => new()
    {
        Provider = database.Provider,
        ServerVersion = database.ServerVersion,
        ConnectionString = database.ConnectionString
    };

    private static BootstrapConfiguration? TryLoadDevelopmentFallback(IConfiguration configuration)
    {
        var section = configuration.GetSection(DatabaseOptions.SectionName);
        if (!section.GetChildren().Any())
        {
            // Nothing to fall back to; Development gets the same bootstrap configuration UI a
            // production deployment gets.
            return null;
        }

        var database = section.Get<DatabaseOptions>()
            ?? throw new BootstrapException(
                "The Development Database section could not be bound.");

        try
        {
            database.Validate();
        }
        catch (InvalidOperationException exception)
        {
            throw new BootstrapException(
                $"The Development database configuration is invalid: {exception.Message}",
                exception);
        }

        // Development keeps accepting the legacy environment variable so an existing developer
        // database stays decryptable; when neither is present a throwaway secret is derived from the
        // connection target, which is stable across restarts of the same developer machine.
        var rootSecret = Environment.GetEnvironmentVariable("RSA_MASTER_KEY");
        if (string.IsNullOrWhiteSpace(rootSecret))
        {
            rootSecret = $"development-root-secret::{database.Provider}::{database.ConnectionString}";
        }

        // A fallback configuration is memory-backed: SourcePath stays null, which is exactly the
        // signal the admin bootstrap editor uses to refuse writing the file on this host.
        return new BootstrapConfiguration(
            InstallationStores.ServiceId,
            new BootstrapDatabaseConfiguration(database.Provider, database.ServerVersion, database.ConnectionString),
            rootSecret);
    }
}

/// <summary>
/// Fatal bootstrap failure. Messages are safe to log: they identify paths and the failing rule, and
/// never contain the connection string or the master key.
/// </summary>
internal sealed class BootstrapException : Exception
{
    public BootstrapException(string message) : base(message)
    {
    }

    public BootstrapException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
