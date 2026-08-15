using System.Text.Json;
using System.Text.Json.Serialization;
using SignaCore.Database;

namespace SignaCore.Host.Bootstrap;

/// <summary>
/// Reads and strictly validates the writable bootstrap file.
/// <para>
/// The production path is fixed — <c>&lt;application-base&gt;/config/signacore.bootstrap.json</c>, which
/// is <c>/app/config/signacore.bootstrap.json</c> in the container — so no additional environment
/// variable or command-line argument is required to deploy.
/// </para>
/// <para>
/// An <em>absent</em> file is not an error: the host starts Bootstrap Configuration Mode and offers
/// to create it. A <em>present but invalid</em> file is fatal, because silently ignoring a bootstrap
/// an operator did write would be indistinguishable from pointing the service at the wrong database.
/// Failure messages identify paths and the failing rule; they never echo the connection string or
/// the root key.
/// </para>
/// <para>
/// Development and test hosts may point <see cref="FilePathConfigurationKey"/> at an equivalent
/// file. Development additionally falls back to the <c>Database</c> section of appsettings so a
/// clone-and-run developer setup keeps working; that fallback is refused outside Development.
/// </para>
/// </summary>
internal static class BootstrapLoader
{
    public const string DirectoryName = "config";
    public const string FileName = "signacore.bootstrap.json";

    /// <summary>Optional host-level override of the bootstrap file location.</summary>
    public const string FilePathConfigurationKey = "Bootstrap:FilePath";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public static string ResolveFilePath(IConfiguration configuration)
    {
        var configured = configuration[FilePathConfigurationKey];
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return Path.GetFullPath(configured.Trim());
        }

        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, DirectoryName, FileName));
    }

    /// <summary>
    /// Returns the validated bootstrap, or <c>null</c> when no bootstrap source exists at all. A
    /// <c>null</c> result is the signal to run Bootstrap Configuration Mode; anything malformed still
    /// throws.
    /// </summary>
    public static BootstrapConfiguration? TryLoad(
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        var filePath = ResolveFilePath(configuration);

        if (!File.Exists(filePath))
        {
            return environment.IsDevelopment()
                ? TryLoadDevelopmentFallback(configuration)
                : null;
        }

        return LoadFile(filePath);
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

    private static BootstrapConfiguration LoadFile(string filePath)
    {
        string json;
        try
        {
            json = File.ReadAllText(filePath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new BootstrapException(
                $"The SignaCore bootstrap file at '{filePath}' could not be read: {exception.Message}",
                exception);
        }

        BootstrapFile? file;
        try
        {
            file = JsonSerializer.Deserialize<BootstrapFile>(json, SerializerOptions);
        }
        catch (JsonException exception)
        {
            // The parser message may quote the offending value, so only the location is reported.
            throw new BootstrapException(
                $"The SignaCore bootstrap file at '{filePath}' is not valid JSON " +
                $"(line {exception.LineNumber}, position {exception.BytePositionInLine}).");
        }

        if (file is null)
        {
            throw new BootstrapException(
                $"The SignaCore bootstrap file at '{filePath}' is empty.");
        }

        var database = BuildDatabaseOptions(file.Database, filePath);
        var rootSecret = ResolveRootSecret(file, filePath);

        return new BootstrapConfiguration(database, rootSecret, filePath);
    }

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

        return new BootstrapConfiguration(database, rootSecret, "Development appsettings fallback");
    }

    private static DatabaseOptions BuildDatabaseOptions(
        BootstrapDatabaseSection? section,
        string filePath)
    {
        if (section is null)
        {
            throw new BootstrapException(
                $"The SignaCore bootstrap file at '{filePath}' is missing the required " +
                "'Database' object.");
        }

        if (string.IsNullOrWhiteSpace(section.Provider))
        {
            throw new BootstrapException(
                $"The SignaCore bootstrap file at '{filePath}' is missing 'Database.Provider'. " +
                "Supported values are PostgreSQL, MySQL, MariaDB, and SQLite.");
        }

        if (string.IsNullOrWhiteSpace(section.ConnectionString))
        {
            throw new BootstrapException(
                $"The SignaCore bootstrap file at '{filePath}' is missing " +
                "'Database.ConnectionString'.");
        }

        var options = new DatabaseOptions
        {
            Provider = section.Provider.Trim(),
            ServerVersion = string.IsNullOrWhiteSpace(section.ServerVersion)
                ? null
                : section.ServerVersion.Trim(),
            ConnectionString = section.ConnectionString.Trim()
        };

        try
        {
            options.Validate();
        }
        catch (InvalidOperationException exception)
        {
            throw new BootstrapException(
                $"The database configuration in '{filePath}' is invalid: {exception.Message}",
                exception);
        }

        return options;
    }

    private static string ResolveRootSecret(BootstrapFile file, string filePath)
    {
        // A file hand-edited or produced by a templating tool commonly picks up a trailing newline
        // or padding; trimming keeps the derived key identical whichever way it was written.
        var rootSecret = file.MasterKey?.Trim();

        if (string.IsNullOrEmpty(rootSecret))
        {
            throw new BootstrapException(
                $"The SignaCore bootstrap file at '{filePath}' is missing 'MasterKey'. " +
                "The external root key is stored inline; there is no separate key file.");
        }

        return rootSecret;
    }
}

/// <summary>
/// Fatal bootstrap failure. Messages are safe to log: they identify paths and the failing rule, and
/// never contain the connection string or the root key.
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
