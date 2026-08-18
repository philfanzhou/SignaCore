using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using SignaCore.Database;
using SignaCore.Host.Bootstrap;
using Xunit;

namespace SignaCore.Tests.Host.Bootstrap;

public sealed class BootstrapLoaderTests : IDisposable
{
    private const string ConnectionString =
        "Host=db.internal;Database=signacore;Username=signacore;Password=super-secret-password";
    private const string RootSecret = "a-long-random-root-secret-value";

    private readonly string _directory;

    public BootstrapLoaderTests()
    {
        _directory = Path.Combine(Path.GetTempPath(), $"signacore-bootstrap-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_directory);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Fact]
    public void Load_WithInlineMasterKey_ReturnsValidatedBootstrap()
    {
        var path = WriteBootstrap($$"""
            {
              "Database": {
                "Provider": "PostgreSQL",
                "ServerVersion": "15",
                "ConnectionString": "{{ConnectionString}}"
              },
              "MasterKey": "{{RootSecret}}"
            }
            """);

        var bootstrap = BootstrapLoader.Load(Configuration(path), Environment(Environments.Production));

        Assert.Equal(DatabaseProvider.PostgreSql, bootstrap.Database.ProviderKind);
        Assert.Equal(ConnectionString, bootstrap.Database.ConnectionString);
        Assert.Equal(RootSecret, bootstrap.RootSecret);
    }

    [Fact]
    public void Load_WithMissingFileInProduction_FailsWithTheExpectedAbsolutePath()
    {
        var expected = Path.Combine(_directory, BootstrapLoader.FileName);

        var exception = Assert.Throws<BootstrapException>(() =>
            BootstrapLoader.Load(Configuration(expected), Environment(Environments.Production)));

        Assert.Contains(expected, exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The JSON parser quotes the offending value in its own message, which for this file is a
    /// connection string or a root key. Only the location may be reported.
    /// </summary>
    [Fact]
    public void Load_WithMalformedJson_ReportsLocationWithoutLeakingSecrets()
    {
        var path = WriteBootstrap($$"""
            {
              "Database": { "Provider": "PostgreSQL", "ConnectionString": "{{ConnectionString}}" },
              "MasterKey": "{{RootSecret}}",
            """);

        var exception = Assert.Throws<BootstrapException>(() =>
            BootstrapLoader.Load(Configuration(path), Environment(Environments.Production)));

        Assert.DoesNotContain("super-secret-password", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(RootSecret, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_WithoutInlineMasterKey_Fails()
    {
        var path = WriteBootstrap(
            """{ "Database": { "Provider": "PostgreSQL", "ServerVersion": "15", "ConnectionString": "Host=db;Database=x;Username=u" } }""");

        var exception = Assert.Throws<BootstrapException>(() =>
            BootstrapLoader.Load(Configuration(path), Environment(Environments.Production)));

        Assert.Contains("MasterKey", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{ "Database": { "Provider": "PostgreSQL", "ServerVersion": "15", "ConnectionString": "Host=db;Database=x;Username=u" }, "MasterKey": "k", "MasterKeyFile": "f" }""")]
    [InlineData("""{ "Database": { "Provider": "PostgreSQL", "ServerVersion": "15", "ConnectionString": "Host=db;Database=x;Username=u", "PoolSecret": "x" }, "MasterKey": "k" }""")]
    public void Load_WithFieldsOutsideTheCanonicalSchema_Fails(string json)
    {
        var path = WriteBootstrap(json);

        var exception = Assert.Throws<BootstrapException>(() =>
            BootstrapLoader.Load(Configuration(path), Environment(Environments.Production)));

        Assert.Contains("not valid JSON", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("PoolSecret", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    // Unknown provider.
    [InlineData("""{ "Database": { "Provider": "postgres", "ServerVersion": "15", "ConnectionString": "Host=db;Database=x;Username=u" }, "MasterKey": "k" }""", "Database.Provider")]
    // MySQL and MariaDB were withdrawn by ADR 0004. A bootstrap file left over from a
    // MySQL-era deployment must fail at startup rather than be read as something else.
    [InlineData("""{ "Database": { "Provider": "MySQL", "ServerVersion": "8.4", "ConnectionString": "Server=db;Database=x;User ID=u" }, "MasterKey": "k" }""", "Database.Provider")]
    [InlineData("""{ "Database": { "Provider": "MariaDB", "ServerVersion": "11.4", "ConnectionString": "Server=db;Database=x;User ID=u" }, "MasterKey": "k" }""", "Database.Provider")]
    // PostgreSQL below the supported major version.
    [InlineData("""{ "Database": { "Provider": "PostgreSQL", "ServerVersion": "13", "ConnectionString": "Host=db;Database=x;Username=u" }, "MasterKey": "k" }""", "PostgreSQL 15")]
    // Server version supplied for SQLite, which does not have one.
    [InlineData("""{ "Database": { "Provider": "SQLite", "ServerVersion": "3", "ConnectionString": "Data Source=x.db" }, "MasterKey": "k" }""", "must not be configured")]
    // In-memory SQLite would silently discard every identity on restart.
    [InlineData("""{ "Database": { "Provider": "SQLite", "ConnectionString": "Data Source=:memory:" }, "MasterKey": "k" }""", "local database file")]
    // Connection string without a host.
    [InlineData("""{ "Database": { "Provider": "PostgreSQL", "ServerVersion": "15", "ConnectionString": "Username=u" }, "MasterKey": "k" }""", "must specify Host and Database")]
    public void Load_WithInvalidDatabaseConfiguration_FailsClearly(string json, string expectedFragment)
    {
        var path = WriteBootstrap(json);

        var exception = Assert.Throws<BootstrapException>(() =>
            BootstrapLoader.Load(Configuration(path), Environment(Environments.Production)));

        Assert.Contains(expectedFragment, exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The Development fallback exists so a clone-and-run developer setup works without preparing a
    /// secret file. It must never apply outside Development.
    /// </summary>
    [Fact]
    public void Load_WithoutFileInDevelopment_FallsBackToTheDatabaseSection()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [BootstrapLoader.FilePathConfigurationKey] =
                    Path.Combine(_directory, BootstrapLoader.FileName),
                ["Database:Provider"] = "SQLite",
                ["Database:ConnectionString"] = "Data Source=dev.db"
            })
            .Build();

        var bootstrap = BootstrapLoader.Load(configuration, Environment(Environments.Development));

        Assert.Equal(DatabaseProvider.Sqlite, bootstrap.Database.ProviderKind);
        Assert.False(string.IsNullOrWhiteSpace(bootstrap.RootSecret));
    }

    [Fact]
    public void DescribeEndpoint_ReportsHostAndDatabaseButNeverCredentials()
    {
        var options = new DatabaseOptions
        {
            Provider = "PostgreSQL",
            ServerVersion = "15",
            ConnectionString = ConnectionString
        };

        var described = BootstrapDiagnostics.DescribeEndpoint(options);

        Assert.Contains("db.internal", described, StringComparison.Ordinal);
        Assert.Contains("signacore", described, StringComparison.Ordinal);
        Assert.DoesNotContain("super-secret-password", described, StringComparison.Ordinal);
    }

    private string WriteBootstrap(string json)
    {
        var path = Path.Combine(_directory, BootstrapLoader.FileName);
        File.WriteAllText(path, json);
        return path;
    }

    private static IConfiguration Configuration(string bootstrapPath) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [BootstrapLoader.FilePathConfigurationKey] = bootstrapPath
            })
            .Build();

    private static IHostEnvironment Environment(string environmentName) =>
        new StubHostEnvironment { EnvironmentName = environmentName };

    private sealed class StubHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;
        public string ApplicationName { get; set; } = "SignaCore.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
