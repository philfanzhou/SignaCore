using Microsoft.Extensions.Configuration;
using SignaCore.Database;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

public class ServiceCollectionExtensionsDatabaseTests
{
    public static TheoryData<string, string?, string, DatabaseProvider> ValidConfigurations => new()
    {
        {
            "PostgreSQL",
            "15",
            "Host=localhost;Database=identity;Username=postgres;Password=test",
            DatabaseProvider.PostgreSql
        },
        {
            "MySQL",
            "8.4",
            "Server=localhost;Database=identity;User=root;Password=test",
            DatabaseProvider.MySql
        },
        {
            "MariaDB",
            "11.4",
            "Server=localhost;Database=identity;User=root;Password=test",
            DatabaseProvider.MariaDb
        },
        {
            "SQLite",
            null,
            "Data Source=identity.db",
            DatabaseProvider.Sqlite
        }
    };

    [Theory]
    [MemberData(nameof(ValidConfigurations))]
    public void BindDatabaseOptions_WithSupportedProvider_ReturnsValidatedOptions(
        string provider,
        string? serverVersion,
        string connectionString,
        DatabaseProvider expectedProvider)
    {
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["Database:Provider"] = provider,
            ["Database:ServerVersion"] = serverVersion,
            ["Database:ConnectionString"] = connectionString
        });

        var options = ServiceCollectionExtensions.BindDatabaseOptions(configuration);

        Assert.Equal(expectedProvider, options.ProviderKind);
        Assert.Equal(connectionString, options.ConnectionString);
    }

    [Theory]
    [InlineData("Database:Name")]
    [InlineData("ConnectionStrings:Default")]
    [InlineData("ConnectionStrings:PostgreSQL")]
    [InlineData("PostgreSql:Host")]
    public void BindDatabaseOptions_WithLegacyKey_Throws(string legacyKey)
    {
        var values = ValidPostgreSqlConfiguration();
        values[legacyKey] = "legacy";
        var configuration = BuildConfiguration(values);

        var exception = Assert.Throws<InvalidOperationException>(
            () => ServiceCollectionExtensions.BindDatabaseOptions(configuration));

        Assert.Contains("Legacy database configuration", exception.Message);
    }

    [Fact]
    public void BindDatabaseOptions_WithUnknownProvider_Throws()
    {
        var values = ValidPostgreSqlConfiguration();
        values["Database:Provider"] = "postgres";
        var configuration = BuildConfiguration(values);

        var exception = Assert.Throws<InvalidOperationException>(
            () => ServiceCollectionExtensions.BindDatabaseOptions(configuration));

        Assert.Contains("Database.Provider", exception.Message);
    }

    [Fact]
    public void BindDatabaseOptions_WithSqliteServerVersion_Throws()
    {
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["Database:Provider"] = "SQLite",
            ["Database:ServerVersion"] = "3",
            ["Database:ConnectionString"] = "Data Source=identity.db"
        });

        var exception = Assert.Throws<InvalidOperationException>(
            () => ServiceCollectionExtensions.BindDatabaseOptions(configuration));

        Assert.Contains("must not be configured", exception.Message);
    }

    [Fact]
    public void BindDatabaseOptions_WithInMemorySqlite_Throws()
    {
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["Database:Provider"] = "SQLite",
            ["Database:ConnectionString"] = "Data Source=:memory:"
        });

        var exception = Assert.Throws<InvalidOperationException>(
            () => ServiceCollectionExtensions.BindDatabaseOptions(configuration));

        Assert.Contains("local database file", exception.Message);
    }

    private static Dictionary<string, string?> ValidPostgreSqlConfiguration()
    {
        return new Dictionary<string, string?>
        {
            ["Database:Provider"] = "PostgreSQL",
            ["Database:ServerVersion"] = "15",
            ["Database:ConnectionString"] =
                "Host=localhost;Database=identity;Username=postgres;Password=test"
        };
    }

    private static IConfiguration BuildConfiguration(Dictionary<string, string?> values)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();
    }
}
