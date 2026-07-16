using QuantumZhou.Identity.Host;
using Xunit;

namespace QuantumZhou.Identity.Tests.Host.Configuration;

public class ServiceCollectionExtensionsDatabaseTests
{
    [Fact]
    public void EnsurePostgreSqlDatabaseCreated_WhenConnectionStringLacksDatabase_DoesNotThrow()
    {
        // A connection string without an explicit Database key should be a no-op,
        // not an exception. NpgsqlConnectionStringBuilder.Database returns null/empty.
        var cs = "Host=localhost;Port=5432;Username=postgres;Password=postgres";

        var exception = Record.Exception(() =>
            ServiceCollectionExtensions.EnsurePostgreSqlDatabaseCreated(cs));

        Assert.Null(exception);
    }

    [Fact]
    public void EnsurePostgreSqlDatabaseCreated_WhenServerUnreachable_DoesNotThrow()
    {
        // Pointing at an unreachable host on a reserved port guarantees the connection
        // fails fast. The method must swallow the error so Migrate() can surface it later.
        var cs = "Host=127.0.0.1;Port=1;Database=ruoyu_identity_test;Username=postgres;Password=postgres;Timeout=1";

        var exception = Record.Exception(() =>
            ServiceCollectionExtensions.EnsurePostgreSqlDatabaseCreated(cs));

        Assert.Null(exception);
    }

    [Fact]
    public void EnsurePostgreSqlDatabaseCreated_WhenMalformedConnectionString_DoesNotThrow()
    {
        // Malformed input must not crash startup; the method degrades gracefully.
        var exception = Record.Exception(() =>
            ServiceCollectionExtensions.EnsurePostgreSqlDatabaseCreated("not a connection string"));

        Assert.Null(exception);
    }
}
