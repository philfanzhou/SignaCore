using Microsoft.Data.Sqlite;
using Npgsql;
using ServiceMantle.Bootstrap;
using SignaCore.Database;

namespace SignaCore.Host.Bootstrap;

/// <summary>
/// Startup diagnostics may report the provider and database host so a misdirected deployment is
/// obvious in the logs. They must never report credentials, the full connection string, or any
/// representation of the root key.
/// </summary>
internal static class BootstrapDiagnostics
{
    /// <summary>Describes a locally bound database target (the bootstrap editor request path).</summary>
    public static string DescribeEndpoint(DatabaseOptions options)
    {
        try
        {
            return DescribeEndpoint(new BootstrapDatabaseConfiguration(
                options.Provider,
                options.ServerVersion,
                options.ConnectionString));
        }
        catch (Exception)
        {
            return "unparsable";
        }
    }

    public static string DescribeEndpoint(BootstrapDatabaseConfiguration database)
    {
        try
        {
            if (string.Equals(database.Provider, "PostgreSQL", StringComparison.OrdinalIgnoreCase))
            {
                var builder = new NpgsqlConnectionStringBuilder(database.ConnectionString);
                return $"{builder.Host}:{builder.Port}/{builder.Database}";
            }

            if (string.Equals(database.Provider, "SQLite", StringComparison.OrdinalIgnoreCase))
            {
                var builder = new SqliteConnectionStringBuilder(database.ConnectionString);
                return Path.GetFileName(builder.DataSource);
            }

            return "unknown";
        }
        catch (Exception)
        {
            // A connection string that cannot even be parsed is reported by validation with a
            // precise message; diagnostics must not become a second place that can leak it.
            return "unparsable";
        }
    }
}
