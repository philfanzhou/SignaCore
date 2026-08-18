using Microsoft.Data.Sqlite;
using Npgsql;
using SignaCore.Database;

namespace SignaCore.Host.Bootstrap;

/// <summary>
/// Startup diagnostics may report the provider and database host so a misdirected deployment is
/// obvious in the logs. They must never report credentials, the full connection string, or any
/// representation of the root key.
/// </summary>
internal static class BootstrapDiagnostics
{
    public static string DescribeEndpoint(DatabaseOptions options)
    {
        try
        {
            switch (options.ProviderKind)
            {
                case DatabaseProvider.PostgreSql:
                {
                    var builder = new NpgsqlConnectionStringBuilder(options.ConnectionString);
                    return $"{builder.Host}:{builder.Port}/{builder.Database}";
                }
                case DatabaseProvider.Sqlite:
                {
                    var builder = new SqliteConnectionStringBuilder(options.ConnectionString);
                    return Path.GetFileName(builder.DataSource);
                }
                default:
                    return "unknown";
            }
        }
        catch (Exception)
        {
            // A connection string that cannot even be parsed is reported by validation with a
            // precise message; diagnostics must not become a second place that can leak it.
            return "unparsable";
        }
    }
}
