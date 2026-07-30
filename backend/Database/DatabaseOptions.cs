using Microsoft.Data.Sqlite;
using MySqlConnector;
using Npgsql;

namespace QuantumZhou.Identity.Database;

public sealed class DatabaseOptions
{
    public const string SectionName = "Database";

    public string Provider { get; set; } = string.Empty;
    public string? ServerVersion { get; set; }
    public string ConnectionString { get; set; } = string.Empty;

    public DatabaseProvider ProviderKind => Provider switch
    {
        "PostgreSQL" => DatabaseProvider.PostgreSql,
        "MySQL" => DatabaseProvider.MySql,
        "MariaDB" => DatabaseProvider.MariaDb,
        "SQLite" => DatabaseProvider.Sqlite,
        _ => throw new InvalidOperationException(
            "Database.Provider must be one of: PostgreSQL, MySQL, MariaDB, SQLite.")
    };

    public Version GetServerVersion()
    {
        if (ProviderKind == DatabaseProvider.Sqlite)
        {
            throw new InvalidOperationException("Database.ServerVersion is not valid for SQLite.");
        }

        if (int.TryParse(ServerVersion, out var majorVersion))
        {
            return new Version(majorVersion, 0);
        }

        if (!Version.TryParse(ServerVersion, out var version))
        {
            throw new InvalidOperationException("Database.ServerVersion must be a valid version.");
        }

        return version;
    }

    public void Validate()
    {
        _ = ProviderKind;

        if (string.IsNullOrWhiteSpace(ConnectionString))
        {
            throw new InvalidOperationException("Database.ConnectionString is required.");
        }

        if (ProviderKind == DatabaseProvider.Sqlite)
        {
            if (!string.IsNullOrWhiteSpace(ServerVersion))
            {
                throw new InvalidOperationException("Database.ServerVersion must not be configured for SQLite.");
            }

            ValidateSqliteConnectionString();
            return;
        }

        if (string.IsNullOrWhiteSpace(ServerVersion))
        {
            throw new InvalidOperationException("Database.ServerVersion is required for the selected provider.");
        }

        var version = GetServerVersion();
        switch (ProviderKind)
        {
            case DatabaseProvider.PostgreSql:
                if (version.Major < 15)
                {
                    throw new InvalidOperationException("PostgreSQL 15 or newer is required.");
                }
                ValidatePostgreSqlConnectionString();
                break;
            case DatabaseProvider.MySql:
                if (version.Major != 8 || version.Minor is not (0 or 4))
                {
                    throw new InvalidOperationException("Supported MySQL versions are 8.0 and 8.4.");
                }
                ValidateMySqlConnectionString();
                break;
            case DatabaseProvider.MariaDb:
                if ((version.Major, version.Minor) is not ((10, 11) or (11, 4)))
                {
                    throw new InvalidOperationException("Supported MariaDB versions are 10.11 and 11.4.");
                }
                ValidateMySqlConnectionString();
                break;
            default:
                throw new InvalidOperationException("Unsupported database provider.");
        }
    }

    private void ValidatePostgreSqlConnectionString()
    {
        try
        {
            var builder = new NpgsqlConnectionStringBuilder(ConnectionString);
            if (string.IsNullOrWhiteSpace(builder.Host) || string.IsNullOrWhiteSpace(builder.Database))
            {
                throw new InvalidOperationException(
                    "PostgreSQL connection string must specify Host and Database.");
            }
        }
        catch (ArgumentException exception)
        {
            throw new InvalidOperationException(
                "Database.ConnectionString is not a valid PostgreSQL connection string.",
                exception);
        }
    }

    private void ValidateMySqlConnectionString()
    {
        try
        {
            var builder = new MySqlConnectionStringBuilder(ConnectionString);
            if (string.IsNullOrWhiteSpace(builder.Server) || string.IsNullOrWhiteSpace(builder.Database))
            {
                throw new InvalidOperationException(
                    "MySQL-compatible connection string must specify Server and Database.");
            }
        }
        catch (ArgumentException exception)
        {
            throw new InvalidOperationException(
                "Database.ConnectionString is not a valid MySQL-compatible connection string.",
                exception);
        }
    }

    private void ValidateSqliteConnectionString()
    {
        try
        {
            var builder = new SqliteConnectionStringBuilder(ConnectionString);
            if (string.IsNullOrWhiteSpace(builder.DataSource))
            {
                throw new InvalidOperationException(
                    "SQLite connection string must specify Data Source.");
            }

            if (string.Equals(builder.DataSource, ":memory:", StringComparison.OrdinalIgnoreCase) ||
                builder.Mode == SqliteOpenMode.Memory)
            {
                throw new InvalidOperationException(
                    "SQLite must use a local database file; in-memory databases are not supported.");
            }
        }
        catch (ArgumentException exception)
        {
            throw new InvalidOperationException(
                "Database.ConnectionString is not a valid SQLite connection string.",
                exception);
        }
    }
}
