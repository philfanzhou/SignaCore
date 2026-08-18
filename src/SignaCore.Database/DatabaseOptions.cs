using Microsoft.Data.Sqlite;
using Npgsql;

namespace SignaCore.Database;

public sealed class DatabaseOptions
{
    public const string SectionName = "Database";

    public string Provider { get; set; } = string.Empty;
    public string? ServerVersion { get; set; }
    public string ConnectionString { get; set; } = string.Empty;

    public DatabaseProvider ProviderKind => Provider switch
    {
        "PostgreSQL" => DatabaseProvider.PostgreSql,
        "SQLite" => DatabaseProvider.Sqlite,
        _ => throw new InvalidOperationException(
            "Database.Provider must be one of: PostgreSQL, SQLite.")
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
