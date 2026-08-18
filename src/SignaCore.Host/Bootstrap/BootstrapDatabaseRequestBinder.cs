using Microsoft.Data.Sqlite;
using Npgsql;
using SignaCore.Database;
using SignaCore.Host.Models;

namespace SignaCore.Host.Bootstrap;

/// <summary>
/// Turns the bootstrap form's database fields into validated <see cref="DatabaseOptions"/>.
/// <para>
/// The structured fields are assembled here rather than in the browser so the password never has to
/// be concatenated into a connection string by client-side code, where it would end up in form
/// state, autofill, and any error message that echoes the request. An operator who needs options the
/// form does not model can still supply a complete connection string instead.
/// </para>
/// </summary>
internal static class BootstrapDatabaseRequestBinder
{
    private const int DefaultPostgreSqlPort = 5432;

    public static bool TryBind(
        BootstrapDatabaseRequest request,
        out DatabaseOptions options,
        out string error)
    {
        options = new DatabaseOptions();
        error = string.Empty;

        var provider = request.Provider?.Trim() ?? string.Empty;
        if (provider.Length == 0)
        {
            error = "Select a database provider.";
            return false;
        }

        options.Provider = provider;

        DatabaseProvider providerKind;
        try
        {
            providerKind = options.ProviderKind;
        }
        catch (InvalidOperationException exception)
        {
            error = exception.Message;
            return false;
        }

        options.ServerVersion = providerKind == DatabaseProvider.Sqlite
            ? null
            : NullIfBlank(request.ServerVersion);

        if (providerKind != DatabaseProvider.Sqlite &&
            request.Port is <= 0 or > 65535)
        {
            error = "Port must be between 1 and 65535.";
            return false;
        }

        if (!TryBuildConnectionString(request, providerKind, out var connectionString, out error))
        {
            return false;
        }

        options.ConnectionString = connectionString;

        try
        {
            options.Validate();
        }
        catch (InvalidOperationException exception)
        {
            error = exception.Message;
            return false;
        }

        return true;
    }

    private static bool TryBuildConnectionString(
        BootstrapDatabaseRequest request,
        DatabaseProvider providerKind,
        out string connectionString,
        out string error)
    {
        connectionString = string.Empty;
        error = string.Empty;

        var advanced = NullIfBlank(request.ConnectionString);
        if (advanced is not null)
        {
            connectionString = advanced;
            return true;
        }

        switch (providerKind)
        {
            case DatabaseProvider.PostgreSql:
            {
                if (!Require(request.Host, "Host", out error) ||
                    !Require(request.Database, "Database", out error) ||
                    !Require(request.Username, "Username", out error))
                {
                    return false;
                }

                var builder = new NpgsqlConnectionStringBuilder
                {
                    Host = request.Host!.Trim(),
                    Port = request.Port ?? DefaultPostgreSqlPort,
                    Database = request.Database!.Trim(),
                    Username = request.Username!.Trim(),
                    Password = request.Password ?? string.Empty
                };
                connectionString = builder.ConnectionString;
                return true;
            }

            case DatabaseProvider.Sqlite:
            {
                if (!Require(request.FilePath, "Database file", out error))
                {
                    return false;
                }

                connectionString = new SqliteConnectionStringBuilder
                {
                    DataSource = request.FilePath!.Trim()
                }.ConnectionString;
                return true;
            }

            default:
                error = "Unsupported database provider.";
                return false;
        }
    }

    private static bool Require(string? value, string label, out string error)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            error = $"{label} is required.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private static string? NullIfBlank(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
