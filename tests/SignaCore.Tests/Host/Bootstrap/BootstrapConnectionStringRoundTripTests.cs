using Microsoft.Data.Sqlite;
using Npgsql;
using Xunit;

namespace SignaCore.Tests.Host.Bootstrap;

/// <summary>
/// Backend parse evidence for the admin console's connection-string helper: every structured
/// value the frontend wraps in double quotes with internal quotes doubled survives
/// <see cref="NpgsqlConnectionStringBuilder"/> and <see cref="SqliteConnectionStringBuilder"/>
/// verbatim, so characters like semicolons or a leading quote cannot corrupt the assembled string
/// the way an unquoted join would.
/// </summary>
public sealed class BootstrapConnectionStringRoundTripTests
{
    public static TheoryData<string> StructuredValues => new()
    {
        "plain-secret",
        "a;b",
        "x=y",
        "'quoted",
        "a\"b",
        " padded ",
        "密码;词",
        "",
    };

    [Theory]
    [MemberData(nameof(StructuredValues))]
    public void Npgsql_ReadsEveryQuotedValueVerbatim(string value)
    {
        var assembled = $"Host=\"db\";Port=5432;Database=\"signacore\";Username=\"user\";Password={Quote(value)}";

        var parsed = new NpgsqlConnectionStringBuilder(assembled);

        Assert.Equal("db", parsed.Host);
        Assert.Equal(5432, parsed.Port);
        Assert.Equal("signacore", parsed.Database);
        Assert.Equal("user", parsed.Username);
        // The builder unquotes and undoubles exactly what the helper quoted.
        Assert.Equal(value, parsed.Password);
    }

    [Theory]
    [MemberData(nameof(StructuredValues))]
    public void Npgsql_ReadsQuotedHostAndDatabaseVerbatim(string value)
    {
        var assembled = $"Host={Quote(value)};Database={Quote("signacore")}";

        var parsed = new NpgsqlConnectionStringBuilder(assembled);

        Assert.Equal(value, parsed.Host);
    }

    [Fact]
    public void Sqlite_ReadsAQuotedPathWithSeparatorsAndQuotesVerbatim()
    {
        var path = "/app/a;b'c\"d.db";
        var assembled = $"Data Source={Quote(path)}";

        var parsed = new SqliteConnectionStringBuilder(assembled);

        Assert.Equal(path, parsed.DataSource);
    }

    private static string Quote(string value) => $"\"{value.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
}
