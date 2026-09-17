using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

/// <summary>
/// Raw-SQL seeding and reading of <c>refresh_tokens</c> rows for the migration contract tests.
/// A migration test that stands on an older history version must not write through the current EF
/// model — the model's INSERT would name family columns the old schema does not have — and its
/// Down-state assertions must not read through it either. These helpers insert and read only the
/// legacy columns, on the provider's own storage representation, and never touch
/// <c>token_value</c> beyond storing the caller's bytes verbatim (<c>DF-09</c>).
/// </summary>
internal static class RefreshTokenFamilyTestSupport
{
    /// <summary>The SQLite UTC-instant storage unit of <c>IdentityDbContext</c>.</summary>
    public static long ToSqliteMicroseconds(DateTimeOffset value) =>
        (value.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10;

    public static Task InsertLegacyRefreshTokenSqliteAsync(
        IdentityDbContext context,
        Guid tokenId,
        Guid accountId,
        string tokenValue,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        string appId,
        bool isRevoked = false,
        string? sourceAppId = null) =>
        context.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO refresh_tokens
                (id, account_id, token_value, created_at, expires_at, is_revoked, app_id, source_app_id)
            VALUES
                ({tokenId}, {accountId}, {tokenValue},
                 {ToSqliteMicroseconds(createdAt)}, {ToSqliteMicroseconds(expiresAt)},
                 {(isRevoked ? 1 : 0)}, {appId}, {sourceAppId});
            """, TestContext.Current.CancellationToken);

    public static Task InsertLegacyRefreshTokenPostgreSqlAsync(
        IdentityDbContext context,
        Guid tokenId,
        Guid accountId,
        string tokenValue,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        string appId,
        bool isRevoked = false,
        string? sourceAppId = null) =>
        context.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO refresh_tokens
                (id, account_id, token_value, created_at, expires_at, is_revoked, app_id, source_app_id)
            VALUES
                ({tokenId}, {accountId}, {tokenValue},
                 {createdAt}, {expiresAt}, {isRevoked}, {appId}, {sourceAppId});
            """, TestContext.Current.CancellationToken);

    public sealed record LegacyRefreshTokenRow(
        string TokenValue,
        bool IsRevoked,
        DateTimeOffset CreatedAt,
        DateTimeOffset ExpiresAt,
        string? SourceAppId);

    public static async Task<LegacyRefreshTokenRow> ReadRefreshTokenRowSqliteAsync(
        IdentityDbContext context,
        Guid tokenId)
    {
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText =
            "SELECT token_value, is_revoked, created_at, expires_at, source_app_id "
            + "FROM refresh_tokens WHERE id = $tokenId";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "$tokenId";
        parameter.Value = tokenId;
        command.Parameters.Add(parameter);
        await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        Assert.True(await reader.ReadAsync(TestContext.Current.CancellationToken));
        return new LegacyRefreshTokenRow(
            reader.GetString(0),
            reader.GetBoolean(1),
            DateTimeOffset.UnixEpoch.AddTicks(reader.GetInt64(2) * 10),
            DateTimeOffset.UnixEpoch.AddTicks(reader.GetInt64(3) * 10),
            reader.IsDBNull(4) ? null : reader.GetString(4));
    }

    public static async Task<LegacyRefreshTokenRow> ReadRefreshTokenRowPostgreSqlAsync(
        IdentityDbContext context,
        Guid tokenId)
    {
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText =
            "SELECT token_value, is_revoked, created_at, expires_at, source_app_id "
            + "FROM refresh_tokens WHERE id = @tokenId";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "tokenId";
        parameter.Value = tokenId;
        command.Parameters.Add(parameter);
        await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        Assert.True(await reader.ReadAsync(TestContext.Current.CancellationToken));
        return new LegacyRefreshTokenRow(
            reader.GetString(0),
            reader.GetBoolean(1),
            reader.GetFieldValue<DateTimeOffset>(2),
            reader.GetFieldValue<DateTimeOffset>(3),
            reader.IsDBNull(4) ? null : reader.GetString(4));
    }

    /// <summary>
    /// Inserts one interactive family member through raw SQL — the shape no legacy write path can
    /// produce — so the constraint, cleanup, isolation, and downgrade-gate cases can exercise
    /// interactive rows before #98 delivers the family write API.
    /// </summary>
    public static Task InsertInteractiveMemberSqliteAsync(
        IdentityDbContext context,
        Guid tokenId,
        Guid accountId,
        string appId,
        Guid familyId,
        Guid? parentId,
        Guid identitySessionId,
        string scope,
        DateTimeOffset authTime,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        bool isRevoked = false,
        DateTimeOffset? consumedAt = null) =>
        context.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO refresh_tokens
                (id, account_id, token_value, created_at, expires_at, is_revoked, app_id,
                 family_id, parent_id, identity_session_id, scope, auth_time, consumed_at)
            VALUES
                ({tokenId}, {accountId}, {DigestFor(tokenId)},
                 {ToSqliteMicroseconds(createdAt)}, {ToSqliteMicroseconds(expiresAt)},
                 {(isRevoked ? 1 : 0)}, {appId},
                 {familyId}, {parentId}, {identitySessionId}, {scope},
                 {ToSqliteMicroseconds(authTime)}, {(long?)(consumedAt is null ? null : ToSqliteMicroseconds(consumedAt.Value))});
            """, TestContext.Current.CancellationToken);

    public static Task InsertInteractiveMemberPostgreSqlAsync(
        IdentityDbContext context,
        Guid tokenId,
        Guid accountId,
        string appId,
        Guid familyId,
        Guid? parentId,
        Guid identitySessionId,
        string scope,
        DateTimeOffset authTime,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        bool isRevoked = false,
        DateTimeOffset? consumedAt = null) =>
        context.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO refresh_tokens
                (id, account_id, token_value, created_at, expires_at, is_revoked, app_id,
                 family_id, parent_id, identity_session_id, scope, auth_time, consumed_at)
            VALUES
                ({tokenId}, {accountId}, {DigestFor(tokenId)},
                 {createdAt}, {expiresAt}, {isRevoked}, {appId},
                 {familyId}, {parentId}, {identitySessionId}, {scope},
                 {authTime}, {consumedAt});
            """, TestContext.Current.CancellationToken);

    /// <summary>A deterministic unique digest-shaped token value for a synthetic row.</summary>
    public static string DigestFor(Guid tokenId) =>
        RefreshTokenDigest.Compute("family-contract-token-" + tokenId.ToString("N"));
}
