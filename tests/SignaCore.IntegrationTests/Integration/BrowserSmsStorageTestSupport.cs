using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

/// <summary>
/// Raw-SQL seeding and reading of <c>identity_sessions</c> and <c>authorization_requests</c> rows
/// for migration contract tests that stand on a history version older than
/// <c>AddBrowserSmsLoginStorage</c> (#443). The current EF model names
/// <c>identity_sessions.sms_user_login_id</c> and <c>authorization_requests.sms_code_send_count</c>,
/// which the older schema does not have, so those tests must neither write nor read these two
/// tables through the model. These helpers touch only the columns every earlier version has, on
/// the provider's own storage representation (SQLite instants are Unix microseconds).
/// </summary>
internal static class BrowserSmsStorageTestSupport
{
    /// <summary>Inserts one Password session using only the pre-#443 columns.</summary>
    public static Task InsertLegacySessionAsync(
        IdentityDbContext context,
        Guid sessionId,
        Guid accountId,
        Guid passwordCredentialId,
        DateTimeOffset authTime,
        string authMethod = IdentityConstants.AuthMethodPassword,
        DateTimeOffset? revokedAt = null,
        string? revocationReason = null)
    {
        var idleExpiresAt = authTime.AddMinutes(IdentityConstants.IdentitySessionIdleTimeoutMinutes);
        var absoluteExpiresAt = authTime.AddSeconds(IdentityConstants.MaxIdentitySessionAgeSeconds);
        if (context.Database.IsSqlite())
        {
            return context.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO identity_sessions
                    (id, account_id, password_credential_id, auth_method, auth_time, last_seen_at,
                     idle_expires_at, absolute_expires_at, revoked_at, revocation_reason)
                VALUES
                    ({sessionId}, {accountId}, {passwordCredentialId}, {authMethod},
                     {ToMicroseconds(authTime)}, {ToMicroseconds(authTime)},
                     {ToMicroseconds(idleExpiresAt)}, {ToMicroseconds(absoluteExpiresAt)},
                     {(long?)(revokedAt is null ? null : ToMicroseconds(revokedAt.Value))},
                     {revocationReason});
                """, TestContext.Current.CancellationToken);
        }

        return context.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO identity_sessions
                (id, account_id, password_credential_id, auth_method, auth_time, last_seen_at,
                 idle_expires_at, absolute_expires_at, revoked_at, revocation_reason)
            VALUES
                ({sessionId}, {accountId}, {passwordCredentialId}, {authMethod},
                 {authTime}, {authTime}, {idleExpiresAt}, {absoluteExpiresAt},
                 {revokedAt}, {revocationReason});
            """, TestContext.Current.CancellationToken);
    }

    /// <summary>Inserts one continuation using only the pre-#443 columns.</summary>
    public static Task InsertLegacyAuthorizationRequestAsync(
        IdentityDbContext context,
        Guid requestId,
        string handleDigest,
        Guid appRegistrationId,
        DateTimeOffset createdAt,
        string redirectUri = "https://client.example.test/callback",
        string scope = "openid",
        string state = "upgrade-state",
        string nonce = "upgrade-nonce",
        string codeChallenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        DateTimeOffset? consumedAt = null)
    {
        var expiresAt = createdAt.AddMinutes(IdentityConstants.LoginHandleLifetimeMinutes);
        if (context.Database.IsSqlite())
        {
            return context.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO authorization_requests
                    (id, handle_digest, app_registration_id, redirect_uri, scope, state, nonce,
                     code_challenge, created_at, expires_at, consumed_at)
                VALUES
                    ({requestId}, {handleDigest}, {appRegistrationId}, {redirectUri}, {scope},
                     {state}, {nonce}, {codeChallenge},
                     {ToMicroseconds(createdAt)}, {ToMicroseconds(expiresAt)},
                     {(long?)(consumedAt is null ? null : ToMicroseconds(consumedAt.Value))});
                """, TestContext.Current.CancellationToken);
        }

        return context.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO authorization_requests
                (id, handle_digest, app_registration_id, redirect_uri, scope, state, nonce,
                 code_challenge, created_at, expires_at, consumed_at)
            VALUES
                ({requestId}, {handleDigest}, {appRegistrationId}, {redirectUri}, {scope},
                 {state}, {nonce}, {codeChallenge}, {createdAt}, {expiresAt}, {consumedAt});
            """, TestContext.Current.CancellationToken);
    }

    /// <summary>The pre-#443 columns of one continuation row, read without the EF model.</summary>
    public sealed record LegacyAuthorizationRequestRow(
        Guid Id,
        Guid AppRegistrationId,
        string RedirectUri,
        string Scope,
        DateTimeOffset CreatedAt,
        DateTimeOffset ExpiresAt,
        DateTimeOffset? ConsumedAt);

    public static async Task<LegacyAuthorizationRequestRow?> ReadLegacyAuthorizationRequestAsync(
        IdentityDbContext context,
        string handleDigest)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var sqlite = context.Database.IsSqlite();
        await context.Database.OpenConnectionAsync(cancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText =
            "SELECT id, app_registration_id, redirect_uri, scope, created_at, expires_at, consumed_at "
            + "FROM authorization_requests WHERE handle_digest = "
            + (sqlite ? "$digest" : "@digest");
        var parameter = command.CreateParameter();
        parameter.ParameterName = sqlite ? "$digest" : "digest";
        parameter.Value = handleDigest;
        command.Parameters.Add(parameter);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var row = sqlite
            ? new LegacyAuthorizationRequestRow(
                Guid.Parse(reader.GetString(0)),
                Guid.Parse(reader.GetString(1)),
                reader.GetString(2),
                reader.GetString(3),
                FromMicroseconds(reader.GetInt64(4)),
                FromMicroseconds(reader.GetInt64(5)),
                reader.IsDBNull(6) ? null : FromMicroseconds(reader.GetInt64(6)))
            : new LegacyAuthorizationRequestRow(
                reader.GetGuid(0),
                reader.GetGuid(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetFieldValue<DateTimeOffset>(4),
                reader.GetFieldValue<DateTimeOffset>(5),
                reader.IsDBNull(6) ? null : reader.GetFieldValue<DateTimeOffset>(6));
        Assert.False(await reader.ReadAsync(cancellationToken));
        return row;
    }

    /// <summary>The pre-#443 columns of one session row, read without the EF model.</summary>
    public sealed record LegacySessionRow(
        Guid AccountId,
        Guid PasswordCredentialId,
        string AuthMethod,
        DateTimeOffset AuthTime,
        DateTimeOffset LastSeenAt,
        DateTimeOffset IdleExpiresAt,
        DateTimeOffset AbsoluteExpiresAt,
        DateTimeOffset? RevokedAt,
        string? RevocationReason);

    public static async Task<LegacySessionRow?> ReadLegacySessionAsync(
        IdentityDbContext context,
        Guid sessionId)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var sqlite = context.Database.IsSqlite();
        await context.Database.OpenConnectionAsync(cancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText =
            "SELECT account_id, password_credential_id, auth_method, auth_time, last_seen_at, "
            + "idle_expires_at, absolute_expires_at, revoked_at, revocation_reason "
            + "FROM identity_sessions WHERE id = "
            + (sqlite ? "$id" : "@id");
        var parameter = command.CreateParameter();
        parameter.ParameterName = sqlite ? "$id" : "id";
        // EF stores SQLite GUIDs as uppercase TEXT; PostgreSQL binds the uuid directly.
        parameter.Value = sqlite ? sessionId.ToString("D").ToUpperInvariant() : sessionId;
        command.Parameters.Add(parameter);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var row = sqlite
            ? new LegacySessionRow(
                Guid.Parse(reader.GetString(0)),
                Guid.Parse(reader.GetString(1)),
                reader.GetString(2),
                FromMicroseconds(reader.GetInt64(3)),
                FromMicroseconds(reader.GetInt64(4)),
                FromMicroseconds(reader.GetInt64(5)),
                FromMicroseconds(reader.GetInt64(6)),
                reader.IsDBNull(7) ? null : FromMicroseconds(reader.GetInt64(7)),
                reader.IsDBNull(8) ? null : reader.GetString(8))
            : new LegacySessionRow(
                reader.GetGuid(0),
                reader.GetGuid(1),
                reader.GetString(2),
                reader.GetFieldValue<DateTimeOffset>(3),
                reader.GetFieldValue<DateTimeOffset>(4),
                reader.GetFieldValue<DateTimeOffset>(5),
                reader.GetFieldValue<DateTimeOffset>(6),
                reader.IsDBNull(7) ? null : reader.GetFieldValue<DateTimeOffset>(7),
                reader.IsDBNull(8) ? null : reader.GetString(8));
        Assert.False(await reader.ReadAsync(cancellationToken));
        return row;
    }

    /// <summary>Counts rows of <paramref name="table"/> matching an optional raw predicate.</summary>
    public static async Task<long> CountAsync(
        IdentityDbContext context,
        string table,
        string? predicate = null)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await context.Database.OpenConnectionAsync(cancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText = $"SELECT count(*) FROM {table}"
            + (predicate is null ? string.Empty : $" WHERE {predicate}");
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken));
    }

    public static long ToMicroseconds(DateTimeOffset value) =>
        (value.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10;

    private static DateTimeOffset FromMicroseconds(long value) =>
        DateTimeOffset.UnixEpoch.AddTicks(value * 10);
}
