using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace SignaCore.Client.AspNetCore.EntityFrameworkCore;

/// <summary>
/// A persistent <see cref="global::SignaCore.Client.AspNetCore.ITicketStore"/> for the hosted-login
/// integration: sessions live in the consumer's own database, survive restarts, and are shared
/// across replicas. The database holds only the SHA-256 digest of the opaque session key and a
/// Data Protection-encrypted payload — never a plaintext key, token, or principal. Rows are
/// reclaimed on expiry at read time and by the package's periodic sweep; removal is one atomic
/// <c>DELETE</c>, so concurrent revocations of one session all succeed while exactly one of them
/// deletes the row.
/// </summary>
/// <typeparam name="TDbContext">The consumer's <see cref="DbContext"/>, mapped with
/// <see cref="SignaCoreTicketStoreModelBuilderExtensions.ConfigureSignaCoreTicketStore"/>.</typeparam>
public sealed class EntityFrameworkTicketStore<TDbContext>(
    IServiceScopeFactory scopeFactory,
    IDataProtectionProvider dataProtectionProvider,
    TimeProvider? timeProvider = null,
    ILogger<EntityFrameworkTicketStore<TDbContext>>? logger = null)
    : global::SignaCore.Client.AspNetCore.ITicketStore
    where TDbContext : DbContext
{
    /// <summary>
    /// The Data Protection purpose string of the ticket payload. A key-ring change that can no
    /// longer unprotect this purpose turns every stored session into an unusable record — the
    /// documented operational boundary: persist and share the Data Protection key ring.
    /// </summary>
    public const string DataProtectionPurpose =
        "SignaCore.Client.AspNetCore.EntityFrameworkCore.SessionTicket.v1";

    private static readonly TicketSerializer Serializer = TicketSerializer.Default;

    private readonly IDataProtector _protector =
        dataProtectionProvider.CreateProtector(DataProtectionPurpose);
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    /// <inheritdoc />
    /// <remarks>
    /// The store imposes no capacity bound of its own — the database and its operator own that
    /// limit. <see langword="null"/> is returned only when persistence failed, which the caller
    /// treats exactly like a full store: the sign-in fails closed.
    /// </remarks>
    public async Task<string?> StoreAsync(
        global::SignaCore.Client.AspNetCore.SignaCoreSessionTicket ticket,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        cancellationToken.ThrowIfCancellationRequested();

        byte[] payload;
        try
        {
            payload = Serialize(ticket);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // Serialization has no database state to leak; still one bounded category.
            SignaCoreTicketStoreLog.Unavailable(logger, "store", cancellationToken);
            return null;
        }

        var key = NewKey();
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var database = scope.ServiceProvider.GetRequiredService<TDbContext>();
            database.Set<SignaCoreSessionTicketEntity>().Add(new SignaCoreSessionTicketEntity
            {
                KeyDigest = Digest(key),
                Payload = payload,
                IssuedUtc = ticket.IssuedUtc,
                ExpiresUtc = ticket.ExpiresUtc
            });
            await database.SaveChangesAsync(cancellationToken);
            return key;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            SignaCoreTicketStoreLog.Unavailable(logger, "store", cancellationToken);
            return null;
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// An expired row is reclaimed on the spot. A row whose payload no longer unprotects or
    /// deserializes (a rotated or lost Data Protection key ring, bit rot, a foreign writer) is
    /// deleted and answers <see langword="null"/> with the fixed
    /// <c>ticket_record_corrupt</c> log category — authentication fails closed, and neither SQL
    /// text nor connection details ever reach the log.
    /// </remarks>
    public async Task<global::SignaCore.Client.AspNetCore.SignaCoreSessionTicket?> RetrieveAsync(
        string key,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(key))
        {
            return null;
        }

        cancellationToken.ThrowIfCancellationRequested();
        var digest = Digest(key);
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var database = scope.ServiceProvider.GetRequiredService<TDbContext>();
            var entity = await database.Set<SignaCoreSessionTicketEntity>()
                .AsNoTracking()
                .FirstOrDefaultAsync(ticket => ticket.KeyDigest == digest, cancellationToken);
            if (entity is null)
            {
                return null;
            }

            if (entity.ExpiresUtc <= _time.GetUtcNow())
            {
                // An expired session is unusable the moment its expiry passes; reclaim it here
                // rather than waiting for the sweep.
                await DeleteAsync(database, digest, cancellationToken);
                return null;
            }

            global::SignaCore.Client.AspNetCore.SignaCoreSessionTicket? ticket;
            try
            {
                ticket = Deserialize(entity);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                // The record can never become readable again; remove it and fail this session
                // closed without touching any other row.
                SignaCoreTicketStoreLog.Corrupt(logger, cancellationToken);
                await DeleteAsync(database, digest, cancellationToken);
                return null;
            }

            return ticket;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            SignaCoreTicketStoreLog.Unavailable(logger, "retrieve", cancellationToken);
            return null;
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// One atomic <c>DELETE ... WHERE</c> on the digest: concurrent revocations of the same
    /// session all complete, exactly one of them deletes the row, and an unknown key remains a
    /// non-error. When the caller needs to know whether it was the one revoker — the
    /// local-session-first logout does — <see cref="TakeAsync"/> is the atomic form that answers
    /// that question.
    /// </remarks>
    public async Task RemoveAsync(string key, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(key))
        {
            return;
        }

        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var database = scope.ServiceProvider.GetRequiredService<TDbContext>();
            await DeleteAsync(database, Digest(key), cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // Revocation is idempotent at the session level; a failed delete is retried by the
            // expiry sweep, which is the durable backstop.
            SignaCoreTicketStoreLog.Unavailable(logger, "remove", cancellationToken);
        }
    }

    /// <summary>
    /// Atomically revokes one session and returns its ticket — the take-and-revoke form of
    /// <see cref="RemoveAsync"/>: a single <c>DELETE ... RETURNING</c> decides the race, so of any
    /// number of concurrent revokers exactly one receives the snapshot (and may, for example,
    /// prepare the upstream logout with it) while the others receive <see langword="null"/>.
    /// This is an addition of the persistence package on top of the frozen
    /// <see cref="global::SignaCore.Client.AspNetCore.ITicketStore"/> contract; the plain
    /// <see cref="RetrieveAsync"/> stays repeatable for ordinary requests.
    /// </summary>
    /// <param name="key">The opaque session key.</param>
    /// <param name="cancellationToken">Propagates the caller's cancellation.</param>
    /// <returns>The revoked session's ticket, or <see langword="null"/> when the key was unknown,
    /// already revoked, or expired — and also when persistence failed, which fails closed.</returns>
    public async Task<global::SignaCore.Client.AspNetCore.SignaCoreSessionTicket?> TakeAsync(
        string key,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(key))
        {
            return null;
        }

        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var database = scope.ServiceProvider.GetRequiredService<TDbContext>();
            var digest = Digest(key);
            var taken = await TakeRowAsync(database, digest, cancellationToken);
            if (taken is null)
            {
                return null;
            }

            try
            {
                return Deserialize(taken);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                // The row is already gone; the corrupt record is only observable here.
                SignaCoreTicketStoreLog.Corrupt(logger, cancellationToken);
                return null;
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            SignaCoreTicketStoreLog.Unavailable(logger, "take", cancellationToken);
            return null;
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// The interface method is synchronous by contract; the implementation drives its async
    /// database work to completion here. It runs on the package's sweep background service,
    /// which has no synchronization context to deadlock.
    /// </remarks>
    public int RemoveExpired(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            return RemoveExpiredAsync(cancellationToken).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            SignaCoreTicketStoreLog.Unavailable(logger, "sweep", CancellationToken.None);
            return 0;
        }
    }

    private async Task<int> RemoveExpiredAsync(CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();
        await using var scope = scopeFactory.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<TDbContext>();
        return await database.Set<SignaCoreSessionTicketEntity>()
            .Where(ticket => ticket.ExpiresUtc <= now)
            .ExecuteDeleteAsync(cancellationToken);
    }

    private static Task<int> DeleteAsync(
        TDbContext database,
        string digest,
        CancellationToken cancellationToken) =>
        database.Set<SignaCoreSessionTicketEntity>()
            .Where(ticket => ticket.KeyDigest == digest)
            .ExecuteDeleteAsync(cancellationToken);

    /// <summary>
    /// The atomic take: one statement deletes the row and returns it. PostgreSQL and SQLite both
    /// speak <c>DELETE ... RETURNING</c>; EF composes <c>FromSql</c> into a subquery, which
    /// PostgreSQL rejects for a top-level <c>DELETE</c>, so the statement runs as a plain
    /// parameterized ADO command against the context's own connection. The digest and the UTC
    /// expiry bound are bind parameters — in the same UTC <see cref="DateTime"/> shape the column
    /// conversion stores — never interpolated SQL text.
    /// </summary>
    private static async Task<SignaCoreSessionTicketEntity?> TakeRowAsync(
        TDbContext database,
        string digest,
        CancellationToken cancellationToken)
    {
        var connection = database.Database.GetDbConnection();
        var command = connection.CreateCommand();
        command.CommandText = $"""
            DELETE FROM {SignaCoreTicketStoreModelBuilderExtensions.TableName}
            WHERE "KeyDigest" = @digest AND "ExpiresUtc" > @now
            RETURNING "KeyDigest", "Payload", "IssuedUtc", "ExpiresUtc"
            """;
        var digestParameter = command.CreateParameter();
        digestParameter.ParameterName = "@digest";
        digestParameter.Value = digest;
        command.Parameters.Add(digestParameter);
        var nowParameter = command.CreateParameter();
        nowParameter.ParameterName = "@now";
        nowParameter.Value = DateTimeOffset.UtcNow.UtcDateTime;
        command.Parameters.Add(nowParameter);

        if (connection.State != System.Data.ConnectionState.Open)
        {
            await connection.OpenAsync(cancellationToken);
        }

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var issued = DateTime.SpecifyKind(
            reader.GetFieldValue<DateTime>(2), DateTimeKind.Utc);
        var expires = DateTime.SpecifyKind(
            reader.GetFieldValue<DateTime>(3), DateTimeKind.Utc);
        return new SignaCoreSessionTicketEntity
        {
            KeyDigest = reader.GetString(0),
            Payload = reader.GetFieldValue<byte[]>(1),
            IssuedUtc = new DateTimeOffset(issued, TimeSpan.Zero),
            ExpiresUtc = new DateTimeOffset(expires, TimeSpan.Zero)
        };
    }

    private byte[] Serialize(
        global::SignaCore.Client.AspNetCore.SignaCoreSessionTicket ticket)
    {
        var properties = new AuthenticationProperties
        {
            IssuedUtc = ticket.IssuedUtc,
            ExpiresUtc = ticket.ExpiresUtc,
            Items =
            {
                [AccessTokenItemKey] = ticket.AccessToken,
                [IdTokenItemKey] = ticket.IdToken
            }
        };
        // A fixed scheme name keeps the round-trip self-describing; the consumer's principal and
        // its identity's own authentication type are preserved by the serializer.
        var serialized = Serializer.Serialize(
            new AuthenticationTicket(ticket.Principal, properties, RoundTripSchemeName));
        return _protector.Protect(serialized);
    }

    private global::SignaCore.Client.AspNetCore.SignaCoreSessionTicket Deserialize(
        SignaCoreSessionTicketEntity entity)
    {
        var ticket = Serializer.Deserialize(_protector.Unprotect(entity.Payload))
            ?? throw new InvalidOperationException("The ticket payload did not deserialize.");
        // The serializer round-trips the principal with its identities and claim sets intact; the
        // session handler re-asserts the authentication type when it serves a request.
        var issuedUtc = ticket.Properties.IssuedUtc ?? entity.IssuedUtc;
        var expiresUtc = ticket.Properties.ExpiresUtc ?? entity.ExpiresUtc;
        var accessToken = ticket.Properties.Items.TryGetValue(AccessTokenItemKey, out var access)
            ? access
            : string.Empty;
        var idToken = ticket.Properties.Items.TryGetValue(IdTokenItemKey, out var id)
            ? id
            : string.Empty;
        return new global::SignaCore.Client.AspNetCore.SignaCoreSessionTicket(
            ticket.Principal, issuedUtc, expiresUtc, accessToken ?? string.Empty,
            idToken ?? string.Empty);
    }

    private const string AccessTokenItemKey = "..access_token";
    private const string IdTokenItemKey = "..id_token";
    private const string RoundTripSchemeName =
        "SignaCore.Client.AspNetCore.EntityFrameworkCore.Ticket";

    private static string Digest(string key)
    {
        var digest = SHA256.HashData(Encoding.ASCII.GetBytes(key));
        return Convert.ToBase64String(digest);
    }

    private static string NewKey()
    {
        Span<byte> entropy = stackalloc byte[32];
        RandomNumberGenerator.Fill(entropy);
        return Convert.ToBase64String(entropy).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}

/// <summary>
/// The bounded operation log of the persistent ticket store: two fixed categories, no message
/// text, no exception, and by construction no SQL, connection string, key, token, or principal.
/// </summary>
internal static class SignaCoreTicketStoreLog
{
    internal static void Unavailable(
        ILogger? logger,
        string operation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        logger?.LogInformation(
            "SignaCore ticket store operation failed closed. Operation: {Operation} Outcome: {Outcome}",
            operation,
            "ticket_store_unavailable");
    }

    internal static void Corrupt(ILogger? logger, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        logger?.LogInformation(
            "SignaCore ticket store record was unreadable and was removed. Operation: retrieve Outcome: {Outcome}",
            "ticket_record_corrupt");
    }
}
