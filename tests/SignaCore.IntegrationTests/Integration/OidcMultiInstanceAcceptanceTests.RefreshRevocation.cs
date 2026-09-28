using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services;
using SignaCore.Host;
using SignaCore.Host.Startup;
using Testcontainers.PostgreSql;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// EV-09/EV-11 against the writers of interactive family members — refresh rotation (child) and
/// Confidential offline code redemption (root) — on another PostgreSQL instance. Each writer takes
/// a shared lock on the application row after the session (and code) lock and before the family
/// rows, so an administrative deactivation or refresh-off either commits before the writer's
/// policy read or waits for its commit and then revokes what it wrote.
/// </summary>
public sealed partial class OidcMultiInstanceAcceptanceTests
{
    private const string OfflineScope = "openid profile offline_access";

    /// <summary>
    /// Rotation first: a test transaction holds the root row, the rotation queues on it while
    /// holding the application share lock, and the administrative change queues behind that
    /// share lock. The committed child is revoked together with the root and stays unusable after
    /// the application is re-enabled. Administration first: the change holds the application row,
    /// the rotation queues on its share lock, then observes the committed change and fails
    /// without consuming the parent or writing a child.
    /// </summary>
    [Theory]
    [InlineData("application", OidcClientType.Public)]
    [InlineData("refresh-capability", OidcClientType.Public)]
    [InlineData("application", OidcClientType.Confidential)]
    [InlineData("refresh-capability", OidcClientType.Confidential)]
    public async Task RefreshRotationDatabaseContractTests_PostgreSql_AdministrativeRevocationSerializesWithRotation(
        string change,
        OidcClientType clientType)
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true",
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true for the PostgreSQL HTTP matrix.");
        var token = TestContext.Current.CancellationToken;
        await using var container = await StartPostgreSqlAsync(token);
        var options = await PrepareOnPostgreSqlAsync(container, $"rotation-revocation-{change}-{clientType}", token);
        var bootstrap = options.Bootstrap;
        using var a = CreateInstance(bootstrap);
        using var b = CreateInstance(bootstrap);
        var cookie = await LoginOnInstanceAsync(a);
        await EnableOfflineAsync(a, clientType, token);
        using var admin = await AdminClientAsync(a);

        // Rotation queues first: its child commits, then the administrative revocation sees it.
        var root = await RedeemOfflineRootAsync(b, clientType, cookie, token);
        var rootId = await MemberIdAsync(options.Context, root, clientType, token);
        var (rotation, firstChange) = await RaceBehindRowLockAsync(
            container.GetConnectionString(),
            "SELECT id FROM refresh_tokens WHERE id = @id FOR UPDATE",
            rootId,
            () => RotateAsync(b, clientType, root, token),
            () => ChangeAsync(admin, change, clientType, token),
            token);
        string child;
        using (rotation)
        using (firstChange)
        {
            Assert.Equal(HttpStatusCode.OK, firstChange.StatusCode);
            Assert.Equal(HttpStatusCode.OK, rotation.StatusCode);
            child = (await rotation.Content.ReadFromJsonAsync<JsonElement>(token))
                .GetProperty("refresh_token").GetString()!;
        }

        await using (var verification = new IdentityDbContext(options.Context))
        {
            var family = await verification.RefreshTokens.AsNoTracking()
                .Where(row => row.FamilyId == rootId).ToListAsync(token);
            Assert.Equal(2, family.Count);
            Assert.NotNull(Assert.Single(family, row => row.Id == rootId).ConsumedAt);
            Assert.All(family, row => Assert.True(row.IsRevoked, "The administrative change left a family member usable."));
            await AssertNoUsableInteractiveFamilyAsync(verification, token);
        }

        await EnableOfflineAsync(a, clientType, token);
        using (var revokedChild = await RotateAsync(b, clientType, child, token))
        {
            await AssertCodeFailureAsync(revokedChild, "invalid_grant");
        }

        // Administration queues first: the rotation observes the committed change and fails closed.
        var secondRoot = await RedeemOfflineRootAsync(b, clientType, cookie, token);
        var secondRootId = await MemberIdAsync(options.Context, secondRoot, clientType, token);
        var (secondChange, rejected) = await RaceBehindRowLockAsync(
            container.GetConnectionString(),
            "SELECT id FROM app_registrations WHERE app_id = @id FOR UPDATE",
            SuccessAppId,
            () => ChangeAsync(admin, change, clientType, token),
            () => RotateAsync(b, clientType, secondRoot, token),
            token);
        using (secondChange)
        using (rejected)
        {
            Assert.Equal(HttpStatusCode.OK, secondChange.StatusCode);
            await AssertCodeFailureAsync(rejected, "invalid_grant");
        }

        await using (var verification = new IdentityDbContext(options.Context))
        {
            var family = await verification.RefreshTokens.AsNoTracking()
                .Where(row => row.FamilyId == secondRootId).ToListAsync(token);
            var parent = Assert.Single(family);
            Assert.Null(parent.ConsumedAt);
            Assert.True(parent.IsRevoked, "The administrative change left the parent usable.");
            await AssertNoUsableInteractiveFamilyAsync(verification, token);
        }
    }

    /// <summary>
    /// The Confidential offline code redemption writes a root, so it takes the same application
    /// share lock after its session and code locks. Redemption first: the root commits and the
    /// deactivation revokes it. Deactivation first: the redemption observes the inactive
    /// application, leaves the code unconsumed, and writes no root.
    /// </summary>
    [Fact]
    public async Task RedemptionDatabaseContractTests_PostgreSql_ConfidentialOfflineRedemptionSerializesWithDeactivation()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true",
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true for the PostgreSQL HTTP matrix.");
        var token = TestContext.Current.CancellationToken;
        await using var container = await StartPostgreSqlAsync(token);
        var options = await PrepareOnPostgreSqlAsync(container, "confidential-redemption-revocation", token);
        using var a = CreateInstance(options.Bootstrap);
        using var b = CreateInstance(options.Bootstrap);
        var cookie = await LoginOnInstanceAsync(a);
        await EnableOfflineAsync(a, OidcClientType.Confidential, token);
        using var admin = await AdminClientAsync(a);
        var offlineUrl = OfflineAuthorizeUrl();

        var firstCode = ExtractQueryValue(await AuthorizeWithIdentityCookieAsync(b, offlineUrl, cookie), "code");
        var (redemption, firstChange) = await RaceBehindRowLockAsync(
            container.GetConnectionString(),
            "SELECT id FROM app_registrations WHERE app_id = @id FOR UPDATE",
            SuccessAppId,
            () => SendCodeAsync(b, CodeFields(firstCode)),
            () => ChangeAsync(admin, "application", OidcClientType.Confidential, token),
            token);
        using (redemption)
        using (firstChange)
        {
            Assert.Equal(HttpStatusCode.OK, firstChange.StatusCode);
            Assert.Equal(HttpStatusCode.OK, redemption.StatusCode);
            var issued = await redemption.Content.ReadFromJsonAsync<JsonElement>(token);
            Assert.True(issued.TryGetProperty("refresh_token", out _));
        }

        await using (var verification = new IdentityDbContext(options.Context))
        {
            var root = Assert.Single(await verification.RefreshTokens.AsNoTracking()
                .Where(row => row.AppId == SuccessAppId && row.ParentId == null).ToListAsync(token));
            Assert.True(root.IsRevoked, "The deactivation left the committed Confidential root usable.");
            await AssertNoUsableInteractiveFamilyAsync(verification, token);
        }

        await EnableOfflineAsync(a, OidcClientType.Confidential, token);
        var secondCode = ExtractQueryValue(await AuthorizeWithIdentityCookieAsync(b, offlineUrl, cookie), "code");
        var (secondChange, rejected) = await RaceBehindRowLockAsync(
            container.GetConnectionString(),
            "SELECT id FROM app_registrations WHERE app_id = @id FOR UPDATE",
            SuccessAppId,
            () => ChangeAsync(admin, "application", OidcClientType.Confidential, token),
            () => SendCodeAsync(b, CodeFields(secondCode)),
            token);
        using (secondChange)
        using (rejected)
        {
            Assert.Equal(HttpStatusCode.OK, secondChange.StatusCode);
            await AssertCodeFailureAsync(rejected, "invalid_grant");
        }

        await using (var verification = new IdentityDbContext(options.Context))
        {
            Assert.Single(await verification.RefreshTokens.AsNoTracking()
                .Where(row => row.AppId == SuccessAppId && row.ParentId == null).ToListAsync(token));
            var code = await verification.AuthorizationCodes.AsNoTracking().SingleAsync(
                row => row.CodeDigest == AuthorizationCodeDigest.Compute(secondCode), token);
            Assert.Null(code.ConsumedAt);
            Assert.Null(code.RefreshFamilyId);
            await AssertNoUsableInteractiveFamilyAsync(verification, token);
        }
    }

    /// <summary>
    /// The application lock is shared among family writers: while one rotation holds it and waits
    /// on its own root row, a rotation of another family of the same application completes.
    /// </summary>
    [Fact]
    public async Task RefreshRotationDatabaseContractTests_PostgreSql_DifferentFamiliesOfOneApplicationDoNotSerialize()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true",
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true for the PostgreSQL HTTP matrix.");
        var token = TestContext.Current.CancellationToken;
        await using var container = await StartPostgreSqlAsync(token);
        var options = await PrepareOnPostgreSqlAsync(container, "rotation-shared-lock", token);
        using var a = CreateInstance(options.Bootstrap);
        using var b = CreateInstance(options.Bootstrap);
        // Two sign-ins give two identity sessions, so the families share only the application.
        var firstCookie = await LoginOnInstanceAsync(a);
        var secondCookie = await LoginOnInstanceAsync(b);
        Assert.NotEqual(firstCookie, secondCookie);
        await EnableOfflineAsync(a, OidcClientType.Confidential, token);
        var firstRoot = await RedeemOfflineRootAsync(a, OidcClientType.Confidential, firstCookie, token);
        var secondRoot = await RedeemOfflineRootAsync(b, OidcClientType.Confidential, secondCookie, token);
        var firstRootId = await MemberIdAsync(options.Context, firstRoot, OidcClientType.Confidential, token);

        await using var holder = new NpgsqlConnection(container.GetConnectionString());
        await holder.OpenAsync(token);
        Task<HttpResponseMessage> blocked;
        await using (var transaction = await holder.BeginTransactionAsync(token))
        {
            await using (var lockCommand = new NpgsqlCommand(
                "SELECT id FROM refresh_tokens WHERE id = @id FOR UPDATE", holder, transaction))
            {
                lockCommand.Parameters.AddWithValue("id", firstRootId);
                Assert.NotNull(await lockCommand.ExecuteScalarAsync(token));
            }

            blocked = Task.Run(() => RotateAsync(b, OidcClientType.Confidential, firstRoot, token), token);
            await WaitForLockWaitersAsync(container.GetConnectionString(), 1, blocked, token);
            using (var independent = await RotateAsync(a, OidcClientType.Confidential, secondRoot, token)
                       .WaitAsync(TimeSpan.FromSeconds(20), token))
            {
                Assert.Equal(HttpStatusCode.OK, independent.StatusCode);
            }

            Assert.False(blocked.IsCompleted, "The held root lock did not keep the first rotation waiting.");
            await transaction.CommitAsync(token);
        }

        using var released = await blocked;
        Assert.Equal(HttpStatusCode.OK, released.StatusCode);
    }

    /// <summary>
    /// SQLite serializes writers, so a rotation racing a deactivation on one instance ends in one
    /// of the two serial outcomes: afterwards the application has no usable interactive member and
    /// neither the root nor any child is accepted once the application is active again.
    /// </summary>
    [Fact]
    public async Task RefreshRotation_Sqlite_ConcurrentDeactivationLeavesNoUsableFamily()
    {
        var token = TestContext.Current.CancellationToken;
        using var host = CreateInstance();
        var cookie = await LoginOnInstanceAsync(host);
        await EnableOfflineAsync(host, OidcClientType.Confidential, token);
        using var admin = await AdminClientAsync(host);
        var root = await RedeemOfflineRootAsync(host, OidcClientType.Confidential, cookie, token);

        var rotationTask = RotateAsync(host, OidcClientType.Confidential, root, token);
        var changeTask = ChangeAsync(admin, "application", OidcClientType.Confidential, token);
        await Task.WhenAll(rotationTask, changeTask);
        using var rotation = await rotationTask;
        using var change = await changeTask;
        Assert.Equal(HttpStatusCode.OK, change.StatusCode);
        var presented = new List<string> { root };
        if (rotation.StatusCode == HttpStatusCode.OK)
        {
            presented.Add((await rotation.Content.ReadFromJsonAsync<JsonElement>(token))
                .GetProperty("refresh_token").GetString()!);
        }
        else
        {
            await AssertCodeFailureAsync(rotation, "invalid_grant");
        }

        using (var scope = host.Services.CreateScope())
        {
            await AssertNoUsableInteractiveFamilyAsync(
                scope.ServiceProvider.GetRequiredService<IdentityDbContext>(), token);
        }

        await EnableOfflineAsync(host, OidcClientType.Confidential, token);
        foreach (var member in presented)
        {
            using var response = await RotateAsync(host, OidcClientType.Confidential, member, token);
            await AssertCodeFailureAsync(response, "invalid_grant");
        }
    }

    private sealed record PostgreSqlInstallation(string Bootstrap, DbContextOptions<IdentityDbContext> Context);

    private static async Task<PostgreSqlContainer> StartPostgreSqlAsync(CancellationToken cancellationToken)
    {
        var container = new PostgreSqlBuilder(Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE")
            ?? "public.ecr.aws/docker/library/postgres:15-alpine").Build();
        await container.StartAsync(cancellationToken);
        return container;
    }

    private async Task<PostgreSqlInstallation> PrepareOnPostgreSqlAsync(
        PostgreSqlContainer container,
        string label,
        CancellationToken cancellationToken)
    {
        var database = new DatabaseOptions
        { Provider = "PostgreSQL", ServerVersion = "15", ConnectionString = container.GetConnectionString() };
        var builder = new DbContextOptionsBuilder<IdentityDbContext>();
        builder.UseIdentityDatabase(database);
        await using var setupContext = new IdentityDbContext(builder.Options);
        var bootstrap = await setupContext.Database.CreateExecutionStrategy().ExecuteAsync(() =>
            InstallationTestSupport.PrepareCompletedInstallationAsync(
                Path.Combine(_workingDirectory, label), database,
                RootSecretOf(label), AdminUsername, AdminPassword));
        cancellationToken.ThrowIfCancellationRequested();
        return new PostgreSqlInstallation(bootstrap, builder.Options);
    }

    private static async Task<HttpClient> AdminClientAsync(WebApplicationFactory<Program> host)
    {
        var admin = NonRedirectingClient(host);
        admin.DefaultRequestHeaders.Add("Cookie", await LoginManagementAsync(host));
        admin.DefaultRequestHeaders.Add("X-ServiceMantle-Request", "1");
        return admin;
    }

    private static string OfflineAuthorizeUrl() => BuildSuccessAuthorizeUrl().Replace(
        Uri.EscapeDataString(SuccessScope), Uri.EscapeDataString(OfflineScope), StringComparison.Ordinal);

    private static async Task EnableOfflineAsync(
        WebApplicationFactory<Program> host,
        OidcClientType clientType,
        CancellationToken cancellationToken)
    {
        if (clientType == OidcClientType.Public)
        {
            await EnablePublicOfflineAsync(host, cancellationToken);
            return;
        }

        using var scope = host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var app = await db.AppRegistrations.SingleAsync(row => row.AppId == SuccessAppId, cancellationToken);
        app.IsActive = true;
        app.AllowRefreshToken = true;
        app.AllowedScopes = OfflineScope;
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task<string> RedeemOfflineRootAsync(
        WebApplicationFactory<Program> host,
        OidcClientType clientType,
        string cookie,
        CancellationToken cancellationToken)
    {
        var code = ExtractQueryValue(await AuthorizeWithIdentityCookieAsync(host, OfflineAuthorizeUrl(), cookie), "code");
        using var response = clientType == OidcClientType.Public
            ? await RedeemPublicAsync(host, code, cancellationToken)
            : await SendCodeAsync(host, CodeFields(code));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken))
            .GetProperty("refresh_token").GetString()!;
    }

    private static async Task<Guid> MemberIdAsync(
        DbContextOptions<IdentityDbContext> options,
        string refreshToken,
        OidcClientType clientType,
        CancellationToken cancellationToken)
    {
        var digest = clientType == OidcClientType.Public
            ? RefreshTokenDigest.ComputePublic(refreshToken)
            : RefreshTokenDigest.Compute(refreshToken);
        await using var db = new IdentityDbContext(options);
        return (await db.RefreshTokens.AsNoTracking().SingleAsync(row => row.TokenValue == digest, cancellationToken)).Id;
    }

    private static async Task<HttpResponseMessage> RotateAsync(
        WebApplicationFactory<Program> host,
        OidcClientType clientType,
        string refreshToken,
        CancellationToken cancellationToken)
    {
        if (clientType == OidcClientType.Confidential)
        {
            return await RefreshPostAsync(host, refreshToken);
        }

        using var http = NonRedirectingClient(host);
        return await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token", ["client_id"] = SuccessAppId, ["refresh_token"] = refreshToken
        }), cancellationToken);
    }

    private static Task<HttpResponseMessage> ChangeAsync(
        HttpClient admin,
        string change,
        OidcClientType clientType,
        CancellationToken cancellationToken) => change == "application"
        ? admin.PutAsJsonAsync($"/api/admin/apps/{SuccessAppId}/callback",
            new { callbackUrl = (string?)null, ttlSeconds = 0, isActive = false }, cancellationToken)
        : admin.PutAsJsonAsync($"/api/admin/apps/{SuccessAppId}/oidc-policy",
            new
            {
                clientType = clientType.ToString(), allowAuthorizationCode = true,
                allowedScopes = new[] { "openid", "profile" }, allowRefreshToken = false,
                identitySessionMaxAgeSeconds = (int?)null
            },
            cancellationToken);

    /// <summary>
    /// Holds one row lock in a separate transaction, starts <paramref name="first"/> and waits
    /// until it queues on a lock, then starts <paramref name="second"/> and waits until it queues
    /// too, then releases the held row.
    /// </summary>
    private static async Task<(HttpResponseMessage First, HttpResponseMessage Second)> RaceBehindRowLockAsync(
        string connectionString,
        string lockSql,
        object id,
        Func<Task<HttpResponseMessage>> first,
        Func<Task<HttpResponseMessage>> second,
        CancellationToken cancellationToken)
    {
        await using var holder = new NpgsqlConnection(connectionString);
        await holder.OpenAsync(cancellationToken);
        Task<HttpResponseMessage> firstTask;
        Task<HttpResponseMessage> secondTask;
        await using (var transaction = await holder.BeginTransactionAsync(cancellationToken))
        {
            await using (var lockCommand = new NpgsqlCommand(lockSql, holder, transaction))
            {
                lockCommand.Parameters.AddWithValue("id", id);
                Assert.NotNull(await lockCommand.ExecuteScalarAsync(cancellationToken));
            }

            firstTask = Task.Run(first, cancellationToken);
            await WaitForLockWaitersAsync(connectionString, 1, firstTask, cancellationToken);
            secondTask = Task.Run(second, cancellationToken);
            await WaitForLockWaitersAsync(connectionString, 2, secondTask, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }

        return (await firstTask, await secondTask);
    }
}
