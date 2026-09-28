using System.Globalization;
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

public sealed partial class OidcMultiInstanceAcceptanceTests
{
    private const string PublicOfflineScope = "openid profile offline_access";

    /// <summary>
    /// EV-09/EV-11 against a Public offline code redemption on another PostgreSQL instance. A
    /// test transaction holds the application row lock while both requests queue behind it in a
    /// forced order, then releases it. Redemption first: the root commits and the later
    /// administrative transaction revokes it. Administration first: the redemption observes the
    /// committed change and fails without a root. Either way no interactive family of the
    /// application stays usable after the administrative change commits.
    /// </summary>
    [Theory]
    [InlineData("refresh-capability")]
    [InlineData("application")]
    public async Task PublicCodeDatabaseContractTests_PostgreSql_AdministrativeRevocationSerializesWithRedemption(
        string change)
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true",
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true for the PostgreSQL HTTP matrix.");
        var token = TestContext.Current.CancellationToken;
        await using var container = new PostgreSqlBuilder(Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE")
            ?? "public.ecr.aws/docker/library/postgres:15-alpine").Build();
        await container.StartAsync(token);
        var database = new DatabaseOptions
        { Provider = "PostgreSQL", ServerVersion = "15", ConnectionString = container.GetConnectionString() };
        var options = new DbContextOptionsBuilder<IdentityDbContext>();
        options.UseIdentityDatabase(database);
        await using var setupContext = new IdentityDbContext(options.Options);
        var bootstrap = await setupContext.Database.CreateExecutionStrategy().ExecuteAsync(() =>
            InstallationTestSupport.PrepareCompletedInstallationAsync(
                Path.Combine(_workingDirectory, "public-revocation-" + change), database,
                RootSecretOf("public-revocation"), AdminUsername, AdminPassword));
        using var a = CreateInstance(bootstrap);
        using var b = CreateInstance(bootstrap);
        var cookie = await LoginOnInstanceAsync(a);
        await EnablePublicOfflineAsync(a, token);
        using var admin = NonRedirectingClient(a);
        admin.DefaultRequestHeaders.Add("Cookie", await LoginManagementAsync(a));
        admin.DefaultRequestHeaders.Add("X-ServiceMantle-Request", "1");
        var authorizeUrl = BuildSuccessAuthorizeUrl().Replace(
            Uri.EscapeDataString(SuccessScope), Uri.EscapeDataString(PublicOfflineScope), StringComparison.Ordinal);

        // Redemption queues first: its root commits, then the administrative revocation sees it.
        var firstCode = ExtractQueryValue(await AuthorizeWithIdentityCookieAsync(b, authorizeUrl, cookie), "code");
        var (firstRedemption, firstChange) = await RaceBehindApplicationLockAsync(
            container.GetConnectionString(),
            () => RedeemPublicAsync(b, firstCode, token),
            () => ChangeApplicationAsync(admin, change, token),
            token);
        using (firstRedemption)
        using (firstChange)
        {
            Assert.Equal(HttpStatusCode.OK, firstChange.StatusCode);
            Assert.Equal(HttpStatusCode.OK, firstRedemption.StatusCode);
            var issued = await firstRedemption.Content.ReadFromJsonAsync<JsonElement>(token);
            Assert.True(issued.TryGetProperty("refresh_token", out _));
        }

        await using (var verification = new IdentityDbContext(options.Options))
        {
            var root = Assert.Single(await verification.RefreshTokens.AsNoTracking()
                .Where(row => row.AppId == SuccessAppId && row.ParentId == null).ToListAsync(token));
            Assert.StartsWith("sha256-public:", root.TokenValue, StringComparison.Ordinal);
            Assert.True(root.IsRevoked, "The administrative change left the committed Public root usable.");
            await AssertNoUsableInteractiveFamilyAsync(verification, token);
        }

        // Administration queues first: the redemption observes the committed change.
        await EnablePublicOfflineAsync(a, token);
        var secondCode = ExtractQueryValue(await AuthorizeWithIdentityCookieAsync(b, authorizeUrl, cookie), "code");
        var (secondChange, secondRedemption) = await RaceBehindApplicationLockAsync(
            container.GetConnectionString(),
            () => ChangeApplicationAsync(admin, change, token),
            () => RedeemPublicAsync(b, secondCode, token),
            token);
        using (secondRedemption)
        using (secondChange)
        {
            Assert.Equal(HttpStatusCode.OK, secondChange.StatusCode);
            await AssertCodeFailureAsync(secondRedemption, "invalid_grant");
        }

        await using (var verification = new IdentityDbContext(options.Options))
        {
            Assert.Single(await verification.RefreshTokens.AsNoTracking()
                .Where(row => row.AppId == SuccessAppId && row.ParentId == null).ToListAsync(token));
            var rejected = await verification.AuthorizationCodes.AsNoTracking().SingleAsync(
                row => row.CodeDigest == AuthorizationCodeDigest.Compute(secondCode), token);
            Assert.Null(rejected.ConsumedAt);
            Assert.Null(rejected.RefreshFamilyId);
            await AssertNoUsableInteractiveFamilyAsync(verification, token);
        }
    }

    /// <summary>
    /// Holds the application row lock in a separate transaction, starts <paramref name="first"/>
    /// and waits until it queues on a row lock, then starts <paramref name="second"/> and waits
    /// until it queues too. Releasing the lock grants the row in that order.
    /// </summary>
    private static async Task<(HttpResponseMessage First, HttpResponseMessage Second)> RaceBehindApplicationLockAsync(
        string connectionString,
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
            await using (var lockCommand = new NpgsqlCommand(
                "SELECT id FROM app_registrations WHERE app_id = @appId FOR UPDATE", holder, transaction))
            {
                lockCommand.Parameters.AddWithValue("appId", SuccessAppId);
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

    private static async Task WaitForLockWaitersAsync(
        string connectionString,
        int expected,
        Task started,
        CancellationToken cancellationToken)
    {
        var begun = TimeProvider.System.GetTimestamp();
        while (TimeProvider.System.GetElapsedTime(begun) < TimeSpan.FromSeconds(30))
        {
            Assert.False(started.IsCompleted, "A request finished without waiting for the application row lock.");
            await using var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var command = new NpgsqlCommand(
                "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()",
                connection);
            var waiting = Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
            if (waiting >= expected)
            {
                return;
            }

            await Task.Delay(20, cancellationToken);
        }

        Assert.Fail($"Expected {expected} sessions waiting for the application row lock.");
    }

    private static async Task EnablePublicOfflineAsync(
        WebApplicationFactory<Program> host,
        CancellationToken cancellationToken)
    {
        using var scope = host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var app = await db.AppRegistrations.SingleAsync(row => row.AppId == SuccessAppId, cancellationToken);
        app.IsActive = true;
        app.ClientType = OidcClientType.Public;
        app.AppSecretHash = string.Empty;
        app.AllowRefreshToken = true;
        app.AllowedScopes = PublicOfflineScope;
        app.IdentitySessionMaxAgeSeconds = 3600;
        await db.SaveChangesAsync(cancellationToken);
    }

    private static async Task<HttpResponseMessage> RedeemPublicAsync(
        WebApplicationFactory<Program> host,
        string code,
        CancellationToken cancellationToken)
    {
        using var http = NonRedirectingClient(host);
        var fields = CodeFields(code);
        fields["client_id"] = SuccessAppId;
        return await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(fields), cancellationToken);
    }

    private static Task<HttpResponseMessage> ChangeApplicationAsync(
        HttpClient admin,
        string change,
        CancellationToken cancellationToken) => change == "application"
        ? admin.PutAsJsonAsync($"/api/admin/apps/{SuccessAppId}/callback",
            new { callbackUrl = (string?)null, ttlSeconds = 0, isActive = false }, cancellationToken)
        : admin.PutAsJsonAsync($"/api/admin/apps/{SuccessAppId}/oidc-policy",
            new
            {
                clientType = "Public", allowAuthorizationCode = true,
                allowedScopes = new[] { "openid", "profile" }, allowRefreshToken = false,
                identitySessionMaxAgeSeconds = (int?)null
            },
            cancellationToken);

    private static async Task AssertNoUsableInteractiveFamilyAsync(
        IdentityDbContext verification,
        CancellationToken cancellationToken) =>
        Assert.False(
            await verification.RefreshTokens.AsNoTracking().AnyAsync(
                row => row.AppId == SuccessAppId && row.IdentitySessionId != null && !row.IsRevoked,
                cancellationToken),
            "An interactive family of the changed application is still unrevoked.");
}
