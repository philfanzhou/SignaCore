using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Host.Services;
using Xunit;

namespace SignaCore.Tests.Host.Services;

/// <summary>
/// The <c>IN-31</c>–<c>IN-33</c> preparation judgement as a unit over one fixed signing key: the
/// admitted token shape, every rejected dimension, the exact <c>IN-32</c> ordinal match, and the
/// <c>IN-33</c> state bound.
/// </summary>
public sealed class OidcLogoutPreparationServiceTests
{
    private const string Issuer = "https://logout-unit.test";
    private const string ClientId = "logout-unit-app";
    private const string Secret = "logout-unit-secret";

    private sealed class StaticKeyManager : IKeyManager
    {
        private readonly RsaSecurityKey _key = new(RSA.Create(2048)) { KeyId = "unit-key" };

        public RsaSecurityKey GetCurrentKey() => _key;
        public IReadOnlyList<SecurityKey> GetValidationKeys() => [_key];
        public Task RefreshKeysAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<IReadOnlyList<RsaSecurityKey>> GetValidKeysAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<RsaSecurityKey>>([_key]);
        public Task<IReadOnlyList<RsaSecurityKey>> GetLogoutHintValidationKeysAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<RsaSecurityKey>>([_key]);
        public Task<bool> NeedsKeyRotationAsync(CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task RotateKeyAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task InitializationCompleted => Task.CompletedTask;
    }

    private sealed record Harness(
        SqliteConnection Connection,
        IdentityDbContext Context,
        OidcLogoutPreparationService Service,
        StaticKeyManager Keys,
        Guid ApplicationId) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await Connection.DisposeAsync();
        }
    }

    private static async Task<Harness> CreateHarnessAsync()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        var context = new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlite(connection).Options);
        await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);

        var application = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = ClientId,
            AppSecretHash = "hash",
            AppName = "Logout Unit App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = AudienceMode.PerApplication,
            ClientType = OidcClientType.Confidential,
            AllowAuthorizationCode = true,
            AllowedScopes = "openid profile",
            AllowRefreshToken = false
        };
        context.AppRegistrations.Add(application);
        context.AppRedirectUris.Add(new AppRedirectUriEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = application.Id,
            Kind = RedirectUriKind.PostLogout,
            CanonicalUri = "https://bff.logout-unit.test/logged-out"
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();

        var unitOfWork = new EfCoreUnitOfWork(context);
        var keys = new StaticKeyManager();
        var service = new OidcLogoutPreparationService(
            new LogoutRequestStore(new LogoutRequestRepository(context), unitOfWork),
            keys,
            new AuditService(new LoginHistoryRepository(context), new AuditLogRepository(context)),
            context,
            new JwtOptions { Issuer = Issuer },
            NullLogger<OidcLogoutPreparationService>.Instance);
        return new Harness(connection, context, service, keys, application.Id);
    }

    private static string Mint(
        Harness harness,
        Guid? subject = null,
        Guid? sessionId = null,
        string? issuer = null,
        string? audience = null,
        RsaSecurityKey? key = null,
        DateTime? issuedAt = null,
        bool withSub = true,
        bool withSid = true,
        bool withIat = true)
    {
        var claims = new List<Claim>();
        if (withSub)
        {
            claims.Add(new Claim("sub", (subject ?? Guid.NewGuid()).ToString("D")));
        }

        if (withSid)
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Sid, (sessionId ?? Guid.NewGuid()).ToString("D")));
        }

        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            new JwtHeader(new SigningCredentials(key ?? harness.Keys.GetCurrentKey(), "RS256")),
            new JwtPayload(
                issuer ?? Issuer,
                audience ?? ClientId,
                claims,
                notBefore: null,
                expires: null,
                issuedAt: withIat ? issuedAt ?? DateTime.UtcNow.AddMinutes(-5) : null)));
    }

    private static Dictionary<string, string> Fields(string idToken, string? uri = null, string? state = null)
    {
        var fields = new Dictionary<string, string> { ["id_token_hint"] = idToken };
        if (uri is not null)
        {
            fields["post_logout_redirect_uri"] = uri;
        }

        if (state is not null)
        {
            fields["state"] = state;
        }

        return fields;
    }

    [Fact]
    public async Task PrepareAsync_WithAValidHint_Succeeds()
    {
        await using var harness = await CreateHarnessAsync();

        var result = await harness.Service.PrepareAsync(
            await Context(harness), Fields(Mint(harness)), null, null, TestContext.Current.CancellationToken);

        Assert.NotNull(result);
        Assert.StartsWith("/oauth2/logout?logout_handle=", result.LogoutUri, StringComparison.Ordinal);
    }

    private static Task<AppRegistrationEntity> Context(Harness harness) =>
        harness.Context.AppRegistrations.AsNoTracking()
            .SingleAsync(app => app.Id == harness.ApplicationId, TestContext.Current.CancellationToken);

    [Fact]
    public async Task PrepareAsync_IgnoresExpiryButNotFreshness()
    {
        await using var harness = await CreateHarnessAsync();

        var expiredToken = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            new JwtHeader(new SigningCredentials(harness.Keys.GetCurrentKey(), "RS256")),
            new JwtPayload(
                Issuer,
                ClientId,
                [new Claim("sub", Guid.NewGuid().ToString("D")), new Claim("sid", Guid.NewGuid().ToString("D"))],
                notBefore: null,
                expires: DateTime.UtcNow.AddHours(-1),
                issuedAt: DateTime.UtcNow.AddMinutes(-5))));

        var result = await harness.Service.PrepareAsync(
            await Context(harness), Fields(expiredToken), null, null, TestContext.Current.CancellationToken);
        Assert.NotNull(result);
    }

    [Fact]
    public async Task PrepareAsync_RejectsEveryInvalidDimension()
    {
        await using var harness = await CreateHarnessAsync();
        var app = await Context(harness);
        var foreignKey = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "foreign" };

        var cases = new (string Name, string Token)[]
        {
            ("wrong issuer", Mint(harness, issuer: "https://attacker.test")),
            ("wrong audience", Mint(harness, audience: "other-client")),
            ("foreign key", Mint(harness, key: foreignKey)),
            ("missing sub", Mint(harness, withSub: false)),
            ("missing sid", Mint(harness, withSid: false)),
            ("missing iat", Mint(harness, withIat: false)),
            ("iat too old", Mint(harness, issuedAt: DateTime.UtcNow.AddHours(25))),
            ("iat in the future", Mint(harness, issuedAt: DateTime.UtcNow.AddHours(2))),
            ("not a jws", "garbage-not-a-token")
        };

        foreach (var (name, token) in cases)
        {
            _ = name;
            Assert.Null(await harness.Service.PrepareAsync(
                app, Fields(token), null, null, TestContext.Current.CancellationToken));
        }
    }

    [Fact]
    public async Task PrepareAsync_MatchesThePostLogoutUriOrdinally()
    {
        await using var harness = await CreateHarnessAsync();
        var app = await Context(harness);
        const string registered = "https://bff.logout-unit.test/logged-out";
        var token = Mint(harness);

        Assert.NotNull(await harness.Service.PrepareAsync(
            app, Fields(token, uri: registered), null, null, TestContext.Current.CancellationToken));
        Assert.Null(await harness.Service.PrepareAsync(
            app, Fields(token, uri: registered + "/"), null, null, TestContext.Current.CancellationToken));
        Assert.Null(await harness.Service.PrepareAsync(
            app, Fields(token, uri: registered.ToUpperInvariant()), null, null, TestContext.Current.CancellationToken));
        Assert.Null(await harness.Service.PrepareAsync(
            app, Fields(token, uri: "https://evil.example.net/logged-out"), null, null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task PrepareAsync_EnforcesTheStateBound()
    {
        await using var harness = await CreateHarnessAsync();
        var app = await Context(harness);
        var token = Mint(harness);

        Assert.NotNull(await harness.Service.PrepareAsync(
            app, Fields(token, state: "unit-state-0123456789abcdef"), null, null, TestContext.Current.CancellationToken));
        Assert.Null(await harness.Service.PrepareAsync(
            app, Fields(token, state: "too-short"), null, null, TestContext.Current.CancellationToken));
        Assert.Null(await harness.Service.PrepareAsync(
            app, Fields(token, state: new string('s', 129)), null, null, TestContext.Current.CancellationToken));
        Assert.Null(await harness.Service.PrepareAsync(
            app, Fields(token, state: "unit state 0123456789abcd!"), null, null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task PrepareAsync_RejectsAnInactiveApplicationAndMalformedFields()
    {
        await using var harness = await CreateHarnessAsync();
        var tracked = await harness.Context.AppRegistrations
            .SingleAsync(app => app.Id == harness.ApplicationId, TestContext.Current.CancellationToken);
        tracked.IsActive = false;
        await harness.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        harness.Context.ChangeTracker.Clear();
        var inactive = await Context(harness);

        Assert.Null(await harness.Service.PrepareAsync(
            inactive, Fields(Mint(harness)), null, null, TestContext.Current.CancellationToken));

        tracked = await harness.Context.AppRegistrations
            .SingleAsync(app => app.Id == harness.ApplicationId, TestContext.Current.CancellationToken);
        tracked.IsActive = true;
        await harness.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        harness.Context.ChangeTracker.Clear();
        var active = await Context(harness);

        Assert.Null(await harness.Service.PrepareAsync(
            active,
            new Dictionary<string, string> { ["id_token_hint"] = new string('x', IdentityConstants.MaxLogoutIdTokenHintLength + 1) },
            null, null, TestContext.Current.CancellationToken));
    }
}
