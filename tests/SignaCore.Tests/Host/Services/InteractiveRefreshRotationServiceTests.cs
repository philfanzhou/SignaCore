using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Host;
using SignaCore.Host.Services;
using Xunit;

namespace SignaCore.Tests.Host.Services;

/// <summary>
/// The interactive refresh rotation as a unit: the <c>EV-29</c> committed shape (conditional
/// consumption, the one child with byte-for-byte root copies, the <c>PS-15</c> outcome with the
/// nonce-free ID token), the <c>EV-31</c> reuse disposal (live descendants only, one id-only
/// audit, session untouched), the <c>EV-32</c> family-revoking rejections and the no-write
/// rejections, the dispatch classification (<c>EV-33</c> legacy fall-through, corrupt partial
/// marker), and the <c>IN-20</c>/<c>IN-26</c>/<c>IN-27</c> input contract.
/// </summary>
public sealed class InteractiveRefreshRotationServiceTests
{
    private const string ClientId = "rotation-unit-app";
    private const string CanonicalScope = "openid profile offline_access";
    private const string Username = "rotation_unit_user";
    private const string CorrelationId = "rotation-unit-correlation-0123";

    [Fact]
    public async Task RotateAsync_CommitsTheConsumptionTheChildAndThePs15Outcome()
    {
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context, scope: CanonicalScope);
        var root = await InsertInteractiveMemberAsync(harness, seed, consumedAt: null);

        var dispatch = await harness.Service.RotateAsync(
            seed.Application,
            CreateForm(root.Plaintext),
            clientCredentialMixPresent: false,
            "203.0.113.9",
            CorrelationId,
            TestContext.Current.CancellationToken);

        Assert.True(dispatch.Handled);
        var outcome = dispatch.Outcome!;
        Assert.True(outcome.IsSuccess);
        Assert.Equal(IdentityConstants.InteractiveAccessTokenLifetimeSeconds, outcome.ExpiresIn);
        Assert.Equal(CanonicalScope, outcome.Scope);
        Assert.NotEqual(outcome.AccessToken, outcome.IdToken);
        Assert.NotEqual(root.Plaintext, outcome.RefreshToken);
        Assert.Equal(43, outcome.RefreshToken!.Length);

        var cancellationToken = TestContext.Current.CancellationToken;
        var rows = await harness.Context.RefreshTokens.AsNoTracking()
            .ToListAsync(cancellationToken);
        var rootRow = Assert.Single(rows, row => row.Id == root.Id);
        var childRow = Assert.Single(rows, row => row.ParentId == root.Id);
        Assert.NotNull(rootRow.ConsumedAt);
        // The child copies the root's bindings and deadline byte for byte; only the parent
        // relationship and the fresh digest are new (EV-29).
        Assert.Equal(root.Id, childRow.FamilyId);
        Assert.Equal(seed.AccountId, childRow.AccountId);
        Assert.Equal(ClientId, childRow.AppId);
        Assert.Equal(seed.SessionId, childRow.IdentitySessionId);
        Assert.Equal(CanonicalScope, childRow.Scope);
        Assert.Equal(rootRow.AuthTime, childRow.AuthTime);
        Assert.Equal(rootRow.ExpiresAt, childRow.ExpiresAt);
        Assert.Null(childRow.ConsumedAt);
        Assert.False(childRow.IsRevoked);
        // DF-09: only the digest is persisted; the plaintext never touches any row or audit.
        Assert.Equal(RefreshTokenDigest.Compute(outcome.RefreshToken), childRow.TokenValue);
        Assert.All(rows, row => Assert.DoesNotContain(outcome.RefreshToken, row.TokenValue, StringComparison.Ordinal));
        Assert.Empty(await harness.Context.AuditLogs.AsNoTracking().ToListAsync(cancellationToken));
        Assert.Null((await harness.Context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seed.SessionId, cancellationToken)).RevokedAt);

        // PS-13: the refreshed access token keeps the closed interactive claim set.
        var token = new JwtSecurityTokenHandler().ReadJwtToken(outcome.AccessToken);
        Assert.Equal(JwtTokenService.AccessTokenType, token.Header.Typ);
        Assert.Equal(ClientId, token.Audiences.Single());
        Assert.Equal(seed.AccountId.ToString(), token.Claims.Single(c => c.Type == IdentityConstants.ClaimSubject).Value);
        Assert.Equal(seed.SessionId.ToString(), token.Claims.Single(c => c.Type == JwtRegisteredClaimNames.Sid).Value);
        Assert.Equal(CanonicalScope, token.Claims.Single(c => c.Type == "scope").Value);

        // PS-15: the refreshed ID token omits the nonce and keeps the original auth facts.
        var idToken = new JwtSecurityTokenHandler().ReadJwtToken(outcome.IdToken);
        Assert.Equal("JWT", idToken.Header.Typ);
        Assert.Equal(ClientId, idToken.Audiences.Single());
        Assert.Equal(seed.AccountId.ToString(), idToken.Claims.Single(c => c.Type == IdentityConstants.ClaimSubject).Value);
        Assert.Equal(seed.SessionId.ToString(), idToken.Claims.Single(c => c.Type == JwtRegisteredClaimNames.Sid).Value);
        Assert.DoesNotContain(idToken.Claims, claim => claim.Type == JwtRegisteredClaimNames.Nonce);
        Assert.Equal("pwd", idToken.Claims.Single(c => c.Type == JwtRegisteredClaimNames.Amr).Value);
        Assert.Equal(
            seed.AuthTime.ToUnixTimeSeconds(),
            long.Parse(idToken.Claims.Single(c => c.Type == JwtRegisteredClaimNames.AuthTime).Value, CultureInfo.InvariantCulture));
        Assert.Equal(Username, idToken.Claims.Single(c => c.Type == IdentityConstants.ClaimName).Value);
        Assert.Equal(
            ((DateTimeOffset)idToken.IssuedAt).ToUnixTimeSeconds() + IdentityConstants.InteractiveIdTokenLifetimeSeconds,
            ((DateTimeOffset)idToken.ValidTo).ToUnixTimeSeconds());
        Assert.DoesNotContain(idToken.Claims, claim => claim.Type is "scope" or IdentityConstants.ClaimClientId
            or IdentityConstants.ClaimAuthMethod or JwtRegisteredClaimNames.Jti);
    }

    [Fact]
    public async Task RotateAsync_OnReplay_RevokesLiveDescendantsAndCommitsOneIdOnlyAudit()
    {
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context, scope: CanonicalScope);
        var now = DateTimeOffset.UtcNow;

        // root (consumed) -> child (consumed) -> grandchild (live): presenting the root must
        // revoke every live descendant — the grandchild — while the consumed ancestors keep
        // their facts and the session is not revoked (EV-31).
        var root = await InsertInteractiveMemberAsync(harness, seed, now.AddMinutes(-3), consumedAt: now.AddMinutes(-2));
        var child = await InsertInteractiveMemberAsync(harness, seed, now.AddMinutes(-2),
            parentId: root.Id, familyId: root.Id, consumedAt: now.AddMinutes(-1));
        var grandchild = await InsertInteractiveMemberAsync(harness, seed, now.AddMinutes(-1),
            parentId: child.Id, familyId: root.Id);

        var dispatch = await harness.Service.RotateAsync(
            seed.Application,
            CreateForm(root.Plaintext),
            clientCredentialMixPresent: false,
            clientIp: null,
            CorrelationId,
            TestContext.Current.CancellationToken);

        var outcome = dispatch.Outcome!;
        Assert.False(outcome.IsSuccess);
        Assert.Equal(400, outcome.Status);
        Assert.Equal("invalid_grant", outcome.ErrorCode);
        Assert.Equal("The refresh token is invalid.", outcome.ErrorDescription);
        Assert.Equal("replay", outcome.FailureReason);

        var cancellationToken = TestContext.Current.CancellationToken;
        var rows = (await harness.Context.RefreshTokens.AsNoTracking().ToListAsync(cancellationToken))
            .ToDictionary(row => row.Id);
        Assert.False(rows[root.Id].IsRevoked);
        Assert.False(rows[child.Id].IsRevoked);
        Assert.True(rows[grandchild.Id].IsRevoked);
        Assert.Null((await harness.Context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seed.SessionId, cancellationToken)).RevokedAt);

        var audit = Assert.Single(await harness.Context.AuditLogs.AsNoTracking().ToListAsync(cancellationToken));
        Assert.Equal("oidc.refresh.replayed", audit.Action);
        Assert.Equal("RefreshTokenFamily", audit.TargetType);
        Assert.Equal(root.Id.ToString("D"), audit.TargetId);
        Assert.Equal(seed.AccountId, audit.ActorId);
        Assert.Equal($"family:{root.Id:D};member:{root.Id:D};revoked:1;app:{ClientId}", audit.Description);
        Assert.Equal(CorrelationId, audit.CorrelationId);
        Assert.DoesNotContain(root.Plaintext, audit.Description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RotateAsync_WhenSessionRevoked_RevokesTheFamilyAndRejectsWithoutAReuseAudit()
    {
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context, scope: CanonicalScope);
        var root = await InsertInteractiveMemberAsync(harness, seed, consumedAt: null);
        await ExecuteAsync(harness.Context, context => context.IdentitySessions
            .Where(row => row.Id == seed.SessionId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.RevokedAt, DateTimeOffset.UtcNow)
                .SetProperty(row => row.RevocationReason, "administrative")));

        var dispatch = await harness.Service.RotateAsync(
            seed.Application,
            CreateForm(root.Plaintext),
            clientCredentialMixPresent: false, clientIp: null, null, TestContext.Current.CancellationToken);

        AssertInvalidGrantWithoutReuse(dispatch);
        var rows = await harness.Context.RefreshTokens.AsNoTracking()
            .Where(row => row.FamilyId == root.Id).ToListAsync(TestContext.Current.CancellationToken);
        Assert.All(rows, row => Assert.True(row.IsRevoked));
    }

    [Fact]
    public async Task RotateAsync_WhenSessionIdleExpired_RevokesTheFamilyAndRejects()
    {
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context, scope: CanonicalScope);
        var root = await InsertInteractiveMemberAsync(harness, seed, consumedAt: null);
        await ExecuteAsync(harness.Context, context => context.IdentitySessions
            .Where(row => row.Id == seed.SessionId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.IdleExpiresAt, DateTimeOffset.UtcNow.AddMinutes(-1))));

        var dispatch = await harness.Service.RotateAsync(
            seed.Application,
            CreateForm(root.Plaintext),
            clientCredentialMixPresent: false, clientIp: null, null, TestContext.Current.CancellationToken);

        AssertInvalidGrantWithoutReuse(dispatch);
        Assert.True(await AllFamilyRevokedAsync(harness, root.Id));
    }

    [Fact]
    public async Task RotateAsync_WhenApplicationMaxAgeIsExceeded_RevokesTheFamilyAndRejects()
    {
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context, scope: CanonicalScope, maxAgeSeconds: 5);
        await ExecuteAsync(harness.Context, context => context.IdentitySessions
            .Where(row => row.Id == seed.SessionId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.AuthTime, DateTimeOffset.UtcNow.AddSeconds(-30))));
        var root = await InsertInteractiveMemberAsync(harness, seed, consumedAt: null);

        var dispatch = await harness.Service.RotateAsync(
            seed.Application,
            CreateForm(root.Plaintext),
            clientCredentialMixPresent: false, clientIp: null, null, TestContext.Current.CancellationToken);

        AssertInvalidGrantWithoutReuse(dispatch);
        Assert.True(await AllFamilyRevokedAsync(harness, root.Id));
    }

    [Fact]
    public async Task RotateAsync_WhenScopeWasRemoved_RevokesTheFamilyAndRejects()
    {
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context, scope: CanonicalScope, allowedScopes: "openid profile");

        var root = await InsertInteractiveMemberAsync(harness, seed, consumedAt: null);
        var dispatch = await harness.Service.RotateAsync(
            seed.Application,
            CreateForm(root.Plaintext),
            clientCredentialMixPresent: false, clientIp: null, null, TestContext.Current.CancellationToken);

        AssertInvalidGrantWithoutReuse(dispatch);
        Assert.True(await AllFamilyRevokedAsync(harness, root.Id));
    }

    [Theory]
    [InlineData(false, true)]   // application deactivated: EV-09's own transaction owns the revocation
    [InlineData(true, false)]   // refresh capability off: EV-11's own transaction owns the revocation
    public async Task RotateAsync_WhenPolicyFailsClosed_RejectsWithoutAFamilyWrite(
        bool allowRefreshToken, bool applicationActive)
    {
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context, scope: CanonicalScope, allowRefreshToken: true);
        if (!allowRefreshToken)
        {
            await ExecuteAsync(harness.Context, context => context.AppRegistrations
                .Where(row => row.Id == seed.Application.Id)
                .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.AllowRefreshToken, false)));
        }

        if (!applicationActive)
        {
            await ExecuteAsync(harness.Context, context => context.AppRegistrations
                .Where(row => row.Id == seed.Application.Id)
                .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsActive, false)));
        }

        var root = await InsertInteractiveMemberAsync(harness, seed, consumedAt: null);
        var dispatch = await harness.Service.RotateAsync(
            seed.Application,
            CreateForm(root.Plaintext),
            clientCredentialMixPresent: false, clientIp: null, null, TestContext.Current.CancellationToken);

        AssertInvalidGrantWithoutReuse(dispatch);
        Assert.False(await AllFamilyRevokedAsync(harness, root.Id));
    }

    [Fact]
    public async Task RotateAsync_WhenAccountDisabled_RejectsWithoutWrites()
    {
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context, scope: CanonicalScope);
        var root = await InsertInteractiveMemberAsync(harness, seed, consumedAt: null);
        await ExecuteAsync(harness.Context, context => context.Accounts
            .Where(row => row.Id == seed.AccountId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsActive, false)));

        var dispatch = await harness.Service.RotateAsync(
            seed.Application,
            CreateForm(root.Plaintext),
            clientCredentialMixPresent: false, clientIp: null, null, TestContext.Current.CancellationToken);

        AssertInvalidGrantWithoutReuse(dispatch);
        Assert.False(await AllFamilyRevokedAsync(harness, root.Id));
    }

    [Fact]
    public async Task RotateAsync_WhenMemberExpiredOrRevoked_RejectsWithoutReuseOrWrites()
    {
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context, scope: CanonicalScope);

        // Expired: the family deadline has passed; expiry never manufactures reuse (EV-32).
        var expired = await InsertInteractiveMemberAsync(
            harness, seed, DateTimeOffset.UtcNow.AddHours(-8), expiresAt: DateTimeOffset.UtcNow.AddHours(-1));
        var expiredDispatch = await harness.Service.RotateAsync(
            seed.Application,
            CreateForm(expired.Plaintext),
            clientCredentialMixPresent: false, clientIp: null, null, TestContext.Current.CancellationToken);
        AssertInvalidGrantWithoutReuse(expiredDispatch);
        Assert.Null((await GetMemberAsync(harness, expired.Id)).ConsumedAt);

        // Explicitly revoked: the first fact stays authoritative and nothing new is written.
        var revoked = await InsertInteractiveMemberAsync(harness, seed, consumedAt: null, isRevoked: true);
        var revokedDispatch = await harness.Service.RotateAsync(
            seed.Application,
            CreateForm(revoked.Plaintext),
            clientCredentialMixPresent: false, clientIp: null, null, TestContext.Current.CancellationToken);
        AssertInvalidGrantWithoutReuse(revokedDispatch);
        Assert.Null((await GetMemberAsync(harness, revoked.Id)).ConsumedAt);
    }

    [Fact]
    public async Task RotateAsync_ForAnotherClient_RejectsWithoutSideEffects()
    {
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context, scope: CanonicalScope);
        var root = await InsertInteractiveMemberAsync(harness, seed, consumedAt: null);
        var other = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "rotation-other-app",
            AppSecretHash = "hash",
            AppName = "Other",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = AudienceMode.PerApplication,
            ClientType = OidcClientType.Confidential,
            AllowAuthorizationCode = true,
            AllowedScopes = CanonicalScope,
            AllowRefreshToken = true
        };
        harness.Context.AppRegistrations.Add(other);
        await harness.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        harness.Context.ChangeTracker.Clear();

        var dispatch = await harness.Service.RotateAsync(
            other,
            CreateForm(root.Plaintext),
            clientCredentialMixPresent: false, clientIp: null, null, TestContext.Current.CancellationToken);

        // A wrong-client presentation never reaches the reuse side effect — not even for a
        // consumed member.
        AssertInvalidGrantWithoutReuse(dispatch);
        Assert.False(await AllFamilyRevokedAsync(harness, root.Id));
    }

    [Fact]
    public async Task RotateAsync_ForALegacyOrMissingRow_DoesNotHandleTheRequest()
    {
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context);
        var legacyId = Guid.NewGuid();
        harness.Context.RefreshTokens.Add(new RefreshTokenEntity
        {
            Id = legacyId,
            FamilyId = legacyId,
            AccountId = seed.AccountId,
            TokenValue = RefreshTokenDigest.Compute("rotation-legacy-token"),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            AppId = ClientId
        });
        await harness.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        harness.Context.ChangeTracker.Clear();

        var legacy = await harness.Service.RotateAsync(
            seed.Application,
            CreateForm("rotation-legacy-token"),
            clientCredentialMixPresent: false, clientIp: null, null, TestContext.Current.CancellationToken);
        Assert.False(legacy.Handled);

        var missing = await harness.Service.RotateAsync(
            seed.Application,
            CreateForm("rotation-no-such-token"),
            clientCredentialMixPresent: false, clientIp: null, null, TestContext.Current.CancellationToken);
        Assert.False(missing.Handled);
        Assert.Empty(await harness.Context.AuditLogs.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RotateAsync_ForAPartialMarker_FailsClosedWithoutSideEffects()
    {
        // CK_refresh_tokens_family_marker keeps a partial marker out of the database; this is
        // the defense-in-depth branch, driven through a corrupt row shape from a fake lookup.
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context, scope: CanonicalScope);
        var corrupt = new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            FamilyId = Guid.NewGuid(),
            AccountId = seed.AccountId,
            TokenValue = RefreshTokenDigest.Compute("rotation-partial-token"),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            AppId = ClientId,
            IdentitySessionId = seed.SessionId,
            Scope = null,
            AuthTime = DateTimeOffset.UtcNow
        };
        var repository = new Mock<IRefreshTokenRepository>(MockBehavior.Strict);
        repository.Setup(repo => repo.GetByTokenValueAsync("rotation-partial-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(corrupt);
        var service = harness.BuildService(repository.Object);

        var dispatch = await service.RotateAsync(
            seed.Application,
            CreateForm("rotation-partial-token"),
            clientCredentialMixPresent: false, clientIp: null, null, TestContext.Current.CancellationToken);

        Assert.True(dispatch.Handled);
        Assert.False(dispatch.Outcome!.IsSuccess);
        Assert.Equal("invalid_grant", dispatch.Outcome.ErrorCode);
        repository.Verify(
            repo => repo.GetByTokenValueAsync("rotation-partial-token", It.IsAny<CancellationToken>()),
            Times.Once);
        repository.VerifyNoOtherCalls();
        Assert.Empty(await harness.Context.RefreshTokens.AsNoTracking()
            .Where(row => row.IdentitySessionId != null).ToListAsync(TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("scope")]
    [InlineData("scope-empty")]
    public async Task RotateAsync_WithAScopeField_RejectsWithInvalidRequest(string scopeField)
    {
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context, scope: CanonicalScope);
        var root = await InsertInteractiveMemberAsync(harness, seed, consumedAt: null);
        var fields = new Dictionary<string, StringValues>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = root.Plaintext
        };
        fields["scope"] = scopeField == "scope" ? "openid" : string.Empty;

        var dispatch = await harness.Service.RotateAsync(
            seed.Application,
            new FormCollection(fields),
            clientCredentialMixPresent: false, clientIp: null, null, TestContext.Current.CancellationToken);

        Assert.True(dispatch.Handled);
        Assert.Equal(400, dispatch.Outcome!.Status);
        Assert.Equal("invalid_request", dispatch.Outcome.ErrorCode);
        Assert.Null((await GetMemberAsync(harness, root.Id)).ConsumedAt);
    }

    [Fact]
    public async Task RotateAsync_WithMixedClientCredentials_AnswersInvalidClient()
    {
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context, scope: CanonicalScope);
        var root = await InsertInteractiveMemberAsync(harness, seed, consumedAt: null);

        var dispatch = await harness.Service.RotateAsync(
            seed.Application,
            CreateForm(root.Plaintext, clientId: ClientId),
            clientCredentialMixPresent: true,
            clientIp: null,
            null,
            TestContext.Current.CancellationToken);

        Assert.True(dispatch.Handled);
        Assert.Equal(401, dispatch.Outcome!.Status);
        Assert.Equal("invalid_client", dispatch.Outcome.ErrorCode);
        Assert.Null((await GetMemberAsync(harness, root.Id)).ConsumedAt);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("unicode-☃-token")]
    [InlineData("tab\ttoken")]
    public async Task RotateAsync_WithAMalformedRefreshTokenField_RejectsWithInvalidRequest(string? token)
    {
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context);

        var fields = new Dictionary<string, StringValues>
        {
            ["grant_type"] = "refresh_token"
        };
        if (token is not null)
        {
            fields["refresh_token"] = token;
        }

        var dispatch = await harness.Service.RotateAsync(
            seed.Application,
            new FormCollection(fields),
            clientCredentialMixPresent: false, clientIp: null, null, TestContext.Current.CancellationToken);

        Assert.True(dispatch.Handled);
        Assert.Equal(400, dispatch.Outcome!.Status);
        Assert.Equal("invalid_request", dispatch.Outcome.ErrorCode);
        Assert.Equal("A token request parameter is missing or malformed.", dispatch.Outcome.ErrorDescription);
    }

    [Fact]
    public async Task RotateAsync_WithAnOverlongToken_RejectsWithInvalidRequest()
    {
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context);
        var overlong = new string('a', 257);

        var dispatch = await harness.Service.RotateAsync(
            seed.Application,
            CreateForm(overlong),
            clientCredentialMixPresent: false, clientIp: null, null, TestContext.Current.CancellationToken);

        Assert.True(dispatch.Handled);
        Assert.Equal("invalid_request", dispatch.Outcome!.ErrorCode);
    }

    [Fact]
    public async Task RotateAsync_WithDuplicateRefreshTokenValues_RejectsWithInvalidRequest()
    {
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context);

        var dispatch = await harness.Service.RotateAsync(
            seed.Application,
            new FormCollection(new Dictionary<string, StringValues>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = new StringValues(["first-token", "second-token"])
            }),
            clientCredentialMixPresent: false, clientIp: null, null, TestContext.Current.CancellationToken);

        Assert.True(dispatch.Handled);
        Assert.Equal("invalid_request", dispatch.Outcome!.ErrorCode);
    }

    /// <summary>
    /// A 256-character legacy shape stays inside IN-26 and keeps the digest lookup — the dispatch
    /// answers not-handled so the legacy grant owns it.
    /// </summary>
    [Fact]
    public async Task RotateAsync_WithAMaximumLengthLegacyShape_StaysOnTheLegacyPath()
    {
        await using var harness = await CreateHarnessAsync();
        var seed = await SeedAsync(harness.Context);
        var legacyToken = new string('L', 256);
        var legacyId = Guid.NewGuid();
        harness.Context.RefreshTokens.Add(new RefreshTokenEntity
        {
            Id = legacyId,
            FamilyId = legacyId,
            AccountId = seed.AccountId,
            TokenValue = RefreshTokenDigest.Compute(legacyToken),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            AppId = ClientId
        });
        await harness.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        harness.Context.ChangeTracker.Clear();

        var dispatch = await harness.Service.RotateAsync(
            seed.Application,
            CreateForm(legacyToken),
            clientCredentialMixPresent: false, clientIp: null, null, TestContext.Current.CancellationToken);

        Assert.False(dispatch.Handled);
    }

    private static void AssertInvalidGrantWithoutReuse(InteractiveRefreshDispatch dispatch)
    {
        Assert.True(dispatch.Handled);
        var outcome = dispatch.Outcome!;
        Assert.False(outcome.IsSuccess);
        Assert.Equal(400, outcome.Status);
        Assert.Equal("invalid_grant", outcome.ErrorCode);
        Assert.Equal("The refresh token is invalid.", outcome.ErrorDescription);
        Assert.Equal("invalid_grant", outcome.FailureReason);
    }

    // ---- Harness ----

    private sealed record Seed(
        AppRegistrationEntity Application,
        Guid AccountId,
        Guid CredentialId,
        Guid SessionId,
        DateTimeOffset AuthTime);

    private static IFormCollection CreateForm(string refreshToken, string? clientId = null)
    {
        var fields = new Dictionary<string, StringValues>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken
        };
        if (clientId is not null)
        {
            fields["client_id"] = clientId;
        }

        return new FormCollection(fields);
    }

    private sealed class RotationHarness(
        SqliteConnection connection,
        IdentityDbContext context,
        InteractiveRefreshRotationService service) : IAsyncDisposable
    {
        public SqliteConnection Connection { get; } = connection;

        public IdentityDbContext Context { get; } = context;

        public InteractiveRefreshRotationService Service { get; } = service;

        public InteractiveRefreshRotationService BuildService(IRefreshTokenRepository? repositoryOverride = null)
        {
            var unitOfWork = new EfCoreUnitOfWork(Context);
            var refreshTokens = repositoryOverride ?? new RefreshTokenRepository(Context);
            return new InteractiveRefreshRotationService(
                refreshTokens,
                new RefreshTokenFamilyStore(refreshTokens, unitOfWork, NullLogger<RefreshTokenFamilyStore>.Instance),
                new IdentitySessionStore(new IdentitySessionRepository(Context), unitOfWork),
                new AccountRepository(Context),
                new PasswordCredentialRepository(Context),
                new InteractiveAccessTokenFactory(
                    new JwtOptions { Issuer = "https://rotation-unit.test" },
                    NullLogger<InteractiveAccessTokenFactory>.Instance),
                new InteractiveIdTokenFactory(new JwtOptions { Issuer = "https://rotation-unit.test" }),
                new StaticKeyManager(),
                new AuditService(new LoginHistoryRepository(Context), new AuditLogRepository(Context)),
                CreateMetrics(),
                unitOfWork,
                Context,
                NullLogger<InteractiveRefreshRotationService>.Instance);
        }

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await Connection.DisposeAsync();
        }
    }

    private static async Task<RotationHarness> CreateHarnessAsync()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        var context = new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlite(connection).Options);
        await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
        var harness = new RotationHarness(connection, context, service: null!);
        return new RotationHarness(connection, context, harness.BuildService());
    }

    private static AuthMetrics CreateMetrics()
    {
        var meterFactory = new Mock<System.Diagnostics.Metrics.IMeterFactory>();
        meterFactory
            .Setup(factory => factory.Create(It.IsAny<System.Diagnostics.Metrics.MeterOptions>()))
            .Returns(new System.Diagnostics.Metrics.Meter("SignaCore"));
        return new AuthMetrics(meterFactory.Object);
    }

    private static async Task<Seed> SeedAsync(
        IdentityDbContext context,
        string scope = "openid profile",
        string allowedScopes = "openid profile offline_access",
        bool allowRefreshToken = true,
        int? maxAgeSeconds = null)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var application = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = ClientId,
            AppSecretHash = "hash",
            AppName = "Rotation Unit Client",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = AudienceMode.PerApplication,
            ClientType = OidcClientType.Confidential,
            AllowAuthorizationCode = true,
            AllowedScopes = allowedScopes,
            AllowRefreshToken = allowRefreshToken,
            IdentitySessionMaxAgeSeconds = maxAgeSeconds
        };
        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        context.AppRegistrations.Add(application);
        context.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });
        context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = credentialId,
            AccountId = accountId,
            Username = Username,
            PasswordHash = "hash",
            CreatedAt = DateTimeOffset.UtcNow
        });
        await context.SaveChangesAsync(cancellationToken);
        context.ChangeTracker.Clear();

        var sessions = new IdentitySessionStore(
            new IdentitySessionRepository(context), new EfCoreUnitOfWork(context));
        var session = await sessions.CreateAsync(accountId, credentialId, DateTimeOffset.UtcNow, cancellationToken);
        return new Seed(application, accountId, credentialId, session.Id, session.AuthTime);
    }

    /// <summary>The seeded member id together with the plaintext that digest-matches its row.</summary>
    private sealed record SeededMember(Guid Id, string Plaintext);

    /// <summary>
    /// Seeds one interactive family member with the canonical marker through the EF model — the
    /// shape only the family write API produces — so the unit suite can exercise every member
    /// state without raw SQL.
    /// </summary>
    private static async Task<SeededMember> InsertInteractiveMemberAsync(
        RotationHarness harness,
        Seed seed,
        DateTimeOffset? createdAt = null,
        Guid? parentId = null,
        Guid? familyId = null,
        DateTimeOffset? consumedAt = null,
        bool isRevoked = false,
        DateTimeOffset? expiresAt = null)
    {
        var created = createdAt ?? DateTimeOffset.UtcNow;
        var id = Guid.NewGuid();
        var plaintext = "rotation-member-" + id.ToString("N");
        harness.Context.RefreshTokens.Add(new RefreshTokenEntity
        {
            Id = id,
            FamilyId = familyId ?? id,
            ParentId = parentId,
            AccountId = seed.AccountId,
            TokenValue = RefreshTokenDigest.Compute(plaintext),
            CreatedAt = created,
            ExpiresAt = expiresAt ?? created.AddDays(IdentityConstants.InteractiveRefreshFamilyLifetimeDays),
            IsRevoked = isRevoked,
            AppId = ClientId,
            IdentitySessionId = seed.SessionId,
            Scope = CanonicalScope,
            AuthTime = seed.AuthTime,
            ConsumedAt = consumedAt
        });
        await harness.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        harness.Context.ChangeTracker.Clear();
        return new SeededMember(id, plaintext);
    }

    private static Task<RefreshTokenEntity> GetMemberAsync(RotationHarness harness, Guid id) =>
        harness.Context.RefreshTokens.AsNoTracking()
            .SingleAsync(row => row.Id == id, TestContext.Current.CancellationToken);

    private static async Task<bool> AllFamilyRevokedAsync(RotationHarness harness, Guid rootId) =>
        await harness.Context.RefreshTokens.AsNoTracking()
            .Where(row => row.FamilyId == rootId)
            .AllAsync(row => row.IsRevoked, TestContext.Current.CancellationToken);

    private static async Task ExecuteAsync(
        IdentityDbContext context,
        Func<IdentityDbContext, Task> action)
    {
        await action(context);
        context.ChangeTracker.Clear();
    }

    /// <summary>A synchronous, in-memory key manager: one fixed RSA key, no refresh effect.</summary>
    private sealed class StaticKeyManager : IKeyManager
    {
        private readonly RsaSecurityKey _key;

        public StaticKeyManager()
        {
            var rsa = RSA.Create(2048);
            _key = new RsaSecurityKey(rsa) { KeyId = Guid.NewGuid().ToString() };
        }

        public RsaSecurityKey GetCurrentKey() => _key;

        public IReadOnlyList<SecurityKey> GetValidationKeys() => [_key];

        public Task RefreshKeysAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<IReadOnlyList<RsaSecurityKey>> GetValidKeysAsync(
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<RsaSecurityKey>>([_key]);

        public Task<bool> NeedsKeyRotationAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(false);

        public Task RotateKeyAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task InitializationCompleted => Task.CompletedTask;
    }
}
