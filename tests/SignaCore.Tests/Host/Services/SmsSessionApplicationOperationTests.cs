using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Moq;
using ServiceMantle.Persistence.Relational.Stores;
using ServiceMantle.Persistence.Relational;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services.Sms;
using SignaCore.Domain.Services;
using SignaCore.Domain;
using SignaCore.Host.Services;
using SignaCore.Host;
using SignaCore.Tests.TestSupport;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Xunit;

namespace SignaCore.Tests.Host.Services;

/// <summary>
/// The application operations on an <c>Sms</c> identity session (#453): the <c>EV-38</c> recheck
/// of the <c>PS-04</c> SMS admission predicate at authorize reuse, code redemption (precheck and
/// in-lock recheck), interactive refresh (with the fixed <c>EV-32</c> reason order and the
/// <c>sms_admission</c> family revocation), and UserInfo; and the <c>PS-12</c>/<c>PS-13</c>/
/// <c>PS-16</c> claim mapping — <c>amr: ["sms"]</c>, <c>auth_method: Sms</c>, <c>name</c> only
/// from exactly one Password credential, and no phone number anywhere. Every service runs over a
/// real SQLite store with a real <c>Sms</c> session created by <c>CreateSmsAsync</c>.
/// </summary>
public sealed class SmsSessionApplicationOperationTests
{
    private const string AppA = "sms-operation-app-a";
    private const string AppB = "sms-operation-app-b";
    private const string RedirectUri = "https://bff.sms-operation.unit.test/callback";
    private const string Issuer = "https://sms-operation.unit.test";
    private const string Nonce = "sms-operation-nonce";
    private const string OfflineScope = "openid profile offline_access";
    private const string BarePhone = "13912345678";
    private const string Phone = "+86" + BarePhone;
    private const string UsernamePrefix = "sms_operation_user_";

    // RFC 7636 appendix B.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    /// <summary>The four ways the <c>PS-04</c> predicate of application A becomes false.</summary>
    public enum AdmissionBreak
    {
        ModeDisabled,
        AdmissionMissing,
        AdmissionInactive,
        NotAdminApprovedUnderManualApproval
    }

    // ---- Authorize reuse (EV-38 / SC-24) ----

    [Theory]
    [InlineData(AdmissionBreak.ModeDisabled)]
    [InlineData(AdmissionBreak.AdmissionMissing)]
    [InlineData(AdmissionBreak.AdmissionInactive)]
    [InlineData(AdmissionBreak.NotAdminApprovedUnderManualApproval)]
    public async Task Reuse_WhenThePredicateIsFalse_ReturnsNotReusableWithoutAnyWrite(AdmissionBreak change)
    {
        await using var harness = await Harness.CreateAsync();
        var stale = await harness.MakeSessionStaleAsync();
        await harness.BreakAsync(change);
        var admissions = await harness.AdmissionSnapshotAsync();

        var code = await harness.Reuse().TryIssueAsync(
            harness.Accepted(harness.AppARowId, AppA), harness.SessionId, DateTimeOffset.UtcNow,
            null, null, TestContext.Current.CancellationToken);

        Assert.Null(code);
        Assert.Empty(await harness.Context.AuthorizationCodes.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Empty(await SharedAuditTable.ReadAsync(harness.Context, TestContext.Current.CancellationToken));
        var session = await harness.SessionAsync();
        Assert.Null(session.RevokedAt);
        Assert.Equal(stale.UtcTicks / 10, session.LastSeenAt.UtcTicks / 10);
        // No provisioning and no admission write on reuse, even under AutoProvision.
        Assert.Equal(admissions, await harness.AdmissionSnapshotAsync());
    }

    [Fact]
    public async Task Reuse_WhenThePredicateHolds_BindsTheCodeToTheSameSessionAndSlidesActivity()
    {
        await using var harness = await Harness.CreateAsync();
        var stale = await harness.MakeSessionStaleAsync();
        var now = DateTimeOffset.UtcNow;

        var code = await harness.Reuse().TryIssueAsync(
            harness.Accepted(harness.AppARowId, AppA), harness.SessionId, now,
            null, null, TestContext.Current.CancellationToken);

        Assert.NotNull(code);
        var lookup = await harness.Codes().FindAsync(code!, now, TestContext.Current.CancellationToken);
        Assert.Equal(harness.SessionId, lookup.Entity!.IdentitySessionId);
        Assert.Equal(harness.AppARowId, lookup.Entity.AppRegistrationId);
        var session = await harness.SessionAsync();
        Assert.True(session.LastSeenAt > stale);
    }

    [Fact]
    public async Task Reuse_ForAnotherApplicationWhosePredicateHolds_IsUnaffectedByApplicationA()
    {
        await using var harness = await Harness.CreateAsync();
        await harness.BreakAsync(AdmissionBreak.AdmissionInactive);

        Assert.Null(await harness.Reuse().TryIssueAsync(
            harness.Accepted(harness.AppARowId, AppA), harness.SessionId, DateTimeOffset.UtcNow,
            null, null, TestContext.Current.CancellationToken));
        var codeForB = await harness.Reuse().TryIssueAsync(
            harness.Accepted(harness.AppBRowId, AppB), harness.SessionId, DateTimeOffset.UtcNow,
            null, null, TestContext.Current.CancellationToken);

        Assert.NotNull(codeForB);
        Assert.Null((await harness.SessionAsync()).RevokedAt);
    }

    [Fact]
    public async Task Reuse_WithACancelledToken_WritesNoCodeActivityOrAudit()
    {
        await using var harness = await Harness.CreateAsync();
        var stale = await harness.MakeSessionStaleAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => harness.Reuse().TryIssueAsync(
            harness.Accepted(harness.AppARowId, AppA), harness.SessionId, DateTimeOffset.UtcNow,
            null, null, new CancellationToken(canceled: true)));

        Assert.Empty(await harness.Context.AuthorizationCodes.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Empty(await SharedAuditTable.ReadAsync(harness.Context, TestContext.Current.CancellationToken));
        Assert.Equal(stale.UtcTicks / 10, (await harness.SessionAsync()).LastSeenAt.UtcTicks / 10);
    }

    // ---- Code redemption ----

    [Theory]
    [InlineData(AdmissionBreak.ModeDisabled)]
    [InlineData(AdmissionBreak.AdmissionMissing)]
    [InlineData(AdmissionBreak.AdmissionInactive)]
    [InlineData(AdmissionBreak.NotAdminApprovedUnderManualApproval)]
    public async Task Redeem_WhenThePredicateIsFalse_ReturnsTheGenericInvalidGrantAndConsumesNothing(AdmissionBreak change)
    {
        await using var harness = await Harness.CreateAsync();
        var code = await harness.CreateCodeAsync(harness.AppARowId, OfflineScope);
        await harness.BreakAsync(change);

        var outcome = await harness.Redemption().RedeemAsync(
            await harness.ApplicationAsync(AppA), RedemptionForm(code.Code), null, null,
            TestContext.Current.CancellationToken);

        AssertGenericInvalidGrant(outcome);
        await harness.AssertCodeUntouchedAsync(code.Id);
    }

    [Theory]
    [InlineData(AdmissionBreak.ModeDisabled)]
    [InlineData(AdmissionBreak.AdmissionMissing)]
    [InlineData(AdmissionBreak.AdmissionInactive)]
    [InlineData(AdmissionBreak.NotAdminApprovedUnderManualApproval)]
    public async Task Redeem_WhenTheAdmissionBreaksAfterThePrecheck_TheLockedRecheckRejects(AdmissionBreak change)
    {
        await using var harness = await Harness.CreateAsync();
        var code = await harness.CreateCodeAsync(harness.AppARowId, OfflineScope);
        // The precheck resolved the authenticated client with the admitting mode; the key refresh
        // runs after every precheck and before the issuance transaction opens.
        var application = await harness.ApplicationAsync(AppA);
        var hookRan = false;
        harness.Keys.BeforeRefresh = async () =>
        {
            hookRan = true;
            await harness.BreakAsync(change);
        };

        var outcome = await harness.Redemption().RedeemAsync(
            application, RedemptionForm(code.Code), null, null, TestContext.Current.CancellationToken);

        Assert.True(hookRan);
        AssertGenericInvalidGrant(outcome);
        await harness.AssertCodeUntouchedAsync(code.Id);
    }

    [Theory]
    [InlineData(0, null)]
    [InlineData(1, null)]
    [InlineData(2, null)]
    [InlineData(0, "sms-nickname")]
    [InlineData(1, "sms-nickname")]
    public async Task RedeemRefreshAndUserInfo_MapAmrNameAndAuthMethodWithoutAnyPhone(
        int passwordCredentials,
        string? nickname)
    {
        await using var harness = await Harness.CreateAsync(passwordCredentials, nickname);
        var expectedName = passwordCredentials == 1 ? UsernamePrefix + "0" : null;
        var code = await harness.CreateCodeAsync(harness.AppARowId, OfflineScope);

        var redeemed = await harness.Redemption().RedeemAsync(
            await harness.ApplicationAsync(AppA), RedemptionForm(code.Code), null, null,
            TestContext.Current.CancellationToken);
        Assert.True(redeemed.IsSuccess);
        AssertIdToken(redeemed.IdToken, expectedName, nickname, expectNonce: true);
        AssertAccessToken(redeemed.AccessToken, nickname ?? expectedName);

        var refreshed = await harness.Refresh().RotateAsync(
            await harness.ApplicationAsync(AppA), RefreshForm(redeemed.RefreshToken!), false, null, null,
            TestContext.Current.CancellationToken);
        var rotation = refreshed.Outcome!;
        Assert.True(rotation.IsSuccess);
        AssertIdToken(rotation.IdToken, expectedName, nickname, expectNonce: false);
        AssertAccessToken(rotation.AccessToken, nickname ?? expectedName);

        var userInfo = await harness.UserInfo().ReadAsync(
            new StringValues("Bearer " + rotation.AccessToken), false, TestContext.Current.CancellationToken);
        Assert.True(userInfo.IsSuccess);
        Assert.Equal(harness.AccountId.ToString("D"), userInfo.Subject);
        Assert.Equal(expectedName, userInfo.Name);
        Assert.Equal(nickname, userInfo.Nickname);

        // No phone number, raw or E.164, in any token segment or UserInfo value.
        var visible = string.Join('\n',
            DecodeJwt(redeemed.AccessToken), DecodeJwt(redeemed.IdToken),
            DecodeJwt(rotation.AccessToken), DecodeJwt(rotation.IdToken),
            userInfo.Subject, userInfo.Name, userInfo.Nickname, userInfo.AppId);
        Assert.DoesNotContain(BarePhone, visible, StringComparison.Ordinal);
        Assert.DoesNotContain(Phone, visible, StringComparison.Ordinal);
    }

    // ---- Interactive refresh ----

    [Theory]
    [InlineData(AdmissionBreak.ModeDisabled)]
    [InlineData(AdmissionBreak.AdmissionMissing)]
    [InlineData(AdmissionBreak.AdmissionInactive)]
    [InlineData(AdmissionBreak.NotAdminApprovedUnderManualApproval)]
    public async Task Refresh_WhenThePredicateIsFalse_RevokesOnlyThisApplicationsFamilyWithSmsAdmission(AdmissionBreak change)
    {
        await using var harness = await Harness.CreateAsync();
        var familyA = await harness.RedeemFamilyAsync(AppA, harness.AppARowId);
        var familyB = await harness.RedeemFamilyAsync(AppB, harness.AppBRowId);
        // One rotation first, so the revocation must reach a child as well as the root.
        var rotated = await harness.RotateAsync(AppA, familyA.RefreshToken);
        Assert.True(rotated.IsSuccess);
        await harness.BreakAsync(change);
        var membersBefore = await harness.FamilyMemberCountAsync(familyA.RootId);
        harness.FamilyLog.Clear();

        var rejected = await harness.RotateAsync(AppA, rotated.RefreshToken!);

        AssertGenericRefreshInvalidGrant(rejected);
        Assert.True(await harness.AllFamilyRevokedAsync(familyA.RootId));
        Assert.Equal(membersBefore, await harness.FamilyMemberCountAsync(familyA.RootId));
        Assert.Contains("Reason=SmsAdmission", Assert.Single(harness.FamilyLog), StringComparison.Ordinal);
        Assert.Null((await harness.SessionAsync()).RevokedAt);

        // The same session's family at B keeps refreshing.
        Assert.True((await harness.RotateAsync(AppB, familyB.RefreshToken)).IsSuccess);
        Assert.False(await harness.AllFamilyRevokedAsync(familyB.RootId));
    }

    [Fact]
    public async Task Refresh_AfterTheAdmissionIsRestored_TheRevokedFamilyStaysRevoked()
    {
        await using var harness = await Harness.CreateAsync();
        var family = await harness.RedeemFamilyAsync(AppA, harness.AppARowId);
        await harness.BreakAsync(AdmissionBreak.AdmissionInactive);
        AssertGenericRefreshInvalidGrant(await harness.RotateAsync(AppA, family.RefreshToken));
        await harness.RestoreAsync();

        AssertGenericRefreshInvalidGrant(await harness.RotateAsync(AppA, family.RefreshToken));
        Assert.True(await harness.AllFamilyRevokedAsync(family.RootId));

        // The restored admission makes the session usable again for new operations.
        var code = await harness.CreateCodeAsync(harness.AppARowId, OfflineScope);
        Assert.True((await harness.Redemption().RedeemAsync(
            await harness.ApplicationAsync(AppA), RedemptionForm(code.Code), null, null,
            TestContext.Current.CancellationToken)).IsSuccess);
    }

    public enum CoincidentFailure
    {
        SessionExpired,
        ApplicationMaxAge,
        ScopeRemoved
    }

    [Theory]
    [InlineData(CoincidentFailure.SessionExpired, "SessionExpired")]
    [InlineData(CoincidentFailure.ApplicationMaxAge, "ApplicationMaxAge")]
    [InlineData(CoincidentFailure.ScopeRemoved, "SmsAdmission")]
    public async Task Refresh_WithCoincidentFailures_RecordsExactlyOneReasonInTheFixedOrder(
        CoincidentFailure coincident,
        string expectedReason)
    {
        await using var harness = await Harness.CreateAsync();
        var family = await harness.RedeemFamilyAsync(AppA, harness.AppARowId);
        await harness.BreakAsync(AdmissionBreak.AdmissionInactive);
        await harness.ApplyAsync(coincident);
        harness.FamilyLog.Clear();

        AssertGenericRefreshInvalidGrant(await harness.RotateAsync(AppA, family.RefreshToken));

        Assert.True(await harness.AllFamilyRevokedAsync(family.RootId));
        Assert.Contains($"Reason={expectedReason}", Assert.Single(harness.FamilyLog), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Refresh_CancelledBeforeTheRevocationCommits_LeavesTheFamilyForTheNextCheck()
    {
        await using var harness = await Harness.CreateAsync();
        var family = await harness.RedeemFamilyAsync(AppA, harness.AppARowId);
        await harness.BreakAsync(AdmissionBreak.AdmissionMissing);
        using var cancellation = new CancellationTokenSource();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => harness.Refresh(
                store => new CancelAfterRevokeFamilyStore(store, cancellation))
            .RotateAsync(
                harness.ApplicationEntity(AppA), RefreshForm(family.RefreshToken), false, null, null,
                cancellation.Token));

        Assert.False(await harness.AnyFamilyMemberRevokedAsync(family.RootId));

        harness.FamilyLog.Clear();
        AssertGenericRefreshInvalidGrant(await harness.RotateAsync(AppA, family.RefreshToken));
        Assert.True(await harness.AllFamilyRevokedAsync(family.RootId));
        Assert.Contains("Reason=SmsAdmission", Assert.Single(harness.FamilyLog), StringComparison.Ordinal);
    }

    // ---- UserInfo ----

    [Theory]
    [InlineData(AdmissionBreak.ModeDisabled)]
    [InlineData(AdmissionBreak.AdmissionMissing)]
    [InlineData(AdmissionBreak.AdmissionInactive)]
    [InlineData(AdmissionBreak.NotAdminApprovedUnderManualApproval)]
    public async Task UserInfo_WhenThePredicateIsFalse_AnswersInvalidTokenWithoutAnyWrite(AdmissionBreak change)
    {
        await using var harness = await Harness.CreateAsync(passwordCredentials: 1);
        var family = await harness.RedeemFamilyAsync(AppA, harness.AppARowId);
        await harness.BreakAsync(change);
        var session = await harness.SessionAsync();
        var admissions = await harness.AdmissionSnapshotAsync();

        var outcome = await harness.UserInfo().ReadAsync(
            new StringValues("Bearer " + family.AccessToken), false, TestContext.Current.CancellationToken);

        Assert.False(outcome.IsSuccess);
        Assert.Equal(OidcUserInfoRejection.InvalidToken, outcome.Rejection);
        var after = await harness.SessionAsync();
        Assert.Equal(session.LastSeenAt, after.LastSeenAt);
        Assert.Null(after.RevokedAt);
        Assert.Equal(admissions, await harness.AdmissionSnapshotAsync());
        Assert.False(await harness.AnyFamilyMemberRevokedAsync(family.RootId));
    }

    // ---- Assertions ----

    private static void AssertGenericInvalidGrant(AuthorizationCodeRedemptionOutcome outcome)
    {
        Assert.False(outcome.IsSuccess);
        Assert.Equal(StatusCodes.Status400BadRequest, outcome.Status);
        Assert.Equal("invalid_grant", outcome.ErrorCode);
        Assert.Equal("The authorization code is invalid.", outcome.ErrorDescription);
        Assert.Equal("invalid_grant", outcome.FailureReason);
    }

    private static void AssertGenericRefreshInvalidGrant(InteractiveRefreshRotationOutcome outcome)
    {
        Assert.False(outcome.IsSuccess);
        Assert.Equal(StatusCodes.Status400BadRequest, outcome.Status);
        Assert.Equal("invalid_grant", outcome.ErrorCode);
        Assert.Equal("The refresh token is invalid.", outcome.ErrorDescription);
        Assert.Equal("invalid_grant", outcome.FailureReason);
    }

    private static void AssertIdToken(string idToken, string? expectedName, string? nickname, bool expectNonce)
    {
        var token = new JwtSecurityTokenHandler().ReadJwtToken(idToken);
        Assert.Equal("sms", Assert.Single(token.Claims, claim => claim.Type == JwtRegisteredClaimNames.Amr).Value);
        Assert.Equal(expectedName, token.Claims.SingleOrDefault(claim => claim.Type == IdentityConstants.ClaimName)?.Value);
        Assert.Equal(nickname, token.Claims.SingleOrDefault(claim => claim.Type == IdentityConstants.ClaimNickname)?.Value);
        Assert.Equal(expectNonce, token.Claims.Any(claim => claim.Type == JwtRegisteredClaimNames.Nonce));
        Assert.DoesNotContain(token.Claims, claim => claim.Type == IdentityConstants.ClaimAuthMethod);
    }

    private static void AssertAccessToken(string accessToken, string? expectedDisplayName)
    {
        var token = new JwtSecurityTokenHandler().ReadJwtToken(accessToken);
        Assert.Equal(
            IdentityConstants.AuthMethodSms,
            Assert.Single(token.Claims, claim => claim.Type == IdentityConstants.ClaimAuthMethod).Value);
        Assert.Equal(expectedDisplayName, token.Claims.SingleOrDefault(claim => claim.Type == IdentityConstants.ClaimName)?.Value);
    }

    private static string DecodeJwt(string token)
    {
        var segments = token.Split('.');
        return Base64UrlEncoder.Decode(segments[0]) + Base64UrlEncoder.Decode(segments[1]);
    }

    private static IFormCollection RedemptionForm(string code) =>
        new FormCollection(new Dictionary<string, StringValues>
        {
            ["grant_type"] = AuthorizationCodeRedemptionService.GrantType,
            ["code"] = code,
            ["redirect_uri"] = RedirectUri,
            ["code_verifier"] = Verifier
        });

    private static IFormCollection RefreshForm(string refreshToken) =>
        new FormCollection(new Dictionary<string, StringValues>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken
        });

    // ---- Harness ----

    private sealed record RedeemedFamily(string AccessToken, string RefreshToken, Guid RootId);

    private sealed class Harness : IAsyncDisposable
    {
        private Harness(SqliteConnection connection, IdentityDbContext context)
        {
            Connection = connection;
            Context = context;
        }

        public SqliteConnection Connection { get; }

        public IdentityDbContext Context { get; }

        public HookedKeyManager Keys { get; } = new();

        public List<string> FamilyLog { get; } = [];

        public Guid AppARowId { get; private set; }

        public Guid AppBRowId { get; private set; }

        public Guid AccountId { get; private set; }

        public Guid SmsLoginId { get; private set; }

        public IdentitySessionEntity Session { get; private set; } = null!;

        public Guid SessionId => Session.Id;

        public static async Task<Harness> CreateAsync(int passwordCredentials = 0, string? nickname = null)
        {
            var ct = TestContext.Current.CancellationToken;
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(ct);
            var context = new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>()
                .UseSqlite(connection).Options);
            await context.Database.EnsureCreatedAsync(ct);
            var harness = new Harness(connection, context);

            // A requires Admin approval; B admits every active admission. Both admit the phone.
            var appA = NewApplication(AppA, SmsLoginMode.ManualApproval);
            var appB = NewApplication(AppB, SmsLoginMode.AutoProvision);
            context.AppRegistrations.AddRange(appA, appB);
            harness.AppARowId = appA.Id;
            harness.AppBRowId = appB.Id;

            harness.AccountId = Guid.NewGuid();
            harness.SmsLoginId = Guid.NewGuid();
            context.Accounts.Add(new AccountEntity
            {
                Id = harness.AccountId,
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                Nickname = nickname
            });
            context.UserLogins.Add(new UserLoginEntity
            {
                Id = harness.SmsLoginId,
                AccountId = harness.AccountId,
                ProviderName = IdentityConstants.AuthMethodSms,
                ProviderUserId = Phone
            });
            for (var index = 0; index < passwordCredentials; index++)
            {
                context.PasswordCredentials.Add(new PasswordCredentialEntity
                {
                    Id = Guid.NewGuid(),
                    AccountId = harness.AccountId,
                    Username = UsernamePrefix + index,
                    PasswordHash = "hash",
                    // The creation order makes "the first credential" deterministic for the
                    // Password rule; the Sms rule must not depend on it.
                    CreatedAt = DateTimeOffset.UtcNow.AddMinutes(index)
                });
            }

            context.AppSmsAccesses.AddRange(
                NewAdmission(appA.Id, harness.SmsLoginId, SmsAccessApprovalSource.Admin),
                NewAdmission(appB.Id, harness.SmsLoginId, SmsAccessApprovalSource.AutoProvision));
            await context.SaveChangesAsync(ct);
            context.ChangeTracker.Clear();

            harness.Session = await harness.Sessions().CreateSmsAsync(
                harness.AccountId, harness.SmsLoginId, DateTimeOffset.UtcNow, ct);
            context.ChangeTracker.Clear();
            return harness;
        }

        public IIdentitySessionStore Sessions() =>
            new IdentitySessionStore(new IdentitySessionRepository(Context), new EfCoreUnitOfWork(Context));

        public IAuthorizationCodeStore Codes() =>
            new AuthorizationCodeStore(new AuthorizationCodeRepository(Context), new EfCoreUnitOfWork(Context));

        public OidcAuthorizationSessionReuseService Reuse()
        {
            var unitOfWork = new EfCoreUnitOfWork(Context);
            return new OidcAuthorizationSessionReuseService(
                Sessions(),
                Codes(),
                new AccountRepository(Context),
                new EfCoreManagementAuditWriter<IdentityDbContext>(Context),
                unitOfWork,
                Context,
                new SmsAdmissionService(Context));
        }

        public AuthorizationCodeRedemptionService Redemption()
        {
            var unitOfWork = new EfCoreUnitOfWork(Context);
            return new AuthorizationCodeRedemptionService(
                Codes(),
                Sessions(),
                new AccountRepository(Context),
                new PasswordCredentialRepository(Context),
                AccessTokens(),
                new InteractiveIdTokenFactory(new JwtOptions { Issuer = Issuer }),
                FamilyStore(new RefreshTokenRepository(Context), unitOfWork),
                callbackService: null,
                Keys,
                new EfCoreManagementAuditWriter<IdentityDbContext>(Context),
                Metrics(),
                unitOfWork,
                new AppRegistrationRepository(Context),
                Context,
                new AdminIdentityOptions(),
                new SmsAdmissionService(Context),
                NullLogger<AuthorizationCodeRedemptionService>.Instance);
        }

        public InteractiveRefreshRotationService Refresh(
            Func<IRefreshTokenFamilyStore, IRefreshTokenFamilyStore>? wrapFamilies = null)
        {
            var unitOfWork = new EfCoreUnitOfWork(Context);
            var refreshTokens = new RefreshTokenRepository(Context);
            var families = FamilyStore(refreshTokens, unitOfWork);
            return new InteractiveRefreshRotationService(
                refreshTokens,
                wrapFamilies?.Invoke(families) ?? families,
                Sessions(),
                new AccountRepository(Context),
                new PasswordCredentialRepository(Context),
                AccessTokens(),
                new InteractiveIdTokenFactory(new JwtOptions { Issuer = Issuer }),
                Keys,
                new EfCoreManagementAuditWriter<IdentityDbContext>(Context),
                Metrics(),
                unitOfWork,
                new AppRegistrationRepository(Context),
                Context,
                new SmsAdmissionService(Context),
                NullLogger<InteractiveRefreshRotationService>.Instance);
        }

        public OidcUserInfoService UserInfo() =>
            new(
                Keys,
                new AccountRepository(Context),
                new PasswordCredentialRepository(Context),
                Context,
                new JwtOptions { Issuer = Issuer },
                new SmsAdmissionService(Context),
                NullLogger<OidcUserInfoService>.Instance);

        public OidcAuthorizationValidationResult.Accepted Accepted(Guid applicationRowId, string clientId) =>
            new(clientId, applicationRowId, RedirectUri, "openid profile", "sms-operation-state", Nonce, Challenge);

        public async Task<AppRegistrationEntity> ApplicationAsync(string appId)
        {
            var application = await Context.AppRegistrations.AsNoTracking()
                .SingleAsync(row => row.AppId == appId, TestContext.Current.CancellationToken);
            return application;
        }

        /// <summary>The authenticated-client snapshot as the token endpoint holds it, read synchronously.</summary>
        public AppRegistrationEntity ApplicationEntity(string appId) =>
            Context.AppRegistrations.AsNoTracking().Single(row => row.AppId == appId);

        public async Task<AuthorizationCodeCreation> CreateCodeAsync(Guid applicationRowId, string scope)
        {
            var creation = await Codes().CreateAsync(
                Session,
                new AuthorizationCodeBinding(applicationRowId, RedirectUri, scope, Nonce, Challenge),
                DateTimeOffset.UtcNow,
                TestContext.Current.CancellationToken);
            Context.ChangeTracker.Clear();
            return creation;
        }

        public async Task<RedeemedFamily> RedeemFamilyAsync(string appId, Guid applicationRowId)
        {
            var code = await CreateCodeAsync(applicationRowId, OfflineScope);
            var outcome = await Redemption().RedeemAsync(
                await ApplicationAsync(appId), RedemptionForm(code.Code), null, null,
                TestContext.Current.CancellationToken);
            Assert.True(outcome.IsSuccess);
            var rootId = await Context.AuthorizationCodes.AsNoTracking()
                .Where(row => row.Id == code.Id)
                .Select(row => row.RefreshFamilyId!.Value)
                .SingleAsync(TestContext.Current.CancellationToken);
            return new RedeemedFamily(outcome.AccessToken, outcome.RefreshToken!, rootId);
        }

        public async Task<InteractiveRefreshRotationOutcome> RotateAsync(string appId, string refreshToken)
        {
            var dispatch = await Refresh().RotateAsync(
                await ApplicationAsync(appId), RefreshForm(refreshToken), false, null, null,
                TestContext.Current.CancellationToken);
            Assert.True(dispatch.Handled);
            return dispatch.Outcome!;
        }

        public async Task BreakAsync(AdmissionBreak change)
        {
            var ct = TestContext.Current.CancellationToken;
            var accessesOfA = Context.AppSmsAccesses
                .Where(row => row.AppRegistrationId == AppARowId && row.UserLoginId == SmsLoginId);
            switch (change)
            {
                case AdmissionBreak.ModeDisabled:
                    await Context.AppRegistrations.Where(row => row.Id == AppARowId)
                        .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.SmsLoginMode, SmsLoginMode.Disabled), ct);
                    break;
                case AdmissionBreak.AdmissionMissing:
                    await accessesOfA.ExecuteDeleteAsync(ct);
                    break;
                case AdmissionBreak.AdmissionInactive:
                    await accessesOfA.ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsActive, false), ct);
                    break;
                case AdmissionBreak.NotAdminApprovedUnderManualApproval:
                    await accessesOfA.ExecuteUpdateAsync(setters => setters
                        .SetProperty(row => row.ApprovalSource, SmsAccessApprovalSource.AutoProvision), ct);
                    break;
            }
        }

        public Task RestoreAsync() =>
            Context.AppSmsAccesses
                .Where(row => row.AppRegistrationId == AppARowId && row.UserLoginId == SmsLoginId)
                .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsActive, true),
                    TestContext.Current.CancellationToken);

        public async Task ApplyAsync(CoincidentFailure coincident)
        {
            var ct = TestContext.Current.CancellationToken;
            switch (coincident)
            {
                case CoincidentFailure.SessionExpired:
                    var past = DateTimeOffset.UtcNow.AddMinutes(-1);
                    await Context.IdentitySessions.Where(row => row.Id == SessionId)
                        .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IdleExpiresAt, past), ct);
                    break;
                case CoincidentFailure.ApplicationMaxAge:
                    await Context.AppRegistrations.Where(row => row.Id == AppARowId)
                        .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IdentitySessionMaxAgeSeconds, 5), ct);
                    await Context.IdentitySessions.Where(row => row.Id == SessionId)
                        .ExecuteUpdateAsync(setters => setters
                            .SetProperty(row => row.AuthTime, DateTimeOffset.UtcNow.AddSeconds(-30)), ct);
                    break;
                case CoincidentFailure.ScopeRemoved:
                    await Context.AppRegistrations.Where(row => row.Id == AppARowId)
                        .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.AllowedScopes, "openid profile"), ct);
                    break;
            }
        }

        /// <summary>Moves the session's activity two minutes back so a reuse would have to slide it.</summary>
        public async Task<DateTimeOffset> MakeSessionStaleAsync()
        {
            var stale = DateTimeOffset.UtcNow.AddMinutes(-2);
            await Context.IdentitySessions.Where(row => row.Id == SessionId)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(row => row.LastSeenAt, stale)
                    .SetProperty(row => row.IdleExpiresAt, stale.AddMinutes(30)),
                    TestContext.Current.CancellationToken);
            return stale;
        }

        public Task<IdentitySessionEntity> SessionAsync() =>
            Context.IdentitySessions.AsNoTracking()
                .SingleAsync(row => row.Id == SessionId, TestContext.Current.CancellationToken);

        public async Task<string> AdmissionSnapshotAsync()
        {
            var rows = await Context.AppSmsAccesses.AsNoTracking()
                .OrderBy(row => row.Id)
                .Select(row => $"{row.Id}:{row.AppRegistrationId}:{row.ApprovalSource}:{row.IsActive}")
                .ToListAsync(TestContext.Current.CancellationToken);
            var accounts = await Context.Accounts.AsNoTracking().CountAsync(TestContext.Current.CancellationToken);
            var logins = await Context.UserLogins.AsNoTracking().CountAsync(TestContext.Current.CancellationToken);
            return $"{string.Join('|', rows)}#{accounts}#{logins}";
        }

        public async Task AssertCodeUntouchedAsync(Guid codeId)
        {
            var ct = TestContext.Current.CancellationToken;
            var code = await Context.AuthorizationCodes.AsNoTracking().SingleAsync(row => row.Id == codeId, ct);
            Assert.Null(code.ConsumedAt);
            Assert.Null(code.RefreshFamilyId);
            Assert.Empty(await Context.RefreshTokens.AsNoTracking().ToListAsync(ct));
            // No redeemed and no replay audit.
            Assert.Empty(await SharedAuditTable.ReadAsync(Context, ct));
            Assert.Null((await SessionAsync()).RevokedAt);
        }

        public Task<bool> AllFamilyRevokedAsync(Guid rootId) =>
            Context.RefreshTokens.AsNoTracking()
                .Where(row => row.FamilyId == rootId)
                .AllAsync(row => row.IsRevoked, TestContext.Current.CancellationToken);

        public Task<bool> AnyFamilyMemberRevokedAsync(Guid rootId) =>
            Context.RefreshTokens.AsNoTracking()
                .Where(row => row.FamilyId == rootId)
                .AnyAsync(row => row.IsRevoked, TestContext.Current.CancellationToken);

        public Task<int> FamilyMemberCountAsync(Guid rootId) =>
            Context.RefreshTokens.AsNoTracking()
                .CountAsync(row => row.FamilyId == rootId, TestContext.Current.CancellationToken);

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await Connection.DisposeAsync();
        }

        private RefreshTokenFamilyStore FamilyStore(IRefreshTokenRepository refreshTokens, IUnitOfWork unitOfWork) =>
            new(refreshTokens, unitOfWork, new ListLogger<RefreshTokenFamilyStore>(FamilyLog));

        private static InteractiveAccessTokenFactory AccessTokens() =>
            new(new JwtOptions { Issuer = Issuer }, NullLogger<InteractiveAccessTokenFactory>.Instance);

        private static AuthMetrics Metrics()
        {
            var meterFactory = new Mock<System.Diagnostics.Metrics.IMeterFactory>();
            meterFactory
                .Setup(factory => factory.Create(It.IsAny<System.Diagnostics.Metrics.MeterOptions>()))
                .Returns(new System.Diagnostics.Metrics.Meter("SignaCore"));
            return new AuthMetrics(meterFactory.Object);
        }

        private static AppRegistrationEntity NewApplication(string appId, SmsLoginMode mode) => new()
        {
            Id = Guid.NewGuid(),
            AppId = appId,
            AppSecretHash = "hash",
            AppName = appId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = AudienceMode.PerApplication,
            ClientType = OidcClientType.Confidential,
            AllowAuthorizationCode = true,
            AllowedScopes = OfflineScope,
            AllowRefreshToken = true,
            SmsLoginMode = mode,
            RedirectUris =
            [
                new AppRedirectUriEntity
                {
                    Id = Guid.NewGuid(),
                    Kind = RedirectUriKind.Redirect,
                    CanonicalUri = RedirectUri
                }
            ]
        };

        private static AppSmsAccessEntity NewAdmission(Guid applicationRowId, Guid loginId, SmsAccessApprovalSource source) => new()
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = applicationRowId,
            UserLoginId = loginId,
            ApprovalSource = source,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
    }

    /// <summary>
    /// Stages the real family revocation inside the rejecting transaction, then observes the
    /// caller's cancellation before the commit — the <c>EV-18</c> shape of a refresh cancelled
    /// after its decision and before its commit.
    /// </summary>
    private sealed class CancelAfterRevokeFamilyStore(
        IRefreshTokenFamilyStore inner,
        CancellationTokenSource cancellation) : IRefreshTokenFamilyStore
    {
        public Task<InteractiveRefreshFamilyRootCreation> CreateRootAsync(
            InteractiveRefreshFamilyRootDescriptor descriptor, DateTimeOffset now, CancellationToken cancellationToken = default) =>
            inner.CreateRootAsync(descriptor, now, cancellationToken);

        public Task CreateChildAsync(
            InteractiveRefreshChildDescriptor descriptor, DateTimeOffset now, CancellationToken cancellationToken = default) =>
            inner.CreateChildAsync(descriptor, now, cancellationToken);

        public Task<bool> TryConsumeAsync(Guid memberId, DateTimeOffset now, CancellationToken cancellationToken = default) =>
            inner.TryConsumeAsync(memberId, now, cancellationToken);

        public async Task<int> RevokeFamilyAsync(
            Guid rootId, RefreshFamilyRevocationReason reason, CancellationToken cancellationToken = default)
        {
            var revoked = await inner.RevokeFamilyAsync(rootId, reason, CancellationToken.None);
            await cancellation.CancelAsync();
            cancellationToken.ThrowIfCancellationRequested();
            return revoked;
        }

        public Task<int> RevokeLiveDescendantsAsync(
            Guid familyId, Guid memberId, RefreshFamilyRevocationReason reason, CancellationToken cancellationToken = default) =>
            inner.RevokeLiveDescendantsAsync(familyId, memberId, reason, cancellationToken);

        public Task<int> RevokeBySessionAsync(
            Guid identitySessionId, RefreshFamilyRevocationReason reason, CancellationToken cancellationToken = default) =>
            inner.RevokeBySessionAsync(identitySessionId, reason, cancellationToken);

        public Task<int> RevokeByAccountAsync(
            Guid accountId, RefreshFamilyRevocationReason reason, CancellationToken cancellationToken = default) =>
            inner.RevokeByAccountAsync(accountId, reason, cancellationToken);

        public Task<int> RevokeByApplicationAsync(
            string appId, RefreshFamilyRevocationReason reason, CancellationToken cancellationToken = default) =>
            inner.RevokeByApplicationAsync(appId, reason, cancellationToken);

        public Task<int> CleanupExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default) =>
            inner.CleanupExpiredAsync(now, cancellationToken);
    }

    /// <summary>One fixed RSA key; <see cref="BeforeRefresh"/> runs at the pre-transaction key refresh.</summary>
    private sealed class HookedKeyManager : IKeyManager
    {
        private readonly RsaSecurityKey _key = new(RSA.Create(2048)) { KeyId = Guid.NewGuid().ToString() };

        public Func<Task>? BeforeRefresh { get; set; }

        public RsaSecurityKey GetCurrentKey() => _key;

        public IReadOnlyList<SecurityKey> GetValidationKeys() => [_key];

        public async Task RefreshKeysAsync(CancellationToken cancellationToken = default)
        {
            if (BeforeRefresh is { } hook)
            {
                BeforeRefresh = null;
                await hook();
            }
        }

        public Task<IReadOnlyList<RsaSecurityKey>> GetValidKeysAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<RsaSecurityKey>>([_key]);

        public Task<bool> NeedsKeyRotationAsync(CancellationToken cancellationToken = default) => Task.FromResult(false);

        public Task RotateKeyAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task InitializationCompleted => Task.CompletedTask;
    }

    private sealed class ListLogger<T>(List<string> entries) : ILogger<T>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (entries)
            {
                entries.Add(formatter(state, exception));
            }
        }
    }
}
