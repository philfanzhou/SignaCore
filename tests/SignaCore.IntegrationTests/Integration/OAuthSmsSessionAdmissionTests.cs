using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServiceMantle.Persistence.Relational;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Database;
using SignaCore.Domain.Services;
using SignaCore.Host.Security;
using SignaCore.Host;
using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net;
using System.Text.Json;
using System.Text;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The SQLite HTTP contract of the application operations on an <c>Sms</c> identity session
/// (#453, <c>EV-38</c>, <c>SC-24</c>, <c>PS-12</c>/<c>PS-13</c>/<c>PS-16</c>). The session, its SMS
/// login identity, and the admissions come from the real stores (<c>CreateSmsAsync</c>), so the
/// suite does not depend on the browser SMS login submission: the redemption, refresh, and
/// UserInfo answers carry <c>amr: ["sms"]</c>, <c>auth_method: Sms</c>, the <c>name</c> rule, and
/// no phone in any body, token, or log line; authorize reuse admits only applications whose
/// <c>PS-04</c> predicate holds; and the administrator's SMS-user revocation makes that
/// application's next refresh revoke its family with <c>sms_admission</c> and its UserInfo answer
/// <c>invalid_token</c>, while the other application and the session stay unaffected.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class OAuthSmsSessionAdmissionTests : IClassFixture<IdentityServerFixture>
{
    private const string AppSecret = "sms-session-admission-secret";
    private const string RedirectUri = "https://bff.sms-session.test/callback";
    private const string Nonce = "sms-session-nonce-0123456789";
    private const string OfflineScope = "openid profile offline_access";

    // RFC 7636 appendix B.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly IdentityServerFixture _fixture;

    public OAuthSmsSessionAdmissionTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task RedeemRefreshAndUserInfo_CarryTheSmsMappingAndNeverThePhone()
    {
        var logs = new ConcurrentQueue<string>();
        await using var host = CreateCapturingHost(logs);
        var seed = await SeedAsync(host.Services, passwordUsername: "sms_session_named_" + Guid.NewGuid().ToString("N")[..8]);
        using var http = host.CreateClient();
        var bodies = new List<string>();

        var code = await CreateCodeAsync(host.Services, seed, seed.AppA);
        using var redeemed = await TokenAsync(http, seed.AppA.AppId, new()
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = RedirectUri,
            ["code_verifier"] = Verifier
        });
        var redeemedBody = await redeemed.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        bodies.Add(redeemedBody);
        Assert.Equal(HttpStatusCode.OK, redeemed.StatusCode);
        var redemption = JsonDocument.Parse(redeemedBody).RootElement;

        var idPayload = Payload(redemption.GetProperty("id_token").GetString()!);
        var amr = idPayload.GetProperty("amr");
        Assert.Equal(JsonValueKind.Array, amr.ValueKind);
        Assert.Equal(["sms"], amr.EnumerateArray().Select(value => value.GetString()).ToArray());
        Assert.Equal(seed.PasswordUsername, idPayload.GetProperty("name").GetString());
        Assert.Equal(seed.AccountId.ToString(), idPayload.GetProperty("sub").GetString());
        var accessPayload = Payload(redemption.GetProperty("access_token").GetString()!);
        Assert.Equal("Sms", accessPayload.GetProperty("auth_method").GetString());

        using var refreshed = await TokenAsync(http, seed.AppA.AppId, new()
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = redemption.GetProperty("refresh_token").GetString()!
        });
        var refreshedBody = await refreshed.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        bodies.Add(refreshedBody);
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        var rotation = JsonDocument.Parse(refreshedBody).RootElement;
        var refreshedIdPayload = Payload(rotation.GetProperty("id_token").GetString()!);
        Assert.Equal(["sms"], refreshedIdPayload.GetProperty("amr").EnumerateArray().Select(value => value.GetString()).ToArray());
        Assert.Equal(seed.PasswordUsername, refreshedIdPayload.GetProperty("name").GetString());

        using var userInfo = await UserInfoAsync(http, rotation.GetProperty("access_token").GetString()!);
        var userInfoBody = await userInfo.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        bodies.Add(userInfoBody);
        Assert.Equal(HttpStatusCode.OK, userInfo.StatusCode);
        var claims = JsonDocument.Parse(userInfoBody).RootElement;
        Assert.Equal(seed.PasswordUsername, claims.GetProperty("name").GetString());
        Assert.Equal(seed.AccountId.ToString(), claims.GetProperty("sub").GetString());

        // No phone number anywhere: bodies, decoded token segments, and every captured log line.
        var tokens = new[]
        {
            redemption.GetProperty("id_token").GetString()!,
            redemption.GetProperty("access_token").GetString()!,
            rotation.GetProperty("id_token").GetString()!,
            rotation.GetProperty("access_token").GetString()!
        };
        var logText = string.Join('\n', logs);
        Assert.Contains("Authorization code redeemed", logText, StringComparison.Ordinal);
        var visible = string.Join('\n', bodies.Concat(tokens.Select(Decode)).Append(logText));
        Assert.DoesNotContain(seed.BarePhone, visible, StringComparison.Ordinal);
        Assert.DoesNotContain(seed.PhoneE164, visible, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AdministratorRevokingTheSmsUser_RevokesOnlyThatApplicationsFamilyOnItsNextRefresh()
    {
        var logs = new ConcurrentQueue<string>();
        await using var host = CreateCapturingHost(logs);
        var seed = await SeedAsync(host.Services);
        using var http = host.CreateClient();
        var familyA = await RedeemFamilyAsync(host.Services, http, seed, seed.AppA);
        var familyB = await RedeemFamilyAsync(host.Services, http, seed, seed.AppB);
        var pendingCode = await CreateCodeAsync(host.Services, seed, seed.AppA);

        using (var admin = await _fixture.CreateAdminHttpClientAsync())
        {
            using var revoked = await admin.DeleteAsync(
                $"/api/admin/apps/{seed.AppA.AppId}/sms-users/{seed.SmsLoginId}",
                TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        }

        // The administrator transaction writes no interactive family; the next refresh does.
        Assert.False(await AnyRevokedAsync(host.Services, familyA.RootId));
        logs.Clear();
        using (var rejected = await TokenAsync(http, seed.AppA.AppId, new()
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = familyA.RefreshToken
        }))
        {
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
            Assert.Equal("invalid_grant", (await rejected.Content.ReadFromJsonAsync<JsonElement>(
                cancellationToken: TestContext.Current.CancellationToken)).GetProperty("error").GetString());
        }

        Assert.True(await AllRevokedAsync(host.Services, familyA.RootId));
        Assert.Contains(logs, line => line.Contains($"RootId={familyA.RootId}", StringComparison.Ordinal)
            && line.Contains("Reason=SmsAdmission", StringComparison.Ordinal));
        Assert.Null((await SessionAsync(host.Services, seed.SessionId)).RevokedAt);

        // UserInfo for A: the same 401 invalid_token answer as any other rejected live state.
        using var smsRejection = await UserInfoAsync(http, familyA.AccessToken);
        var reference = await RevokedSessionUserInfoAsync(host.Services, http, seed);
        Assert.Equal(HttpStatusCode.Unauthorized, smsRejection.StatusCode);
        Assert.Equal(reference.Challenge, smsRejection.Headers.WwwAuthenticate.Single().ToString());
        Assert.Contains("error=\"invalid_token\"", reference.Challenge, StringComparison.Ordinal);
        Assert.Equal(
            WithoutTraceId(reference.Body),
            WithoutTraceId(await smsRejection.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)));

        // A's pending code: the generic invalid_grant, unconsumed.
        using (var redeem = await TokenAsync(http, seed.AppA.AppId, new()
        {
            ["grant_type"] = "authorization_code",
            ["code"] = pendingCode,
            ["redirect_uri"] = RedirectUri,
            ["code_verifier"] = Verifier
        }))
        {
            Assert.Equal(HttpStatusCode.BadRequest, redeem.StatusCode);
        }

        // The family code of A was consumed earlier; the pending one alone stays unconsumed.
        Assert.Equal(1, await QueryAsync(host.Services, db => db.AuthorizationCodes
            .CountAsync(row => row.IdentitySessionId == seed.SessionId
                && row.AppRegistrationId == seed.AppA.Id
                && row.ConsumedAt == null
                && row.RefreshFamilyId == null, TestContext.Current.CancellationToken)));

        // B is unaffected: its family keeps rotating and its UserInfo answers.
        using (var refreshedB = await TokenAsync(http, seed.AppB.AppId, new()
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = familyB.RefreshToken
        }))
        {
            Assert.Equal(HttpStatusCode.OK, refreshedB.StatusCode);
        }

        using (var userInfoB = await UserInfoAsync(http, familyB.AccessToken))
        {
            Assert.Equal(HttpStatusCode.OK, userInfoB.StatusCode);
        }

        // Restoring the admission does not revive the revoked family.
        await ExecuteAsync(host.Services, db => db.AppSmsAccesses
            .Where(row => row.AppRegistrationId == seed.AppA.Id && row.UserLoginId == seed.SmsLoginId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsActive, true),
                TestContext.Current.CancellationToken));
        using (var stillRejected = await TokenAsync(http, seed.AppA.AppId, new()
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = familyA.RefreshToken
        }))
        {
            Assert.Equal(HttpStatusCode.BadRequest, stillRejected.StatusCode);
        }
    }

    [Fact]
    public async Task Authorize_ReusesTheSmsSessionOnlyForApplicationsWhosePredicateHolds()
    {
        var seed = await SeedAsync(_fixture.Services);
        await ExecuteAsync(_fixture.Services, db => db.AppSmsAccesses
            .Where(row => row.AppRegistrationId == seed.AppA.Id)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.ApprovalSource, SmsAccessApprovalSource.AutoProvision),
                TestContext.Current.CancellationToken));
        var stale = DateTimeOffset.UtcNow.AddMinutes(-2);
        await ExecuteAsync(_fixture.Services, db => db.IdentitySessions
            .Where(row => row.Id == seed.SessionId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.LastSeenAt, stale)
                .SetProperty(row => row.IdleExpiresAt, stale.AddMinutes(30)),
                TestContext.Current.CancellationToken));
        var cookie = MintIdentityCookie(_fixture.Services, seed.SessionId);
        var admissions = await AdmissionSnapshotAsync(_fixture.Services, seed);
        using var client = _fixture.CreateNonRedirectingHttpClient(handleCookies: false);

        // A (ManualApproval, not Admin-approved): the login continuation, no code, no activity.
        var continuationsA = await QueryAsync(_fixture.Services, db => db.AuthorizationRequests
            .CountAsync(row => row.AppRegistrationId == seed.AppA.Id, TestContext.Current.CancellationToken));
        using (var fallback = await client.SendAsync(
                   AuthorizeRequest(seed.AppA.AppId, cookie), TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.Found, fallback.StatusCode);
            Assert.StartsWith("/oauth2/login?login_handle=", fallback.Headers.Location!.ToString(), StringComparison.Ordinal);
        }

        Assert.Equal(continuationsA + 1, await QueryAsync(_fixture.Services, db => db.AuthorizationRequests
            .CountAsync(row => row.AppRegistrationId == seed.AppA.Id, TestContext.Current.CancellationToken)));
        Assert.Equal(0, await QueryAsync(_fixture.Services, db => db.AuthorizationCodes
            .CountAsync(row => row.IdentitySessionId == seed.SessionId, TestContext.Current.CancellationToken)));
        var afterFallback = await SessionAsync(_fixture.Services, seed.SessionId);
        Assert.Equal(stale.UtcTicks / 10, afterFallback.LastSeenAt.UtcTicks / 10);
        Assert.Null(afterFallback.RevokedAt);
        Assert.Equal(admissions, await AdmissionSnapshotAsync(_fixture.Services, seed));

        // B (AutoProvision, active admission): reused without login, bound to the same session.
        using (var reused = await client.SendAsync(
                   AuthorizeRequest(seed.AppB.AppId, cookie), TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.Found, reused.StatusCode);
            var location = reused.Headers.Location!.ToString();
            Assert.StartsWith(RedirectUri, location, StringComparison.Ordinal);
            Assert.Contains("code=", location, StringComparison.Ordinal);
        }

        Assert.Equal(1, await QueryAsync(_fixture.Services, db => db.AuthorizationCodes
            .CountAsync(row => row.IdentitySessionId == seed.SessionId && row.AppRegistrationId == seed.AppB.Id,
                TestContext.Current.CancellationToken)));
        Assert.True((await SessionAsync(_fixture.Services, seed.SessionId)).LastSeenAt > stale);
        Assert.Equal(admissions, await AdmissionSnapshotAsync(_fixture.Services, seed));
    }

    // ---- Seeding ----

    private sealed record SeededApp(Guid Id, string AppId);

    private sealed record Seed(
        SeededApp AppA,
        SeededApp AppB,
        Guid AccountId,
        Guid SmsLoginId,
        Guid SessionId,
        string BarePhone,
        string PhoneE164,
        string? PasswordUsername);

    private sealed record Family(string AccessToken, string RefreshToken, Guid RootId);

    /// <summary>
    /// Two applications that both admit one fresh phone — A under <c>ManualApproval</c> with an
    /// Admin-approved admission, B under <c>AutoProvision</c> — and one live <c>Sms</c> session.
    /// </summary>
    private static async Task<Seed> SeedAsync(IServiceProvider services, string? passwordUsername = null)
    {
        var ct = TestContext.Current.CancellationToken;
        var suffix = Guid.NewGuid().ToString("N")[..12];
        var bare = "139" + Random.Shared.NextInt64(0, 100_000_000).ToString("D8", System.Globalization.CultureInfo.InvariantCulture);
        var phone = "+86" + bare;
        var appA = new SeededApp(Guid.NewGuid(), "sms-session-a-" + suffix);
        var appB = new SeededApp(Guid.NewGuid(), "sms-session-b-" + suffix);
        var accountId = Guid.NewGuid();
        var loginId = Guid.NewGuid();
        await ExecuteAsync(services, async db =>
        {
            db.AppRegistrations.Add(NewApplication(appA, SmsLoginMode.ManualApproval));
            db.AppRegistrations.Add(NewApplication(appB, SmsLoginMode.AutoProvision));
            db.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });
            db.UserLogins.Add(new UserLoginEntity
            {
                Id = loginId,
                AccountId = accountId,
                ProviderName = IdentityConstants.AuthMethodSms,
                ProviderUserId = phone
            });
            if (passwordUsername is not null)
            {
                db.PasswordCredentials.Add(new PasswordCredentialEntity
                {
                    Id = Guid.NewGuid(),
                    AccountId = accountId,
                    Username = passwordUsername,
                    PasswordHash = "unused-hash",
                    CreatedAt = DateTimeOffset.UtcNow
                });
            }

            db.AppSmsAccesses.Add(NewAdmission(appA.Id, loginId, SmsAccessApprovalSource.Admin));
            db.AppSmsAccesses.Add(NewAdmission(appB.Id, loginId, SmsAccessApprovalSource.AutoProvision));
            await db.SaveChangesAsync(ct);
        });

        var sessionId = Guid.Empty;
        await ExecuteAsync(services, async db =>
        {
            var session = await new IdentitySessionStore(new IdentitySessionRepository(db), new EfCoreUnitOfWork(db))
                .CreateSmsAsync(accountId, loginId, DateTimeOffset.UtcNow, ct);
            sessionId = session.Id;
        });
        return new Seed(appA, appB, accountId, loginId, sessionId, bare, phone, passwordUsername);
    }

    private static AppRegistrationEntity NewApplication(SeededApp app, SmsLoginMode mode) => new()
    {
        Id = app.Id,
        AppId = app.AppId,
        AppSecretHash = BCrypt.Net.BCrypt.HashPassword(AppSecret),
        AppName = "SMS Session " + app.AppId,
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
                AppRegistrationId = app.Id,
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

    private static async Task<string> CreateCodeAsync(IServiceProvider services, Seed seed, SeededApp app)
    {
        using var scope = services.CreateScope();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var sessions = new IdentitySessionStore(
            scope.ServiceProvider.GetRequiredService<IIdentitySessionRepository>(), unitOfWork);
        var codes = new AuthorizationCodeStore(
            scope.ServiceProvider.GetRequiredService<IAuthorizationCodeRepository>(), unitOfWork);
        var lookup = await sessions.GetAsync(seed.SessionId, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
        Assert.Equal(IdentitySessionState.Active, lookup.State);
        var creation = await codes.CreateAsync(
            lookup.Session!,
            new AuthorizationCodeBinding(app.Id, RedirectUri, OfflineScope, Nonce, Challenge),
            DateTimeOffset.UtcNow,
            TestContext.Current.CancellationToken);
        return creation.Code;
    }

    private static async Task<Family> RedeemFamilyAsync(
        IServiceProvider services, HttpClient http, Seed seed, SeededApp app)
    {
        var code = await CreateCodeAsync(services, seed, app);
        using var response = await TokenAsync(http, app.AppId, new()
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = RedirectUri,
            ["code_verifier"] = Verifier
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);
        var refreshToken = body.GetProperty("refresh_token").GetString()!;
        var rootId = await QueryAsync(services, db => db.AuthorizationCodes.AsNoTracking()
            .Where(row => row.IdentitySessionId == seed.SessionId && row.AppRegistrationId == app.Id
                && row.RefreshFamilyId != null)
            .Select(row => row.RefreshFamilyId!.Value)
            .SingleAsync(TestContext.Current.CancellationToken));
        return new Family(body.GetProperty("access_token").GetString()!, refreshToken, rootId);
    }

    /// <summary>
    /// A UserInfo rejection of the same application's token for a different, administratively
    /// revoked <c>Sms</c> session — the reference shape of "another rejected live state".
    /// </summary>
    private static async Task<(string Challenge, string Body)> RevokedSessionUserInfoAsync(
        IServiceProvider services, HttpClient http, Seed seed)
    {
        var other = seed with { SessionId = Guid.Empty };
        await ExecuteAsync(services, async db =>
        {
            var session = await new IdentitySessionStore(new IdentitySessionRepository(db), new EfCoreUnitOfWork(db))
                .CreateSmsAsync(seed.AccountId, seed.SmsLoginId, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
            other = seed with { SessionId = session.Id };
        });
        // B still admits the phone, so this redemption succeeds before the session is revoked.
        var family = await RedeemFamilyAsync(services, http, other, seed.AppB);
        await ExecuteAsync(services, async db =>
        {
            await using var transaction = await db.Database.BeginTransactionAsync(TestContext.Current.CancellationToken);
            await new IdentitySessionStore(new IdentitySessionRepository(db), new EfCoreUnitOfWork(db))
                .RevokeAsync(other.SessionId, IdentitySessionRevocationReason.Administrative, DateTimeOffset.UtcNow,
                    TestContext.Current.CancellationToken);
            await transaction.CommitAsync(TestContext.Current.CancellationToken);
        });
        using var response = await UserInfoAsync(http, family.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        return (response.Headers.WwwAuthenticate.Single().ToString(),
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    // ---- HTTP ----

    private WebApplicationFactory<Program> CreateCapturingHost(ConcurrentQueue<string> logs) =>
        _fixture.WithTestServices(services =>
        {
            services.RemoveAll<ILoggerFactory>();
            services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
            {
                logging.AddProvider(new CapturingLoggerProvider(logs));
                logging.SetMinimumLevel(LogLevel.Information);
                logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
                logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning);
            }));
        });

    private static async Task<HttpResponseMessage> TokenAsync(
        HttpClient http, string appId, Dictionary<string, string> fields)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
        {
            Content = new FormUrlEncodedContent(fields)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{appId}:{AppSecret}")));
        return await http.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static async Task<HttpResponseMessage> UserInfoAsync(HttpClient http, string accessToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/oauth2/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await http.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static HttpRequestMessage AuthorizeRequest(string appId, string cookieValue)
    {
        var url = "/oauth2/authorize?" + string.Join('&', new[]
        {
            ("response_type", "code"),
            ("client_id", appId),
            ("redirect_uri", RedirectUri),
            ("scope", "openid profile"),
            ("state", "sms-session-state-0123456789"),
            ("nonce", Nonce),
            ("code_challenge", Challenge),
            ("code_challenge_method", "S256"),
        }.Select(pair => $"{Uri.EscapeDataString(pair.Item1)}={Uri.EscapeDataString(pair.Item2)}"));
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Cookie", $"{IdentitySessionDefaults.CookieName}={cookieValue}");
        return request;
    }

    /// <summary>
    /// The protected <c>PS-18</c> identity cookie for one session id, minted by the host's own
    /// identity-scheme ticket format — the exact payload the login success path writes.
    /// </summary>
    private static string MintIdentityCookie(IServiceProvider services, Guid sessionId)
    {
        var options = services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(IdentitySessionDefaults.AuthenticationScheme);
        var now = DateTimeOffset.UtcNow;
        return options.TicketDataFormat.Protect(new AuthenticationTicket(
            IdentitySessionPrincipal.Create(sessionId),
            new AuthenticationProperties { IssuedUtc = now, ExpiresUtc = now.AddHours(1) },
            IdentitySessionDefaults.AuthenticationScheme));
    }

    /// <summary>The problem body with its per-request trace id removed, as sorted name=value lines.</summary>
    private static string WithoutTraceId(string body) =>
        string.Join('\n', JsonDocument.Parse(body).RootElement.EnumerateObject()
            .Where(property => property.Name != "traceId")
            .Select(property => $"{property.Name}={property.Value.GetRawText()}")
            .Order(StringComparer.Ordinal));

    private static JsonElement Payload(string jwt) =>
        JsonDocument.Parse(Base64UrlEncoder.Decode(jwt.Split('.')[1])).RootElement;

    private static string Decode(string jwt)
    {
        var segments = jwt.Split('.');
        return Base64UrlEncoder.Decode(segments[0]) + Base64UrlEncoder.Decode(segments[1]);
    }

    // ---- Database ----

    private static Task<IdentitySessionEntity> SessionAsync(IServiceProvider services, Guid sessionId) =>
        QueryAsync(services, db => db.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == sessionId, TestContext.Current.CancellationToken));

    private static Task<bool> AllRevokedAsync(IServiceProvider services, Guid rootId) =>
        QueryAsync(services, db => db.RefreshTokens.AsNoTracking()
            .Where(row => row.FamilyId == rootId)
            .AllAsync(row => row.IsRevoked, TestContext.Current.CancellationToken));

    private static Task<bool> AnyRevokedAsync(IServiceProvider services, Guid rootId) =>
        QueryAsync(services, db => db.RefreshTokens.AsNoTracking()
            .Where(row => row.FamilyId == rootId)
            .AnyAsync(row => row.IsRevoked, TestContext.Current.CancellationToken));

    private static async Task<string> AdmissionSnapshotAsync(IServiceProvider services, Seed seed)
    {
        var rows = await QueryAsync(services, db => db.AppSmsAccesses.AsNoTracking()
            .Where(row => row.UserLoginId == seed.SmsLoginId)
            .OrderBy(row => row.Id)
            .Select(row => $"{row.Id}:{row.AppRegistrationId}:{row.ApprovalSource}:{row.IsActive}")
            .ToListAsync(TestContext.Current.CancellationToken));
        var logins = await QueryAsync(services, db => db.UserLogins.AsNoTracking()
            .CountAsync(row => row.AccountId == seed.AccountId, TestContext.Current.CancellationToken));
        return $"{string.Join('|', rows)}#{logins}";
    }

    private static async Task<TResult> QueryAsync<TResult>(
        IServiceProvider services, Func<IdentityDbContext, Task<TResult>> query)
    {
        using var scope = services.CreateScope();
        return await query(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }

    private static async Task ExecuteAsync(IServiceProvider services, Func<IdentityDbContext, Task> action)
    {
        using var scope = services.CreateScope();
        await action(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }

    private sealed class CapturingLoggerProvider(ConcurrentQueue<string> messages) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, messages);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(string categoryName, ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                messages.Enqueue(exception is null
                    ? $"[{logLevel}] {categoryName}: {formatter(state, exception)}"
                    : $"[{logLevel}] {categoryName}: {formatter(state, exception)}\n{exception}");
        }
    }
}
