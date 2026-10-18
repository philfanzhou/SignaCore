using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host;
using SignaCore.Host.Http;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The stable <c>code=SMS_LOGIN_DISABLED</c> on the legacy <c>/api/auth/sms-code</c> and
/// <c>/api/auth/token</c> (<c>grantType=sms</c>) responses over the real host (#609): it appears only
/// for the committed <c>Disabled</c> policy of the calling application, is omitted (never null) from
/// every other answer, and changes no existing field or side effect.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class LegacySmsDisabledReasonTests : IClassFixture<IdentityServerFixture>
{
    private const string SmsDisabledMessage = "SMS login is disabled for this application";
    private const string SmsDisabledCode = "SMS_LOGIN_DISABLED";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly IdentityServerFixture _fixture;

    public LegacySmsDisabledReasonTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    /// <summary>
    /// A committed change to <c>Disabled</c> (through the admin API, on another host instance) adds
    /// the code to the next request on both endpoints; a committed change back (a direct database
    /// update) removes it and restores the existing answers. A second application in another mode is
    /// unaffected throughout.
    /// </summary>
    [Fact]
    public async Task PolicyChange_AddsAndRemovesTheCode_ForThatApplicationOnly()
    {
        using var host = _fixture.WithTestServices(_ => { });
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var changed = await SeedAppAsync(host.Services, SmsLoginMode.ManualApproval);
        var other = await SeedAppAsync(host.Services, SmsLoginMode.ManualApproval);
        using var gateway = CreateClient(host, changed);
        using var otherGateway = CreateClient(host, other);
        var phone = NewPhone();

        // ManualApproval without a provider profile: the existing answers, no code.
        await AssertManualApprovalAnswersAsync(gateway, phone);
        await AssertManualApprovalAnswersAsync(otherGateway, phone);

        await SetPolicyThroughAdminAsync(admin, changed, "Disabled");
        await AssertDisabledAnswersAsync(gateway, phone);
        await AssertManualApprovalAnswersAsync(otherGateway, phone);

        await SetPolicyInDatabaseAsync(host.Services, changed, SmsLoginMode.ManualApproval);
        await AssertManualApprovalAnswersAsync(gateway, phone);
        await AssertManualApprovalAnswersAsync(otherGateway, phone);

        await SetPolicyInDatabaseAsync(host.Services, other, SmsLoginMode.Disabled);
        await AssertDisabledAnswersAsync(otherGateway, phone);
        await AssertManualApprovalAnswersAsync(gateway, phone);
    }

    /// <summary>
    /// The full SMS flow under <c>AutoProvision</c>: success, a wrong code, and an invalid phone carry
    /// no code. After the change to <c>Disabled</c>, both endpoints answer with the code and do no
    /// work: no SMS is sent, the still-valid earlier code is not consumed, no token, refresh token,
    /// account, or admission is created, sms-code writes no audit row, and the token request writes
    /// exactly one <c>login_failure</c> row with the existing reason. A refresh of the SMS-origin
    /// session keeps its existing failure without the code.
    /// </summary>
    [Fact]
    public async Task DisabledPolicy_AnswersWithTheCode_AndDoesNoWork()
    {
        var sender = new FakeSmsSender();
        using var host = _fixture.CreateSmsHost(sender);
        var app = await SeedAppAsync(host.Services, SmsLoginMode.AutoProvision, OAuthLoginSmsCodeTestSupport.ProfileKey);
        using var gateway = CreateClient(host, app);
        var signedIn = NewPhone();
        var pending = NewPhone();
        var fresh = NewPhone();

        // Enabled: success and the ordinary failures have no code property.
        var sent = await PostSmsCodeAsync(gateway, signedIn);
        AssertBody(sent, success: true, "Verification code sent", code: null);
        var signIn = await PostSmsTokenAsync(gateway, signedIn, sender.Calls.Last().Code);
        AssertBody(signIn, success: true, "Login successful", code: null);
        var refreshToken = signIn.GetProperty("refreshToken").GetString();
        Assert.False(string.IsNullOrEmpty(refreshToken));
        AssertBody(await PostSmsCodeAsync(gateway, "12345"), success: false, "Invalid mainland China mobile number", code: null);
        AssertBody(await PostSmsCodeAsync(gateway, pending), success: true, "Verification code sent", code: null);
        var pendingCode = sender.Calls.Last().Code;
        var wrongCode = pendingCode == "000000" ? "111111" : "000000";
        AssertBody(await PostSmsTokenAsync(gateway, pending, wrongCode), success: false, "Wrong or expired verification code", code: null);
        AssertBody(await PostSmsTokenAsync(gateway, fresh, ""), success: false, "Phone or code cannot be empty", code: null);

        await SetPolicyInDatabaseAsync(host.Services, app, SmsLoginMode.Disabled);
        var sendsBefore = sender.CallCount;
        var otpBefore = await OAuthLoginSmsCodeTestSupport.OtpAsync(
            host.Services, app.Id, OAuthLoginSmsCodeTestSupport.E164(pending));
        var historiesBefore = await OAuthLoginSmsCodeTestSupport.SmsHistoriesAsync(host.Services, app.AppId);
        var refreshTokensBefore = await RefreshTokenCountAsync(host.Services, app.AppId);

        // sms-code: the code, no send, no OTP or identity row, no audit row.
        AssertBody(await PostSmsCodeAsync(gateway, fresh), success: false, SmsDisabledMessage, SmsDisabledCode);
        Assert.Equal(sendsBefore, sender.CallCount);
        Assert.Null(await OAuthLoginSmsCodeTestSupport.OtpAsync(host.Services, app.Id, OAuthLoginSmsCodeTestSupport.E164(fresh)));
        Assert.Equal(0, await OAuthLoginSmsCodeTestSupport.PhoneIdentityRowCountAsync(
            host.Services, OAuthLoginSmsCodeTestSupport.E164(fresh)));
        Assert.Equal(historiesBefore.Count, (await OAuthLoginSmsCodeTestSupport.SmsHistoriesAsync(host.Services, app.AppId)).Count);

        // token: the code with a still-valid code, the OTP row untouched, one failure audit row.
        var refused = await PostSmsTokenAsync(gateway, pending, pendingCode);
        AssertBody(refused, success: false, SmsDisabledMessage, SmsDisabledCode);
        Assert.True(string.IsNullOrEmpty(refused.GetProperty("accessToken").GetString()));
        Assert.True(string.IsNullOrEmpty(refused.GetProperty("refreshToken").GetString()));
        var otpAfter = await OAuthLoginSmsCodeTestSupport.OtpAsync(
            host.Services, app.Id, OAuthLoginSmsCodeTestSupport.E164(pending));
        Assert.NotNull(otpBefore);
        Assert.NotNull(otpAfter);
        Assert.Equal(
            (otpBefore.Status, otpBefore.Attempts, otpBefore.Version, otpBefore.CodeMac),
            (otpAfter.Status, otpAfter.Attempts, otpAfter.Version, otpAfter.CodeMac));
        Assert.Equal(0, await OAuthLoginSmsCodeTestSupport.PhoneIdentityRowCountAsync(
            host.Services, OAuthLoginSmsCodeTestSupport.E164(pending)));
        Assert.Equal(refreshTokensBefore, await RefreshTokenCountAsync(host.Services, app.AppId));
        var newHistories = (await OAuthLoginSmsCodeTestSupport.SmsHistoriesAsync(host.Services, app.AppId))
            .Where(row => historiesBefore.All(before => before.Id != row.Id))
            .ToList();
        var failure = Assert.Single(newHistories);
        Assert.Equal("login_failure", failure.EventType);
        Assert.Equal(IdentityConstants.GrantTypeSms, failure.AuthMethod);
        Assert.Equal(SmsDisabledMessage, failure.FailureReason);
        Assert.Equal(pending, failure.Username);

        // Empty phone: sms-code still checks it first (no code); token checks the policy first.
        AssertBody(await PostSmsCodeAsync(gateway, ""), success: false, "Phone number is required", code: null);
        AssertBody(await PostSmsTokenAsync(gateway, "", ""), success: false, SmsDisabledMessage, SmsDisabledCode);

        // A refresh of the SMS-origin session keeps its existing failure, without the code.
        AssertBody(
            await PostAsync(gateway, "/api/auth/token", new { grantType = IdentityConstants.GrantTypeRefreshToken, refreshToken }),
            success: false,
            SmsDisabledMessage,
            code: null);
    }

    // ---- assertions ----

    private static async Task AssertManualApprovalAnswersAsync(HttpClient gateway, string phone)
    {
        AssertBody(
            await PostSmsCodeAsync(gateway, phone),
            success: false,
            "SMS provider is not configured for this application",
            code: null);
        AssertBody(
            await PostSmsTokenAsync(gateway, phone, "123456"),
            success: false,
            "SMS account is not authorized for this application",
            code: null);
    }

    private static async Task AssertDisabledAnswersAsync(HttpClient gateway, string phone)
    {
        var smsCode = await PostSmsCodeAsync(gateway, phone);
        AssertBody(smsCode, success: false, SmsDisabledMessage, SmsDisabledCode);
        Assert.Equal(["success", "message", "code"], smsCode.EnumerateObject().Select(property => property.Name));

        var token = await PostSmsTokenAsync(gateway, phone, "123456");
        AssertBody(token, success: false, SmsDisabledMessage, SmsDisabledCode);
        Assert.Equal(
            ["success", "message", "accessToken", "refreshToken", "expiresIn", "expiresAt", "userInfo", "code"],
            token.EnumerateObject().Select(property => property.Name));
    }

    /// <summary>
    /// Asserts the existing fields, and that <c>code</c> either equals <paramref name="code"/> or is
    /// absent from the serialized JSON (not present as null).
    /// </summary>
    private static void AssertBody(JsonElement body, bool success, string message, string? code)
    {
        Assert.Equal(success, body.GetProperty("success").GetBoolean());
        Assert.Equal(message, body.GetProperty("message").GetString());
        if (code is null)
        {
            Assert.False(body.TryGetProperty("code", out _), "The code property must be omitted.");
        }
        else
        {
            Assert.Equal(JsonValueKind.String, body.GetProperty("code").ValueKind);
            Assert.Equal(code, body.GetProperty("code").GetString());
        }
    }

    // ---- requests ----

    private static Task<JsonElement> PostSmsCodeAsync(HttpClient gateway, string phone) =>
        PostAsync(gateway, "/api/auth/sms-code", new { phone });

    private static Task<JsonElement> PostSmsTokenAsync(HttpClient gateway, string phone, string code) =>
        PostAsync(gateway, "/api/auth/token", new { grantType = IdentityConstants.GrantTypeSms, phone, code });

    private static async Task<JsonElement> PostAsync(HttpClient gateway, string path, object body)
    {
        using var response = await gateway.PostAsJsonAsync(path, body, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>(Ct);
    }

    // ---- arrangement ----

    private sealed record SeededApp(Guid Id, string AppId, string Secret);

    private static string NewPhone() => OAuthLoginSmsCodeTestSupport.NewPhone();

    private static async Task<SeededApp> SeedAppAsync(IServiceProvider services, SmsLoginMode mode, string? profileKey = null)
    {
        var appId = "legacy-sms-" + Guid.NewGuid().ToString("N")[..12];
        var secret = "legacy-sms-secret-" + Guid.NewGuid().ToString("N");
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var entity = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = appId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword(secret, 4),
            AppName = "Legacy SMS Reason Test App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = AudienceMode.PerApplication,
            SmsLoginMode = mode,
            SmsProfileKey = profileKey
        };
        db.AppRegistrations.Add(entity);
        await db.SaveChangesAsync(Ct);
        return new SeededApp(entity.Id, appId, secret);
    }

    private static HttpClient CreateClient(WebApplicationFactory<Program> host, SeededApp app)
    {
        var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = false
        });
        http.DefaultRequestHeaders.Add(IdentityHeaders.AppId, app.AppId);
        http.DefaultRequestHeaders.Add(IdentityHeaders.AppSecret, app.Secret);
        return http;
    }

    private static async Task SetPolicyThroughAdminAsync(HttpClient admin, SeededApp app, string mode)
    {
        using var response = await admin.PutAsJsonAsync(
            $"/api/admin/apps/{app.AppId}/sms-policy", new { mode, profileKey = (string?)null }, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static Task SetPolicyInDatabaseAsync(IServiceProvider services, SeededApp app, SmsLoginMode mode) =>
        OAuthLoginSmsCodeTestSupport.WithDbAsync(services, db => db.AppRegistrations
            .Where(row => row.Id == app.Id)
            .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.SmsLoginMode, mode), Ct));

    private static Task<int> RefreshTokenCountAsync(IServiceProvider services, string appId) =>
        OAuthLoginSmsCodeTestSupport.QueryDbAsync(services, db => db.RefreshTokens.CountAsync(row => row.AppId == appId, Ct));
}
