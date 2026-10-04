using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.Sms;
using SignaCore.Host.Security;
using SignaCore.Host.Services;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginSmsCodeTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The browser SMS login <c>POST /oauth2/login</c> with <c>action=sms_login</c> over the real host
/// (#445, <c>AC-17</c>): the login page renders the SMS region exactly while <c>IN-19</c> is open;
/// the <c>IN-17</c>/<c>IN-18</c> shape checks and the closed gate are local answers; every
/// <c>EV-37</c> case answers one byte-identical generic page with only the masked audit row and
/// the closed metric carrying the case (<c>SC-22</c>); a verified code completes the <c>EV-36</c>
/// transaction whose code redeems into <c>amr: ["sms"]</c> with no phone anywhere (<c>SC-21</c>);
/// <c>AutoProvision</c> provisions only inside the successful login (<c>SC-23</c>); policy drift
/// after the OTP check consumes nothing; and the races of <c>SC-26</c> resolve to one winner.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class OAuthLoginSmsLoginEndpointTests : IClassFixture<IdentityServerFixture>
{
    private const string ClientSecret = "sms-login-client-secret";
    private const string CodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string WrongOtp = "000000";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly IdentityServerFixture _fixture;

    public OAuthLoginSmsLoginEndpointTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    // ---- AC-17: the SMS region follows the IN-19 gate ----

    [Theory]
    [InlineData(SmsLoginMode.ManualApproval, ProfileKey, true)]
    [InlineData(SmsLoginMode.AutoProvision, ProfileKey, true)]
    [InlineData(SmsLoginMode.Disabled, ProfileKey, false)]
    [InlineData(SmsLoginMode.AutoProvision, "  ", false)]
    [InlineData(SmsLoginMode.ManualApproval, null, false)]
    public async Task TheLoginPage_RendersTheSmsRegion_ExactlyWhileTheGateIsOpen(
        SmsLoginMode mode, string? profileKey, bool open)
    {
        using var host = _fixture.CreateSmsHost(new FakeSmsSender());
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, mode, profileKey);
        var (handle, _) = await SeedContinuationAsync(host.Services, app);

        using var page = await client.GetAsync($"/oauth2/login?login_handle={handle}", Ct);
        var body = await page.Content.ReadAsStringAsync(Ct);

        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        OAuthLoginTestSupport.AssertFormNoticePlacement(body);
        Assert.DoesNotContain("<script", body, StringComparison.OrdinalIgnoreCase);
        // The Password form keeps exactly its five fields in every case.
        Assert.Equal(1, Occurrences(body, "name=\"username\""));
        Assert.Equal(1, Occurrences(body, "name=\"password\""));
        Assert.Equal(1, Occurrences(body, "value=\"login\""));
        Assert.Equal(1, Occurrences(body, "value=\"cancel\""));
        if (open)
        {
            Assert.Equal(2, Occurrences(body, "<form "));
            Assert.Equal(2, Occurrences(body, "name=\"login_handle\""));
            Assert.Equal(2, Occurrences(body, "name=\"__RequestVerificationToken\""));
            Assert.Contains("<h2 id=\"sms-heading\">Sign in with a verification code</h2>", body, StringComparison.Ordinal);
            Assert.Contains(PhoneInput(string.Empty), body, StringComparison.Ordinal);
            Assert.Contains(OtpInput, body, StringComparison.Ordinal);
            Assert.Contains(SendButton + "Send code</button>", body, StringComparison.Ordinal);
            Assert.Contains(SmsSubmitButton + "Sign in with code</button>", body, StringComparison.Ordinal);
            // The SMS form follows the Password form, so its fields never join the Password POST.
            Assert.True(body.IndexOf("name=\"phone\"", StringComparison.Ordinal)
                > body.IndexOf("</form>", StringComparison.Ordinal));
        }
        else
        {
            Assert.Equal(1, Occurrences(body, "<form "));
            foreach (var absent in new[] { "sms_login", "name=\"phone\"", "name=\"otp\"", "formaction", "sms-code" })
            {
                Assert.DoesNotContain(absent, body, StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public async Task TheSmsRegion_IsLocalized_WithTheSameFieldsInEveryLanguage()
    {
        using var host = _fixture.CreateSmsHost(new FakeSmsSender());
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var (handle, _) = await SeedContinuationAsync(host.Services, app);

        using var request = new HttpRequestMessage(HttpMethod.Get, $"/oauth2/login?login_handle={handle}");
        request.Headers.TryAddWithoutValidation("Accept-Language", "zh-CN");
        using var page = await client.SendAsync(request, Ct);
        var body = await page.Content.ReadAsStringAsync(Ct);

        Assert.Contains("<h2 id=\"sms-heading\">使用短信验证码登录</h2>", body, StringComparison.Ordinal);
        Assert.Contains("<label for=\"phone\">手机号</label>", body, StringComparison.Ordinal);
        Assert.Contains("<label for=\"otp\">验证码</label>", body, StringComparison.Ordinal);
        Assert.Contains(SendButton + "发送验证码</button>", body, StringComparison.Ordinal);
        Assert.Contains(SmsSubmitButton + "验证码登录</button>", body, StringComparison.Ordinal);
        Assert.Contains(PhoneInput(string.Empty), body, StringComparison.Ordinal);
        Assert.Contains(OtpInput, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task APasswordFailurePage_RendersTheSmsRegion_WhileTheGateIsOpen()
    {
        using var host = _fixture.CreateSmsHost(new FakeSmsSender());
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.ManualApproval);
        var session = await BeginAsync(host.Services, client, app);

        using var response = await client.SendAsync(
            OAuthLoginTestSupport.CreateLoginPost(
                fields:
                [
                    new("login_handle", session.Handle),
                    new("username", "sms-page-unknown-" + Guid.NewGuid().ToString("N")[..8]),
                    new("password", "not-the-password"),
                    new(LoginAntiforgeryDefaults.TokenFieldName, session.Token),
                    new("action", "login"),
                ],
                cookieHeader: CookieHeader(session)),
            Ct);
        var body = await response.Content.ReadAsStringAsync(Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Sign-in failed. Check your username and password", body, StringComparison.Ordinal);
        Assert.Contains(PhoneInput(string.Empty), body, StringComparison.Ordinal);
        Assert.Contains(SmsSubmitButton, body, StringComparison.Ordinal);
    }

    // ---- IN-19, IN-17, IN-18: local answers ----

    [Theory]
    [InlineData(SmsLoginMode.Disabled, ProfileKey)]
    [InlineData(SmsLoginMode.ManualApproval, null)]
    [InlineData(SmsLoginMode.AutoProvision, " ")]
    public async Task AClosedGate_MakesSmsLoginTheLocal400_WithNothingReadOrWritten(SmsLoginMode mode, string? profileKey)
    {
        var sender = new FakeSmsSender();
        using var metrics = new SmsCodeMetricsCollector("login-sms");
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, mode, profileKey);
        var session = await BeginAsync(host.Services, client, app);
        var phone = NewPhone();
        await SeedIdentityAsync(host.Services, E164(phone), admission: (app.Id, SmsAccessApprovalSource.Admin, true));
        await SeedOtpAsync(host.Services, app.Id, E164(phone), _ => { });

        using var response = await client.SendAsync(Login(session, phone, WrongOtp), Ct);

        await AssertLocalRejectionAsync(response);
        await AssertUntouchedAsync(host.Services, app, session, phone, expectedAttempts: 0);
        Assert.Equal(["local_rejected"], metrics.Outcomes);
    }

    [Fact]
    public async Task ShapeFailures_AreLocal400s_AndAnInvalidPhoneIsTheFixedPageWithoutAnOtpRead()
    {
        var sender = new FakeSmsSender();
        using var metrics = new SmsCodeMetricsCollector("login-sms");
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.ManualApproval);
        var session = await BeginAsync(host.Services, client, app);
        var phone = NewPhone();
        await SeedIdentityAsync(host.Services, E164(phone), admission: (app.Id, SmsAccessApprovalSource.Admin, true));
        await SeedOtpAsync(host.Services, app.Id, E164(phone), _ => { });

        IReadOnlyList<KeyValuePair<string, string>> Without(string name) =>
            [.. SmsLoginFields(session, phone, WrongOtp).Where(field => field.Key != name)];

        var localRequests = new[]
        {
            Post(session, Without("phone")),
            Post(session, SmsLoginFields(session, new string(' ', 22) + phone, WrongOtp)),
            Post(session, Without("otp")),
            Post(session, SmsLoginFields(session, phone, new string('1', IdentityConstants.MaxSubmittedOtpLength + 1))),
            // The antiforgery check still precedes everything SMS-specific.
            Post(session, SmsLoginFields(session, phone, WrongOtp, token: OAuthLoginTestSupport.TamperLastCharacter(session.Token))),
        };
        foreach (var request in localRequests)
        {
            using (request)
            using (var response = await client.SendAsync(request, Ct))
            {
                await AssertLocalRejectionAsync(response);
            }
        }

        // An empty or unnormalizable phone: the fixed invalid-phone page with an empty phone input,
        // decided before the code is looked at — even a missing code does not change it.
        var invalidBodies = new List<string>();
        foreach (var fields in new IReadOnlyList<KeyValuePair<string, string>>[]
                 {
                     SmsLoginFields(session, "", WrongOtp),
                     SmsLoginFields(session, "12345", WrongOtp),
                     [.. SmsLoginFields(session, "abc", WrongOtp).Where(field => field.Key != "otp")],
                 })
        {
            using var response = await client.SendAsync(Post(session, fields), Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await response.Content.ReadAsStringAsync(Ct);
            Assert.Contains(EnglishInvalidPhoneNotice, body, StringComparison.Ordinal);
            Assert.Contains(PhoneInput(string.Empty), body, StringComparison.Ordinal);
            invalidBodies.Add(body);
        }

        Assert.Single(invalidBodies.Distinct());
        await AssertUntouchedAsync(host.Services, app, session, phone, expectedAttempts: 0);
        Assert.Equal(Enumerable.Repeat("local_rejected", localRequests.Length + 3), metrics.Outcomes);

        // Exactly 16 code units is an admitted code: a wrong one is the generic failure.
        using var boundary = await client.SendAsync(
            Post(session, SmsLoginFields(session, phone, new string('1', IdentityConstants.MaxSubmittedOtpLength))), Ct);
        Assert.Equal(HttpStatusCode.OK, boundary.StatusCode);
        Assert.Contains(EnglishSmsFailureNotice, await boundary.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
    }

    [Fact]
    public async Task EachActionIgnoresTheOtherFormsFields()
    {
        using var host = _fixture.CreateSmsHost(new FakeSmsSender());
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.ManualApproval);
        var session = await BeginAsync(host.Services, client, app);
        var phone = NewPhone();
        var overLong = new string('9', 200);

        // Password login with any phone and code: the generic credential failure, not a 400.
        using (var login = await client.SendAsync(Post(session,
                   [
                       new("login_handle", session.Handle), new("username", "sms-ignore-" + Guid.NewGuid().ToString("N")[..8]),
                       new("password", "wrong"), new(LoginAntiforgeryDefaults.TokenFieldName, session.Token),
                       new("action", "login"), new("phone", overLong), new("otp", overLong),
                   ]), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            Assert.Contains("Check your username and password", await login.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
        }

        // SMS login with over-long username and password: they are never read.
        using (var sms = await client.SendAsync(Post(session,
                   [.. SmsLoginFields(session, phone, WrongOtp), new("username", overLong), new("password", overLong)]), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, sms.StatusCode);
            Assert.Contains(EnglishSmsFailureNotice, await sms.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
        }

        // Cancel with a phone and code: the access_denied exit.
        using var cancel = await client.SendAsync(Post(session,
            [
                new("login_handle", session.Handle), new(LoginAntiforgeryDefaults.TokenFieldName, session.Token),
                new("action", "cancel"), new("phone", overLong), new("otp", overLong),
            ]), Ct);
        Assert.Equal(HttpStatusCode.Found, cancel.StatusCode);
        Assert.Contains("error=access_denied", cancel.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    // ---- EV-37 / SC-22: one generic failure ----

    [Fact]
    public async Task EveryFailureCase_AnswersTheSameBytes_AndOnlyTheAuditCarriesTheCase()
    {
        var sender = new FakeSmsSender();
        using var metrics = new SmsCodeMetricsCollector("login-sms");
        using var host = _fixture.CreateSmsHost(sender);
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.ManualApproval);
        var phone = NewPhone();
        var typed = phone[..3] + " " + phone[3..7] + "-" + phone[7..];
        var e164 = E164(phone);
        var bypassOptions = CreateSmsOptions();
        bypassOptions.BypassCode = "246810";
        bypassOptions.BypassPhones = [phone];
        using var bypassHost = _fixture.CreateSmsHost(sender, services => services.Replace(ServiceDescriptor.Singleton(bypassOptions)));
        using var auditFailureHost = _fixture.CreateSmsHost(sender, services =>
            services.Replace(ServiceDescriptor.Scoped<IAuditService, ThrowingSmsAuditService>()));
        using var client = host.CreateBrowserClient();
        var session = await BeginAsync(host.Services, client, app);

        var cases = new FailureCase[]
        {
            new("not_registered", "not_registered", () => Task.CompletedTask, AccountResolved: false),
            new("not_admitted", "not_admitted", () => SeedIdentityAsync(host.Services, e164)),
            new("admission_inactive", "admission_inactive",
                () => SeedIdentityAsync(host.Services, e164, admission: (app.Id, SmsAccessApprovalSource.Admin, false))),
            new("not_admin_approved", "not_admin_approved",
                () => SeedIdentityAsync(host.Services, e164, admission: (app.Id, SmsAccessApprovalSource.AutoProvision, true))),
            new("account_disabled", "account_disabled",
                () => SeedIdentityAsync(host.Services, e164, accountActive: false, admission: (app.Id, SmsAccessApprovalSource.Admin, true))),
            new("no_current_otp", "otp_rejected", Admitted),
            new("wrong_code", "otp_rejected", async () =>
            {
                await Admitted();
                await SeedOtpAsync(host.Services, app.Id, e164, _ => { });
            }, ExpectedAttempts: 1),
            new("expired_code", "otp_rejected", async () =>
            {
                await Admitted();
                await SeedOtpAsync(host.Services, app.Id, e164, otp => otp.ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1));
            }, ExpectedAttempts: 0),
            new("locked_code", "otp_rejected", async () =>
            {
                await Admitted();
                await SeedOtpAsync(host.Services, app.Id, e164, otp => otp.LockoutUntil = DateTimeOffset.UtcNow.AddMinutes(5));
            }, ExpectedAttempts: 0),
            // IN-18: the configured bypass never applies on the browser path.
            new("bypass_code", "otp_rejected", Admitted, Otp: "246810", Client: bypassHost.CreateBrowserClient()),
            // The failure unit cannot commit: the answer is unchanged and no row survives.
            new("unit_not_committed", null, async () =>
            {
                await Admitted();
                await SeedOtpAsync(host.Services, app.Id, e164, _ => { });
            }, ExpectedAttempts: 0, Client: auditFailureHost.CreateBrowserClient()),
        };

        (HttpStatusCode Status, IReadOnlyList<KeyValuePair<string, string>> Headers, string Body)? reference = null;
        foreach (var testCase in cases)
        {
            await ResetPhoneAsync(host.Services, e164);
            await testCase.Arrange();
            var identityRows = await PhoneIdentityRowCountAsync(host.Services, e164);
            var historiesBefore = (await SmsHistoriesAsync(host.Services, app.AppId)).Count;
            var outcomesBefore = metrics.Outcomes.Count;

            using var response = await (testCase.Client ?? client).SendAsync(
                Post(session, SmsLoginFields(session, typed, testCase.Otp)), Ct);
            var answer = await ReadAnswerAsync(response);

            Assert.Equal(HttpStatusCode.OK, answer.Status);
            AssertRenderedFormHeaders(response);
            Assert.Contains(EnglishSmsFailureNotice, answer.Body, StringComparison.Ordinal);
            OAuthLoginTestSupport.AssertFormNoticePlacement(answer.Body);
            Assert.Contains(PhoneInput(e164), answer.Body, StringComparison.Ordinal);
            Assert.Contains(OtpInput, answer.Body, StringComparison.Ordinal);
            Assert.DoesNotContain(typed, answer.Body, StringComparison.Ordinal);
            Assert.DoesNotContain(testCase.Otp, answer.Body, StringComparison.Ordinal);
            reference ??= answer;
            Assert.True(reference.Value.Headers.SequenceEqual(answer.Headers), $"Headers differ for {testCase.Name}.");
            Assert.True(reference.Value.Body == answer.Body, $"Body differs for {testCase.Name}.");

            // Side effects: the OTP counter only for an eligible phone with a current code, never
            // the Password counter, never provisioning, never the continuation.
            var otp = await OtpAsync(host.Services, app.Id, e164);
            Assert.True((testCase.ExpectedAttempts ?? 0) == (otp?.Attempts ?? 0), $"OTP attempts differ for {testCase.Name}.");
            Assert.Equal(identityRows, await PhoneIdentityRowCountAsync(host.Services, e164));
            Assert.Null((await ContinuationAsync(host.Services, session.ContinuationId)).ConsumedAt);
            var histories = await SmsHistoriesAsync(host.Services, app.AppId);
            if (testCase.Reason is null)
            {
                Assert.Equal(historiesBefore, histories.Count);
            }
            else
            {
                Assert.Equal(historiesBefore + 1, histories.Count);
                var row = histories[^1];
                Assert.Equal(("login_failure", "oidc_sms_login", testCase.Reason), (row.EventType, row.AuthMethod, row.FailureReason));
                Assert.Equal(e164[..3] + "****" + e164[^4..], row.Username);
                Assert.True(testCase.AccountResolved == row.AccountId is not null, $"Account id differs for {testCase.Name}.");
                Assert.Equal(FixedCorrelationId, row.CorrelationId);
            }

            Assert.Equal("failure", metrics.Outcomes.Skip(outcomesBefore).Single());
        }

        Assert.Empty(await QueryDbAsync(host.Services, db => db.LoginAttempts.AsNoTracking().ToListAsync(Ct)));
        Assert.Equal(0, sender.CallCount);
        // Outcomes carry exactly the endpoint and outcome labels, durations the endpoint only.
        Assert.Equal(metrics.Outcomes.Count, metrics.Durations.Count);
        Assert.All(metrics.LabelSets, labels => Assert.Contains(labels, new[] { "endpoint", "endpoint,outcome" }));

        // The page language is the only other input of the bytes.
        using var chinese = await client.SendAsync(
            Post(session, SmsLoginFields(session, typed, WrongOtp), acceptLanguage: "zh-CN"), Ct);
        var chineseBody = await chinese.Content.ReadAsStringAsync(Ct);
        Assert.Contains(ChineseSmsFailureNotice, chineseBody, StringComparison.Ordinal);
        Assert.Contains(PhoneInput(e164), chineseBody, StringComparison.Ordinal);

        // The continuation stays usable for a Password login (SC-22).
        var username = "sms-fallback-" + Guid.NewGuid().ToString("N")[..8];
        await OAuthLoginTestSupport.SeedUserAsync(host.Services, username, "Fallback-Password-1");
        using var password = await client.SendAsync(Post(session,
            [
                new("login_handle", session.Handle), new("username", username), new("password", "Fallback-Password-1"),
                new(LoginAntiforgeryDefaults.TokenFieldName, session.Token), new("action", "login"),
            ]), Ct);
        Assert.Equal(HttpStatusCode.Found, password.StatusCode);
        Assert.Contains("code=", password.Headers.Location!.ToString(), StringComparison.Ordinal);

        Task Admitted() => SeedIdentityAsync(host.Services, e164, admission: (app.Id, SmsAccessApprovalSource.Admin, true));
    }

    // ---- EV-36 / SC-21: send, log in, redeem ----

    [Fact]
    public async Task SendThenLogin_CreatesAnSmsSessionAndCode_WhoseRedemptionCarriesAmrSmsAndNoPhone()
    {
        var sender = new FakeSmsSender();
        using var metrics = new SmsCodeMetricsCollector("login-sms");
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.ManualApproval, clientSecret: ClientSecret);
        var session = await BeginAsync(host.Services, client, app, scope: "openid profile");
        var phone = NewPhone();
        var accountId = await SeedIdentityAsync(host.Services, E164(phone), admission: (app.Id, SmsAccessApprovalSource.Admin, true));

        using (var send = await client.SendAsync(SendPost(session, fields: SendFields(session, phone)), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, send.StatusCode);
        }

        var code = Assert.Single(sender.Calls).Code;
        using var login = await client.SendAsync(Post(session, SmsLoginFields(session, "+86 " + phone, code)), Ct);

        Assert.Equal(HttpStatusCode.Found, login.StatusCode);
        var location = login.Headers.Location!.ToString();
        Assert.StartsWith(RedirectUri + "?code=", location, StringComparison.Ordinal);
        Assert.Contains("&state=", location, StringComparison.Ordinal);
        Assert.DoesNotContain(phone, location, StringComparison.Ordinal);
        var identityCookie = OAuthLoginTestSupport.GetSetCookieHeader(login, IdentitySessionDefaults.CookieName);
        Assert.NotNull(identityCookie);

        var loginId = await QueryDbAsync(host.Services, db => db.UserLogins
            .Where(row => row.ProviderUserId == E164(phone)).Select(row => row.Id).SingleAsync(Ct));
        var identitySession = await QueryDbAsync(host.Services, db => db.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.SmsUserLoginId == loginId, Ct));
        Assert.Equal((accountId, "Sms"), (identitySession.AccountId, identitySession.AuthMethod));
        Assert.Equal(OtpStatus.Consumed, (await OtpAsync(host.Services, app.Id, E164(phone)))!.Status);
        Assert.NotNull((await ContinuationAsync(host.Services, session.ContinuationId)).ConsumedAt);
        var rows = await SmsHistoriesAsync(host.Services, app.AppId);
        Assert.Equal(["sms_code_sent", "login_success"], rows.Select(row => row.EventType));
        Assert.All(rows, row => Assert.Equal(E164(phone)[..3] + "****" + E164(phone)[^4..], row.Username));
        Assert.Equal(["success"], metrics.Outcomes);

        // Redemption (EV-20/EV-21): amr is ["sms"], no name without a sole Password credential,
        // and no phone in any token or UserInfo response.
        var (tokenJson, idToken) = await RedeemAsync(client, app, ExtractQuery(location, "code"));
        Assert.Equal(["sms"], idToken.Claims.Where(claim => claim.Type == "amr").Select(claim => claim.Value));
        Assert.DoesNotContain(idToken.Claims, claim => claim.Type == "name");
        Assert.Equal(accountId.ToString(), idToken.Subject);
        var userInfo = await UserInfoAsync(client, tokenJson);
        foreach (var form in new[] { phone, E164(phone), phone[3..] })
        {
            Assert.DoesNotContain(form, tokenJson, StringComparison.Ordinal);
            Assert.DoesNotContain(form, userInfo, StringComparison.Ordinal);
        }

        // After the commit the result stands: the same form again is EV-03, and a later send on
        // the consumed continuation is the local 400 too (SC-26).
        using (var replay = await client.SendAsync(Post(session, SmsLoginFields(session, phone, code)), Ct))
        {
            await AssertLocalRejectionAsync(replay);
        }

        using (var lateSend = await client.SendAsync(SendPost(session, fields: SendFields(session, phone)), Ct))
        {
            await AssertLocalRejectionAsync(lateSend);
        }

        Assert.Single(sender.Calls);
        // The replay fails on its handle before its action is read, so it records no login-sms outcome.
        Assert.Equal(["success"], metrics.Outcomes);
    }

    [Fact]
    public async Task TheNameClaim_ComesOnlyFromASolePasswordCredential()
    {
        var sender = new FakeSmsSender();
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.ManualApproval, clientSecret: ClientSecret);
        var session = await BeginAsync(host.Services, client, app, scope: "openid profile");
        var phone = NewPhone();
        var username = "sms-name-" + Guid.NewGuid().ToString("N")[..8];
        var accountId = await SeedIdentityAsync(host.Services, E164(phone), admission: (app.Id, SmsAccessApprovalSource.Admin, true));
        await WithDbAsync(host.Services, async db =>
        {
            db.PasswordCredentials.Add(new PasswordCredentialEntity
            {
                Id = Guid.NewGuid(),
                AccountId = accountId,
                Username = username,
                PasswordHash = "unused",
                CreatedAt = DateTimeOffset.UtcNow
            });
            await db.SaveChangesAsync(Ct);
        });

        using (var send = await client.SendAsync(SendPost(session, fields: SendFields(session, phone)), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, send.StatusCode);
        }

        using var login = await client.SendAsync(Post(session, SmsLoginFields(session, phone, Assert.Single(sender.Calls).Code)), Ct);
        Assert.Equal(HttpStatusCode.Found, login.StatusCode);
        var (_, idToken) = await RedeemAsync(client, app, ExtractQuery(login.Headers.Location!.ToString(), "code"));
        Assert.Equal(["sms"], idToken.Claims.Where(claim => claim.Type == "amr").Select(claim => claim.Value));
        Assert.Equal(username, idToken.Claims.Single(claim => claim.Type == "name").Value);
    }

    // ---- SC-23: AutoProvision provisions only inside the successful login ----

    [Fact]
    public async Task AutoProvision_CreatesTheAccountIdentityAndAdmission_OnlyInTheSuccessfulLogin()
    {
        var sender = new FakeSmsSender();
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(host.Services, client, app);
        var phone = NewPhone();

        using (var send = await client.SendAsync(SendPost(session, fields: SendFields(session, phone)), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, send.StatusCode);
        }

        Assert.Equal(0, await PhoneIdentityRowCountAsync(host.Services, E164(phone)));
        using (var wrong = await client.SendAsync(Post(session, SmsLoginFields(session, phone, WrongOtp)), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, wrong.StatusCode);
        }

        Assert.Equal(0, await PhoneIdentityRowCountAsync(host.Services, E164(phone)));
        Assert.Equal(1, (await OtpAsync(host.Services, app.Id, E164(phone)))!.Attempts);

        using var login = await client.SendAsync(Post(session, SmsLoginFields(session, phone, Assert.Single(sender.Calls).Code)), Ct);
        Assert.Equal(HttpStatusCode.Found, login.StatusCode);
        var created = await QueryDbAsync(host.Services, async db =>
        {
            var identity = await db.UserLogins.AsNoTracking().SingleAsync(row => row.ProviderUserId == E164(phone), Ct);
            var access = await db.AppSmsAccesses.AsNoTracking().SingleAsync(row => row.UserLoginId == identity.Id, Ct);
            var sessionRow = await db.IdentitySessions.AsNoTracking().SingleAsync(row => row.SmsUserLoginId == identity.Id, Ct);
            var account = await db.Accounts.AsNoTracking().SingleAsync(row => row.Id == identity.AccountId, Ct);
            return (access.AppRegistrationId, access.ApprovalSource, access.IsActive, sessionRow.AccountId == account.Id, account.IsActive);
        });
        Assert.Equal((app.Id, SmsAccessApprovalSource.AutoProvision, true, true, true), created);
        var rows = await SmsHistoriesAsync(host.Services, app.AppId);
        Assert.Equal(["sms_code_sent", "login_failure", "login_success"], rows.Select(row => row.EventType));
        Assert.Equal("otp_rejected", rows[1].FailureReason);
    }

    [Fact]
    public async Task AGrantProvisionedPhone_IsReusedByTheBrowserLogin_WithOneAccountAndIdentity()
    {
        var sender = new FakeSmsSender();
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var other = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(host.Services, client, app);
        var phone = NewPhone();

        // The SMS token grant's own provisioning path, for another application.
        using (var scope = host.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var otherApp = await db.AppRegistrations.AsNoTracking().SingleAsync(row => row.Id == other.Id, Ct);
            await scope.ServiceProvider.GetRequiredService<ISmsAdmissionService>().ProvisionAsync(
                otherApp, E164(phone), SmsAccessApprovalSource.AutoProvision, null, Ct);
        }

        using (var send = await client.SendAsync(SendPost(session, fields: SendFields(session, phone)), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, send.StatusCode);
        }

        using var login = await client.SendAsync(Post(session, SmsLoginFields(session, phone, Assert.Single(sender.Calls).Code)), Ct);
        Assert.Equal(HttpStatusCode.Found, login.StatusCode);
        Assert.Equal(1, await QueryDbAsync(host.Services, db => db.UserLogins.CountAsync(row => row.ProviderUserId == E164(phone), Ct)));
        Assert.Equal(3, await PhoneIdentityRowCountAsync(host.Services, E164(phone)));
    }

    // ---- SC-21 derivations: policy drift after the OTP check consumes nothing ----

    [Theory]
    [InlineData("redirect_removed")]
    [InlineData("client_disabled")]
    [InlineData("scope_removed")]
    public async Task PolicyDriftAfterTheOtpCheck_ConsumesNeitherTheOtpNorTheContinuation(string drift)
    {
        var sender = new FakeSmsSender();
        using var metrics = new SmsCodeMetricsCollector("login-sms");
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(host.Services, client, app, scope: "openid profile");
        var phone = NewPhone();
        using (var send = await client.SendAsync(SendPost(session, fields: SendFields(session, phone)), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, send.StatusCode);
        }

        await WithDbAsync(host.Services, db => drift switch
        {
            "redirect_removed" => db.AppRedirectUris.Where(row => row.AppRegistrationId == app.Id).ExecuteDeleteAsync(Ct),
            "client_disabled" => db.AppRegistrations.Where(row => row.Id == app.Id)
                .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsActive, false), Ct),
            _ => db.AppRegistrations.Where(row => row.Id == app.Id)
                .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.AllowedScopes, "openid"), Ct),
        });

        using var login = await client.SendAsync(Post(session, SmsLoginFields(session, phone, Assert.Single(sender.Calls).Code)), Ct);

        if (drift == "scope_removed")
        {
            Assert.Equal(HttpStatusCode.Found, login.StatusCode);
            var location = login.Headers.Location!.ToString();
            Assert.StartsWith(RedirectUri + "?", location, StringComparison.Ordinal);
            Assert.Contains("error=invalid_scope", location, StringComparison.Ordinal);
            Assert.DoesNotContain("code=", location, StringComparison.Ordinal);
        }
        else
        {
            await AssertLocalRejectionAsync(login);
        }

        Assert.Null(OAuthLoginTestSupport.GetSetCookieHeader(login, IdentitySessionDefaults.CookieName));
        Assert.Equal(OtpStatus.Sent, (await OtpAsync(host.Services, app.Id, E164(phone)))!.Status);
        Assert.Equal(0, (await OtpAsync(host.Services, app.Id, E164(phone)))!.Attempts);
        Assert.Null((await ContinuationAsync(host.Services, session.ContinuationId)).ConsumedAt);
        Assert.Equal(0, await PhoneIdentityRowCountAsync(host.Services, E164(phone)));
        Assert.Equal(["sms_code_sent"], (await SmsHistoriesAsync(host.Services, app.AppId)).Select(row => row.EventType));
        Assert.Equal(["local_rejected"], metrics.Outcomes);
    }

    // ---- SC-26: races on one continuation ----

    [Fact]
    public async Task TwoConcurrentSmsLogins_WithTheSameCode_ProduceOneRedirectAndOneLocal400()
    {
        var sender = new FakeSmsSender();
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(host.Services, client, app);
        var phone = NewPhone();
        using (var send = await client.SendAsync(SendPost(session, fields: SendFields(session, phone)), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, send.StatusCode);
        }

        var code = Assert.Single(sender.Calls).Code;
        var responses = await Task.WhenAll(
            client.SendAsync(Post(session, SmsLoginFields(session, phone, code)), Ct),
            client.SendAsync(Post(session, SmsLoginFields(session, phone, code)), Ct));
        try
        {
            Assert.Single(responses, response => response.StatusCode == HttpStatusCode.Found);
            var loser = Assert.Single(responses, response => response.StatusCode != HttpStatusCode.Found);
            Assert.Equal(HttpStatusCode.BadRequest, loser.StatusCode);
            Assert.Null(OAuthLoginTestSupport.GetSetCookieHeader(loser, IdentitySessionDefaults.CookieName));
        }
        finally
        {
            foreach (var response in responses) response.Dispose();
        }

        var loginId = await QueryDbAsync(host.Services, db => db.UserLogins
            .Where(row => row.ProviderUserId == E164(phone)).Select(row => row.Id).SingleAsync(Ct));
        Assert.Equal(1, await QueryDbAsync(host.Services, db => db.IdentitySessions.CountAsync(row => row.SmsUserLoginId == loginId, Ct)));
        Assert.Equal(["sms_code_sent", "login_success"], (await SmsHistoriesAsync(host.Services, app.AppId)).Select(row => row.EventType));
    }

    [Fact]
    public async Task AnSmsLoginRacingAPasswordLogin_ConsumesTheContinuationOnce()
    {
        var sender = new FakeSmsSender();
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(host.Services, client, app);
        var phone = NewPhone();
        var username = "sms-race-" + Guid.NewGuid().ToString("N")[..8];
        var passwordAccount = await OAuthLoginTestSupport.SeedUserAsync(host.Services, username, "Race-Password-1");
        using (var send = await client.SendAsync(SendPost(session, fields: SendFields(session, phone)), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, send.StatusCode);
        }

        var responses = await Task.WhenAll(
            client.SendAsync(Post(session, SmsLoginFields(session, phone, Assert.Single(sender.Calls).Code)), Ct),
            client.SendAsync(Post(session,
                [
                    new("login_handle", session.Handle), new("username", username), new("password", "Race-Password-1"),
                    new(LoginAntiforgeryDefaults.TokenFieldName, session.Token), new("action", "login"),
                ]), Ct));
        try
        {
            Assert.Single(responses, response => response.StatusCode == HttpStatusCode.Found);
            Assert.Single(responses, response => response.StatusCode == HttpStatusCode.BadRequest);
        }
        finally
        {
            foreach (var response in responses) response.Dispose();
        }

        var sessions = await QueryDbAsync(host.Services, db => db.IdentitySessions.AsNoTracking()
            .Where(row => row.AccountId == passwordAccount
                || db.UserLogins.Any(login => login.Id == row.SmsUserLoginId && login.ProviderUserId == E164(phone)))
            .ToListAsync(Ct));
        Assert.Single(sessions);
        if (sessions[0].AuthMethod == "Password")
        {
            // The SMS loser rolled back its whole unit: no provisioning and no OTP consumption.
            Assert.Equal(0, await PhoneIdentityRowCountAsync(host.Services, E164(phone)));
            Assert.Equal(OtpStatus.Sent, (await OtpAsync(host.Services, app.Id, E164(phone)))!.Status);
        }
    }

    [Fact]
    public async Task ACodeReplacedBeforeTheConsumption_IsTheGenericFailure_WithTheRaceReason()
    {
        var sender = new FakeSmsSender();
        using var metrics = new SmsCodeMetricsCollector("login-sms");
        using var host = _fixture.CreateSmsHost(sender, services =>
            services.Replace(ServiceDescriptor.Scoped<IOtpService>(provider => new ReplacingOtpService(
                ActivatorUtilities.CreateInstance<DbOtpService>(provider),
                provider.GetRequiredService<IdentityDbContext>()))));
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(host.Services, client, app);
        var phone = NewPhone();
        using (var send = await client.SendAsync(SendPost(session, fields: SendFields(session, phone)), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, send.StatusCode);
        }

        using var login = await client.SendAsync(Post(session, SmsLoginFields(session, phone, Assert.Single(sender.Calls).Code)), Ct);

        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var body = await login.Content.ReadAsStringAsync(Ct);
        Assert.Contains(EnglishSmsFailureNotice, body, StringComparison.Ordinal);
        Assert.Contains(PhoneInput(E164(phone)), body, StringComparison.Ordinal);
        Assert.Null((await ContinuationAsync(host.Services, session.ContinuationId)).ConsumedAt);
        Assert.Equal(0, await PhoneIdentityRowCountAsync(host.Services, E164(phone)));
        Assert.Equal(OtpStatus.Sent, (await OtpAsync(host.Services, app.Id, E164(phone)))!.Status);
        var last = (await SmsHistoriesAsync(host.Services, app.AppId))[^1];
        Assert.Equal(("login_failure", "otp_race", (Guid?)null), (last.EventType, last.FailureReason, last.AccountId));
        Assert.Equal(["failure"], metrics.Outcomes);
    }

    [Fact]
    public async Task StructureFailuresBeforeTheAction_RecordNoSmsLoginMetric()
    {
        using var metrics = new SmsCodeMetricsCollector("login-sms");
        using var host = _fixture.CreateSmsHost(new FakeSmsSender());
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(host.Services, client, app);
        var fields = SmsLoginFields(session, NewPhone(), WrongOtp);

        foreach (var request in new[]
                 {
                     Post(session, [.. fields, new("otp", "twice")]),
                     Post(session, fields, handleOverride: OAuthLoginTestSupport.RandomHandle()),
                     Post(session, [.. fields.Where(field => field.Key != "action"), new("action", "SMS_LOGIN")]),
                 })
        {
            using (request)
            using (var response = await client.SendAsync(request, Ct))
            {
                await AssertLocalRejectionAsync(response);
            }
        }

        Assert.Empty(metrics.Outcomes);
        Assert.Empty(metrics.Durations);
    }

    // ---- Helpers ----

    private static HttpRequestMessage Login(SmsSession session, string phone, string otp) =>
        Post(session, SmsLoginFields(session, phone, otp));

    private static HttpRequestMessage Post(
        SmsSession session,
        IReadOnlyList<KeyValuePair<string, string>> fields,
        string? acceptLanguage = null,
        string? handleOverride = null)
    {
        var body = handleOverride is null
            ? fields
            : [.. fields.Select(field => field.Key == "login_handle" ? new KeyValuePair<string, string>("login_handle", handleOverride) : field)];
        return SendPost(session, fields: body, acceptLanguage: acceptLanguage, path: "/oauth2/login");
    }

    private static async Task<(string TokenJson, JwtSecurityToken IdToken)> RedeemAsync(HttpClient client, SmsApp app, string code)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = CodeVerifier
            })
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{app.AppId}:{ClientSecret}")));
        using var response = await client.SendAsync(request, Ct);
        var json = await response.Content.ReadAsStringAsync(Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(json);
        return (json, new JwtSecurityTokenHandler().ReadJwtToken(document.RootElement.GetProperty("id_token").GetString()));
    }

    private static async Task<string> UserInfoAsync(HttpClient client, string tokenJson)
    {
        using var document = JsonDocument.Parse(tokenJson);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/oauth2/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", document.RootElement.GetProperty("access_token").GetString());
        using var response = await client.SendAsync(request, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsStringAsync(Ct);
    }

    private static string ExtractQuery(string location, string name)
    {
        foreach (var pair in location[(location.IndexOf('?') + 1)..].Split('&'))
        {
            var parts = pair.Split('=', 2);
            if (parts[0] == name) return Uri.UnescapeDataString(parts[1]);
        }

        throw new Xunit.Sdk.XunitException($"No '{name}' in the redirect.");
    }

    private static Task<AuthorizationRequestEntity> ContinuationAsync(IServiceProvider services, Guid continuationId) =>
        QueryDbAsync(services, db => db.AuthorizationRequests.AsNoTracking().SingleAsync(row => row.Id == continuationId, Ct));

    private static int Occurrences(string text, string value)
    {
        var count = 0;
        for (var index = text.IndexOf(value, StringComparison.Ordinal); index >= 0;
             index = text.IndexOf(value, index + value.Length, StringComparison.Ordinal))
        {
            count++;
        }

        return count;
    }

    private static async Task AssertLocalRejectionAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(OAuthLoginTestSupport.EnglishLocalErrorPage, await response.Content.ReadAsStringAsync(Ct));
        OAuthLoginTestSupport.AssertLoginSecurityHeaders(response);
        Assert.False(response.Headers.Contains("Set-Cookie"));
    }

    private static void AssertRenderedFormHeaders(HttpResponseMessage response)
    {
        OAuthLoginTestSupport.AssertLoginSecurityHeaders(
            response,
            OAuthLoginTestSupport.ExpectedFormContentSecurityPolicy("https://bff.sms-send.test"));
        Assert.False(response.Headers.Contains("Set-Cookie"));
        Assert.Equal("Accept-Language", Assert.Single(response.Headers.Vary));
    }

    private static async Task AssertUntouchedAsync(
        IServiceProvider services, SmsApp app, SmsSession session, string phone, int expectedAttempts)
    {
        Assert.Null((await ContinuationAsync(services, session.ContinuationId)).ConsumedAt);
        var otp = await OtpAsync(services, app.Id, E164(phone));
        Assert.Equal((OtpStatus.Sent, expectedAttempts), (otp!.Status, otp.Attempts));
        Assert.Empty(await SmsHistoriesAsync(services, app.AppId));
    }

    private sealed record FailureCase(
        string Name,
        string? Reason,
        Func<Task> Arrange,
        bool AccountResolved = true,
        int? ExpectedAttempts = null,
        string Otp = WrongOtp,
        HttpClient? Client = null);

    /// <summary>Fails every browser SMS audit row; every other row is written as usual.</summary>
    private sealed class ThrowingSmsAuditService(ILoginHistoryRepository histories) : IAuditService
    {
        private readonly AuditService _inner = new(histories);

        public Task RecordLoginAsync(Guid? accountId, string username, string authMethod, string eventType,
            string? clientIp, string? userAgent, string? failureReason = null, string? appId = null,
            string? correlationId = null, CancellationToken cancellationToken = default) =>
            authMethod == OidcSmsCodeSendService.AuthMethod
                ? throw new InvalidOperationException("Simulated audit persistence failure.")
                : _inner.RecordLoginAsync(accountId, username, authMethod, eventType, clientIp, userAgent,
                    failureReason, appId, correlationId, cancellationToken);
    }

    /// <summary>
    /// A concurrent send replaces the OTP right after the read-only verification passed: the
    /// verified MAC is stale by the time the login's conditional consumption runs.
    /// </summary>
    private sealed class ReplacingOtpService(DbOtpService inner, IdentityDbContext context) : IOtpService
    {
        public Task<string> GenerateAndSendAsync(Guid appRegistrationId, string phoneE164, string profileKey,
            CancellationToken cancellationToken = default) =>
            inner.GenerateAndSendAsync(appRegistrationId, phoneE164, profileKey, cancellationToken);

        public Task<OtpSendOutcome> TrySendAsync(Guid appRegistrationId, string phoneE164, string profileKey,
            CancellationToken cancellationToken = default) =>
            inner.TrySendAsync(appRegistrationId, phoneE164, profileKey, cancellationToken);

        public async Task<OtpVerificationResult> VerifyAsync(Guid appRegistrationId, string phoneE164, string code,
            CancellationToken cancellationToken = default)
        {
            var result = await inner.VerifyAsync(appRegistrationId, phoneE164, code, cancellationToken);
            if (result.IsVerified)
            {
                await context.Otps
                    .Where(row => row.AppRegistrationId == appRegistrationId && row.Phone == phoneE164)
                    .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.CodeMac, new string('D', 64)), cancellationToken);
            }

            return result;
        }

        public Task InvalidateAsync(Guid appRegistrationId, string phoneE164, CancellationToken cancellationToken = default) =>
            inner.InvalidateAsync(appRegistrationId, phoneE164, cancellationToken);
    }
}
