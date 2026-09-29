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
using SignaCore.Domain.Services.Sms;
using SignaCore.Host.Security;
using Xunit;
using static SignaCore.Tests.Integration.OidcDatabaseTestSupport;
using static SignaCore.Tests.Integration.OAuthLoginSmsCodeTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The browser SMS login over two PostgreSQL replicas (#445): one replica renders the page and
/// sends the code, the other logs in, and the first redeems the code into <c>amr: ["sms"]</c>
/// (<c>SC-21</c>); an ineligible phone gets the same send bytes and the generic failure without
/// provisioning (<c>SC-22</c>); <c>AutoProvision</c> creates the identity only in the successful
/// login (<c>SC-23</c>); and two submissions of one continuation on the two replicas commit
/// exactly once (<c>SC-26</c>). Gated on <c>RUN_SIGNACORE_DATABASE_CONTRACTS</c>.
/// </summary>
public sealed class OidcSmsLoginEndToEndDatabaseContractTests
{
    private const string SmsClientSecret = "sms-e2e-client-secret";
    private const string LoginPath = "/oauth2/login";

    [Fact]
    public async Task SendOnOneReplica_LoginOnTheOther_RedeemsIntoAmrSmsWithoutAPhone()
    {
        await using var harness = await Harness.CreateAsync();
        var senderA = new FakeSmsSender();
        var senderB = new FakeSmsSender();
        using var a = harness.CreateHost(services => ConfigureSms(services, senderA));
        using var b = harness.CreateHost(services => ConfigureSms(services, senderB));
        var app = await SeedSmsAppAsync(a.Factory.Services, SmsLoginMode.ManualApproval, clientSecret: SmsClientSecret);
        var session = await BeginAsync(a.Factory.Services, a.Client, app, scope: "openid profile");
        var phone = NewPhone();
        var accountId = await SeedIdentityAsync(a.Factory.Services, E164(phone), admission: (app.Id, SmsAccessApprovalSource.Admin, true));

        using (var send = await a.Client.SendAsync(SendPost(session, fields: SendFields(session, phone)), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, send.StatusCode);
            Assert.Contains(PhoneInput(E164(phone)), await send.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
        }

        var code = Assert.Single(senderA.Calls).Code;
        using var login = await b.Client.SendAsync(SmsLoginPost(session, phone, code), Ct);

        Assert.Equal(HttpStatusCode.Found, login.StatusCode);
        Assert.NotNull(OAuthLoginTestSupport.GetSetCookieHeader(login, IdentitySessionDefaults.CookieName));
        await using (var db = harness.Context())
        {
            var loginId = await db.UserLogins.Where(row => row.ProviderUserId == E164(phone)).Select(row => row.Id).SingleAsync(Ct);
            var identitySession = await db.IdentitySessions.AsNoTracking().SingleAsync(row => row.SmsUserLoginId == loginId, Ct);
            Assert.Equal((accountId, "Sms"), (identitySession.AccountId, identitySession.AuthMethod));
            Assert.Equal(OtpStatus.Consumed, (await db.Otps.AsNoTracking().SingleAsync(row => row.AppRegistrationId == app.Id, Ct)).Status);
            Assert.NotNull((await db.AuthorizationRequests.AsNoTracking().SingleAsync(row => row.Id == session.ContinuationId, Ct)).ConsumedAt);
            var rows = await db.LoginHistories.AsNoTracking().Where(row => row.AppId == app.AppId).OrderBy(row => row.CreatedAt).ToListAsync(Ct);
            Assert.Equal(["sms_code_sent", "login_success"], rows.Select(row => row.EventType));
            Assert.All(rows, row => Assert.Equal(E164(phone)[..3] + "****" + E164(phone)[^4..], row.Username));
        }

        var location = login.Headers.Location!.ToString();
        var tokenJson = await RedeemAsync(a.Client, app, Query(location, "code"));
        using var document = JsonDocument.Parse(tokenJson);
        var idToken = new JwtSecurityTokenHandler().ReadJwtToken(document.RootElement.GetProperty("id_token").GetString());
        Assert.Equal(["sms"], idToken.Claims.Where(claim => claim.Type == "amr").Select(claim => claim.Value));
        Assert.DoesNotContain(idToken.Claims, claim => claim.Type == "name");
        Assert.DoesNotContain(phone, tokenJson, StringComparison.Ordinal);

        // No raw phone or code reached either replica's logs.
        foreach (var logs in new[] { a.Probe.Logs, b.Probe.Logs })
        {
            AssertNoCanary(logs, phone, E164(phone), code);
        }
    }

    [Fact]
    public async Task AnIneligiblePhone_GetsTheUniformSendAndTheGenericFailure_AcrossReplicas()
    {
        await using var harness = await Harness.CreateAsync();
        var sender = new FakeSmsSender();
        using var a = harness.CreateHost(services => ConfigureSms(services, sender));
        using var b = harness.CreateHost(services => ConfigureSms(services, sender));
        var app = await SeedSmsAppAsync(a.Factory.Services, SmsLoginMode.ManualApproval);
        var session = await BeginAsync(a.Factory.Services, a.Client, app);
        var admitted = NewPhone();
        var unregistered = NewPhone();
        await SeedIdentityAsync(a.Factory.Services, E164(admitted), admission: (app.Id, SmsAccessApprovalSource.Admin, true));

        string sentBody;
        using (var sent = await a.Client.SendAsync(SendPost(session, fields: SendFields(session, admitted)), Ct))
        {
            sentBody = (await sent.Content.ReadAsStringAsync(Ct)).Replace(E164(admitted), "{phone}", StringComparison.Ordinal);
        }

        using (var suppressed = await b.Client.SendAsync(SendPost(session, fields: SendFields(session, unregistered)), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, suppressed.StatusCode);
            Assert.Equal(sentBody, (await suppressed.Content.ReadAsStringAsync(Ct)).Replace(E164(unregistered), "{phone}", StringComparison.Ordinal));
        }

        using var wrong = await a.Client.SendAsync(SmsLoginPost(session, admitted, "000000"), Ct);
        using var ineligible = await b.Client.SendAsync(SmsLoginPost(session, unregistered, "000000"), Ct);
        var wrongBody = (await wrong.Content.ReadAsStringAsync(Ct)).Replace(E164(admitted), "{phone}", StringComparison.Ordinal);
        var ineligibleBody = (await ineligible.Content.ReadAsStringAsync(Ct)).Replace(E164(unregistered), "{phone}", StringComparison.Ordinal);
        Assert.Equal((HttpStatusCode.OK, HttpStatusCode.OK), (wrong.StatusCode, ineligible.StatusCode));
        Assert.Contains(EnglishSmsFailureNotice, wrongBody, StringComparison.Ordinal);
        Assert.Equal(wrongBody, ineligibleBody);

        await using var db = harness.Context();
        Assert.Equal(1, (await db.Otps.AsNoTracking().SingleAsync(row => row.Phone == E164(admitted), Ct)).Attempts);
        Assert.False(await db.UserLogins.AnyAsync(row => row.ProviderUserId == E164(unregistered), Ct));
        Assert.Null((await db.AuthorizationRequests.AsNoTracking().SingleAsync(row => row.Id == session.ContinuationId, Ct)).ConsumedAt);
        var failures = await db.LoginHistories.AsNoTracking()
            .Where(row => row.AppId == app.AppId && row.EventType == "login_failure").Select(row => row.FailureReason).ToListAsync(Ct);
        Assert.Equal(["not_registered", "otp_rejected"], failures.Order());
        Assert.Empty(await db.LoginAttempts.AsNoTracking().ToListAsync(Ct));
    }

    [Fact]
    public async Task AutoProvision_CreatesTheIdentityOnlyInTheSuccessfulLogin_AcrossReplicas()
    {
        await using var harness = await Harness.CreateAsync();
        var sender = new FakeSmsSender();
        using var a = harness.CreateHost(services => ConfigureSms(services, sender));
        using var b = harness.CreateHost(services => ConfigureSms(services, sender));
        var app = await SeedSmsAppAsync(a.Factory.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(a.Factory.Services, a.Client, app);
        var phone = NewPhone();

        using (var send = await a.Client.SendAsync(SendPost(session, fields: SendFields(session, phone)), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, send.StatusCode);
        }

        Assert.Equal(0, await PhoneIdentityRowCountAsync(a.Factory.Services, E164(phone)));
        using var login = await b.Client.SendAsync(SmsLoginPost(session, phone, Assert.Single(sender.Calls).Code), Ct);
        Assert.Equal(HttpStatusCode.Found, login.StatusCode);

        await using var db = harness.Context();
        var identity = await db.UserLogins.AsNoTracking().SingleAsync(row => row.ProviderUserId == E164(phone), Ct);
        var access = await db.AppSmsAccesses.AsNoTracking().SingleAsync(row => row.UserLoginId == identity.Id, Ct);
        Assert.Equal((app.Id, SmsAccessApprovalSource.AutoProvision, true), (access.AppRegistrationId, access.ApprovalSource, access.IsActive));
        Assert.Equal(identity.AccountId,
            (await db.IdentitySessions.AsNoTracking().SingleAsync(row => row.SmsUserLoginId == identity.Id, Ct)).AccountId);
    }

    [Fact]
    public async Task TwoSubmissionsOnTwoReplicas_CommitExactlyOnce()
    {
        await using var harness = await Harness.CreateAsync();
        var sender = new FakeSmsSender();
        using var a = harness.CreateHost(services => ConfigureSms(services, sender));
        using var b = harness.CreateHost(services => ConfigureSms(services, sender));
        var app = await SeedSmsAppAsync(a.Factory.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(a.Factory.Services, a.Client, app);
        var phone = NewPhone();
        using (var send = await a.Client.SendAsync(SendPost(session, fields: SendFields(session, phone)), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, send.StatusCode);
        }

        var code = Assert.Single(sender.Calls).Code;
        var responses = await Task.WhenAll(
            a.Client.SendAsync(SmsLoginPost(session, phone, code), Ct),
            b.Client.SendAsync(SmsLoginPost(session, phone, code), Ct));
        try
        {
            Assert.Single(responses, response => response.StatusCode == HttpStatusCode.Found);
            Assert.Single(responses, response => response.StatusCode == HttpStatusCode.BadRequest);
        }
        finally
        {
            foreach (var response in responses) response.Dispose();
        }

        await using var db = harness.Context();
        var identity = await db.UserLogins.AsNoTracking().SingleAsync(row => row.ProviderUserId == E164(phone), Ct);
        Assert.Equal(1, await db.IdentitySessions.CountAsync(row => row.SmsUserLoginId == identity.Id, Ct));
        Assert.Equal(1, await db.AppSmsAccesses.CountAsync(row => row.UserLoginId == identity.Id, Ct));
        Assert.Equal(1, await db.LoginHistories.CountAsync(row => row.AppId == app.AppId && row.EventType == "login_success", Ct));
    }

    private static void ConfigureSms(IServiceCollection services, FakeSmsSender sender)
    {
        services.Replace(ServiceDescriptor.Singleton(CreateSmsOptions()));
        services.AddSingleton<ISmsSender>(sender);
    }

    private static HttpRequestMessage SmsLoginPost(SmsSession session, string phone, string otp) =>
        SendPost(session, fields: SmsLoginFields(session, phone, otp), path: LoginPath);

    private static async Task<string> RedeemAsync(HttpClient client, SmsApp app, string code)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = OAuthLoginSmsCodeTestSupport.RedirectUri,
                ["code_verifier"] = CodeVerifier
            })
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{app.AppId}:{SmsClientSecret}")));
        using var response = await client.SendAsync(request, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsStringAsync(Ct);
    }

    private static string Query(string location, string name) =>
        Uri.UnescapeDataString(location[(location.IndexOf('?') + 1)..].Split('&')
            .Select(pair => pair.Split('=', 2))
            .Single(parts => parts[0] == name)[1]);
}
