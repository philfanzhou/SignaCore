using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services.Sms;
using Xunit;
using SmsSupport = SignaCore.Tests.Integration.OAuthLoginSmsCodeTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The browser SMS login across the two-instance base (#445): the code is sent through instance A
/// and the login completes on instance B over the shared continuation, OTP row, and key ring; two
/// submissions of one continuation on the two instances commit exactly once (<c>SC-26</c>).
/// </summary>
public sealed partial class OidcMultiInstanceAcceptanceTests
{
    [Fact]
    public async Task AnSmsCodeSentByInstanceA_CompletesTheLoginOnInstanceB()
    {
        var sender = new FakeSmsSender();
        var a = CreateInstance(configureTestServices: services => ConfigureSms(services, sender));
        var b = CreateInstance(configureTestServices: services => ConfigureSms(services, sender));
        using var aClient = a.CreateBrowserClient();
        using var bClient = b.CreateBrowserClient();
        var app = await SmsSupport.SeedSmsAppAsync(a.Services, SmsLoginMode.AutoProvision);
        var session = await SmsSupport.BeginAsync(a.Services, aClient, app);
        var phone = SmsSupport.NewPhone();

        using (var send = await aClient.SendAsync(
                   SmsSupport.SendPost(session, fields: SmsSupport.SendFields(session, phone)),
                   TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.OK, send.StatusCode);
        }

        using var login = await bClient.SendAsync(
            SmsLoginPost(session, phone, Assert.Single(sender.Calls).Code), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, login.StatusCode);
        Assert.Contains("code=", login.Headers.Location!.ToString(), StringComparison.Ordinal);
        using var scope = a.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var identity = await db.UserLogins.AsNoTracking()
            .SingleAsync(row => row.ProviderUserId == SmsSupport.E164(phone), TestContext.Current.CancellationToken);
        Assert.Equal("Sms", (await db.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.SmsUserLoginId == identity.Id, TestContext.Current.CancellationToken)).AuthMethod);
    }

    [Fact]
    public async Task TwoSmsSubmissionsOnTwoInstances_CommitExactlyOnce()
    {
        var sender = new FakeSmsSender();
        var a = CreateInstance(configureTestServices: services => ConfigureSms(services, sender));
        var b = CreateInstance(configureTestServices: services => ConfigureSms(services, sender));
        using var aClient = a.CreateBrowserClient();
        using var bClient = b.CreateBrowserClient();
        var app = await SmsSupport.SeedSmsAppAsync(a.Services, SmsLoginMode.AutoProvision);
        var session = await SmsSupport.BeginAsync(a.Services, aClient, app);
        var phone = SmsSupport.NewPhone();
        using (var send = await aClient.SendAsync(
                   SmsSupport.SendPost(session, fields: SmsSupport.SendFields(session, phone)),
                   TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.OK, send.StatusCode);
        }

        var code = Assert.Single(sender.Calls).Code;
        var responses = await Task.WhenAll(
            aClient.SendAsync(SmsLoginPost(session, phone, code), TestContext.Current.CancellationToken),
            bClient.SendAsync(SmsLoginPost(session, phone, code), TestContext.Current.CancellationToken));
        try
        {
            Assert.Single(responses, response => response.StatusCode == HttpStatusCode.Found);
            Assert.Single(responses, response => response.StatusCode == HttpStatusCode.BadRequest);
        }
        finally
        {
            foreach (var response in responses) response.Dispose();
        }

        using var scope = a.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var identity = await db.UserLogins.AsNoTracking()
            .SingleAsync(row => row.ProviderUserId == SmsSupport.E164(phone), TestContext.Current.CancellationToken);
        Assert.Equal(1, await db.IdentitySessions.CountAsync(
            row => row.SmsUserLoginId == identity.Id, TestContext.Current.CancellationToken));
    }

    private static void ConfigureSms(IServiceCollection services, FakeSmsSender sender)
    {
        services.Replace(ServiceDescriptor.Singleton(SmsSupport.CreateSmsOptions()));
        services.AddSingleton<ISmsSender>(sender);
    }

    private static HttpRequestMessage SmsLoginPost(SmsSupport.SmsSession session, string phone, string otp) =>
        SmsSupport.SendPost(session, fields: SmsSupport.SmsLoginFields(session, phone, otp), path: "/oauth2/login");
}
