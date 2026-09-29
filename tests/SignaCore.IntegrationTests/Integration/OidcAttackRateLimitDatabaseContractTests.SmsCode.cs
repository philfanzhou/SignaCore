using System.Net;
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
/// The browser SMS send route on two PostgreSQL replicas (#444, <c>SC-25</c>): the
/// <c>oidc-sms-code</c> window and the per-continuation count are one shared budget, the window is
/// partitioned by the source network only, and an undecided store refuses with the fixed 503.
/// </summary>
public sealed partial class OidcAttackRateLimitDatabaseContractTests
{
    private const int SmsCodeBudget = IdentityConstants.OidcSmsCodeRateLimitPerMinute;

    [Fact]
    public async Task SmsCodeWindow_IsOneSourceNetworkBudgetAcrossHosts_WhateverClientCarrierItNames()
    {
        await using var harness = await Harness.CreateAsync();
        var senderA = new FakeSmsSender();
        var senderB = new FakeSmsSender();
        using var a = harness.CreateHost(services => ConfigureSms(services, senderA));
        using var b = harness.CreateHost(services => ConfigureSms(services, senderB));
        var app = await SeedSmsAppAsync(a.Factory.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(a.Factory.Services, a.Client, app);
        await harness.ExecuteAsync("DELETE FROM oidc_rate_limit_buckets");
        var digest = a.Digest("ip:" + RemoteIp);

        // Alternating replicas; a third of the requests name the registered client in the query
        // and a third in a Basic header. All of them count in the one source-network window.
        for (var i = 0; i < SmsCodeBudget; i++)
        {
            using var request = CarrierRequest(session, "invalid", i % 3);
            using var admitted = await (i % 2 == 0 ? a : b).Client.SendAsync(request, Ct);
            Assert.Equal(i % 3 == 1 ? HttpStatusCode.BadRequest : HttpStatusCode.OK, admitted.StatusCode);
            if (i == 0)
                await harness.ExecuteAsync("UPDATE oidc_rate_limit_buckets SET window_expires_at = now() + interval '1 hour'");
        }

        var handled = a.Probe.HandlerInvocations + b.Probe.HandlerInvocations;
        var phone = NewPhone();
        for (var carrier = 0; carrier < 3; carrier++)
        {
            using var request = CarrierRequest(session, phone, carrier);
            using var rejected = await (carrier % 2 == 0 ? b : a).Client.SendAsync(request, Ct);
            await AssertFixedRejectionAsync(rejected, HttpStatusCode.TooManyRequests);
        }

        Assert.Equal(handled, a.Probe.HandlerInvocations + b.Probe.HandlerInvocations);
        Assert.Equal(SmsCodeBudget, await harness.PermitCountAsync(OidcRateLimitPolicies.SmsCode, digest));
        // One bucket only: no registered-client partition was ever created for this policy.
        Assert.Equal(1, await harness.CountAsync());
        Assert.Null(await harness.PermitCountAsync(OidcRateLimitPolicies.SmsCode, a.Digest("client:" + ClientId)));
        Assert.Equal(0, senderA.CallCount + senderB.CallCount);
        Assert.Equal(0, await CountAsync(a.Factory.Services, session.ContinuationId));
    }

    [Fact]
    public async Task SmsCodeContinuationBudget_IsSharedAcrossHosts()
    {
        await using var harness = await Harness.CreateAsync();
        var senderA = new FakeSmsSender();
        var senderB = new FakeSmsSender();
        using var a = harness.CreateHost(services => ConfigureSms(services, senderA));
        using var b = harness.CreateHost(services => ConfigureSms(services, senderB));
        var app = await SeedSmsAppAsync(a.Factory.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(a.Factory.Services, a.Client, app);
        var phones = Enumerable.Range(0, IdentityConstants.MaxSmsCodeSendsPerContinuation + 1).Select(_ => NewPhone()).ToList();

        var bodies = new List<string>();
        for (var i = 0; i < phones.Count; i++)
        {
            using var request = SendPost(session, fields: SendFields(session, phones[i]));
            using var response = await (i % 2 == 0 ? a : b).Client.SendAsync(request, Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            bodies.Add(await response.Content.ReadAsStringAsync(Ct));
        }

        // Every body differs from the others only by the normalized phone it re-renders (AC-17).
        Assert.Single(bodies.Select((body, index) => body.Replace(E164(phones[index]), "{phone}", StringComparison.Ordinal)).Distinct());
        Assert.Equal(IdentityConstants.MaxSmsCodeSendsPerContinuation, senderA.CallCount + senderB.CallCount);
        Assert.DoesNotContain(senderA.Calls.Concat(senderB.Calls), call => call.PhoneE164 == E164(phones[^1]));
        Assert.Equal(IdentityConstants.MaxSmsCodeSendsPerContinuation, await CountAsync(b.Factory.Services, session.ContinuationId));
        var last = (await SmsHistoriesAsync(b.Factory.Services, app.AppId))[^1];
        Assert.Equal(("sms_code_suppressed", "continuation_budget"), (last.EventType, last.FailureReason));
        await using var db = harness.Context();
        Assert.Null((await db.AuthorizationRequests.AsNoTracking().SingleAsync(row => row.Id == session.ContinuationId, Ct)).ConsumedAt);
    }

    [Fact]
    public async Task SmsCodeWindow_UndecidedStore_IsTheFixed503_WithNoCountOrSend()
    {
        await using var harness = await Harness.CreateAsync();
        var sender = new FakeSmsSender();
        using var a = harness.CreateHost(services => ConfigureSms(services, sender));
        var app = await SeedSmsAppAsync(a.Factory.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(a.Factory.Services, a.Client, app);
        using (var first = await a.Client.SendAsync(SendPost(session, fields: SendFields(session, "invalid")), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        var digest = a.Digest("ip:" + RemoteIp);
        var handled = a.Probe.HandlerInvocations;
        await using (await harness.LockRowAsync(OidcRateLimitPolicies.SmsCode, digest))
        {
            using var undecided = await a.Client.SendAsync(SendPost(session, fields: SendFields(session, NewPhone())), Ct);
            await AssertFixedRejectionAsync(undecided, HttpStatusCode.ServiceUnavailable);
        }

        Assert.Equal(handled, a.Probe.HandlerInvocations);
        Assert.Equal(1, await harness.PermitCountAsync(OidcRateLimitPolicies.SmsCode, digest));
        Assert.Equal(0, sender.CallCount);
        Assert.Equal(0, await CountAsync(a.Factory.Services, session.ContinuationId));
    }

    private static void ConfigureSms(IServiceCollection services, FakeSmsSender sender)
    {
        services.Replace(ServiceDescriptor.Singleton(CreateSmsOptions()));
        services.AddSingleton<ISmsSender>(sender);
    }

    private static HttpRequestMessage CarrierRequest(SmsSession session, string phone, int carrier)
    {
        var request = SendPost(
            session,
            fields: SendFields(session, phone),
            query: carrier == 1 ? "?client_id=" + ClientId : null);
        if (carrier == 2)
        {
            request.Headers.Authorization = BasicHeader(ClientId, ClientSecret);
        }

        return request;
    }
}
