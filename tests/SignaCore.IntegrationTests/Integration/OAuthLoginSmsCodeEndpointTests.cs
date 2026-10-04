using System.Net;
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
/// The browser SMS send route <c>POST /oauth2/login/sms-code</c> over the real host (#444,
/// <c>AC-16</c>): the <c>IN-16</c>/<c>IN-19</c>/<c>IN-17</c> local answers write nothing, every
/// counted case answers one uniform result byte-for-byte (<c>SC-22</c>) while only the masked
/// audit row and the closed metric carry the true case, the three budgets hold (<c>SC-25</c>),
/// two racing sends call the provider at most once (<c>SC-26</c>), and from <c>AC-17</c> both pages
/// of the route render the SMS region — the uniform page with the normalized phone, the
/// invalid-phone page with an empty phone input.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class OAuthLoginSmsCodeEndpointTests : IClassFixture<IdentityServerFixture>
{
    private readonly IdentityServerFixture _fixture;

    public OAuthLoginSmsCodeEndpointTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    // ---- IN-16: structure, continuation, and antiforgery failures ----

    [Fact]
    public async Task StructureFailures_AreTheLocal400_WithNoCountLookupOrSend()
    {
        var sender = new FakeSmsSender();
        using var metrics = new SmsCodeMetricsCollector();
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(host.Services, client, app);
        var phone = NewPhone();
        var valid = OAuthLoginTestSupport.BuildEscapedBody(SendFields(session, phone));

        var requests = new List<HttpRequestMessage>
        {
            SendPost(session, rawBody: valid, query: "?client_id=" + app.AppId),
            SendPost(session, rawBody: valid, contentType: null),
            SendPost(session, rawBody: valid, contentType: "application/json"),
            SendPost(session, rawBody: valid, contentType: "application/x-www-form-urlencoded; charset=iso-8859-1"),
            SendPost(session, rawBody: valid, contentType: "application/x-www-form-urlencoded; boundary=x"),
            SendPost(session, rawBody: valid + "&phone=" + phone),
            SendPost(session, rawBody: valid + "&username=someone"),
            SendPost(session, rawBody: valid + "&action=sms_login"),
            SendPost(session, rawBody: valid + "&&otp="),
            SendPost(session, rawBody: valid + "&otp=%FF"),
            SendPost(session, rawBody: valid + "&otp=" + new string('1', 16 * 1024)),
        };

        foreach (var request in requests)
        {
            using (request)
            using (var response = await client.SendAsync(request, TestContext.Current.CancellationToken))
            {
                await AssertLocalRejectionAsync(response);
            }
        }

        await AssertNothingHappenedAsync(host.Services, sender, app, session, phone);
        Assert.Equal(Enumerable.Repeat("local_rejected", requests.Count), metrics.Outcomes);
    }

    [Fact]
    public async Task ContinuationAndAntiforgeryFailures_AreTheLocal400_WithNoCountLookupOrSend()
    {
        var sender = new FakeSmsSender();
        using var metrics = new SmsCodeMetricsCollector();
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(host.Services, client, app);
        var other = await BeginAsync(host.Services, client, app);
        var phone = NewPhone();
        var (expiredHandle, expiredId) = await SeedContinuationAsync(
            host.Services, app, DateTimeOffset.UtcNow.AddMinutes(-(IdentityConstants.LoginHandleLifetimeMinutes + 1)));
        var (consumedHandle, consumedId) = await SeedContinuationAsync(host.Services, app);
        using (var scope = host.Services.CreateScope())
        {
            Assert.True(await scope.ServiceProvider.GetRequiredService<IAuthorizationRequestStore>()
                .TryConsumeAsync(consumedHandle, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken));
        }

        var requests = new List<HttpRequestMessage>
        {
            SendPost(session, fields: [new(LoginAntiforgeryDefaults.TokenFieldName, session.Token), new("phone", phone)]),
            SendPost(session, fields: SendFields(session, phone, handle: session.Handle[..42])),
            SendPost(session, fields: SendFields(session, phone, handle: OAuthLoginTestSupport.RandomHandle())),
            SendPost(session, fields: SendFields(session, phone, handle: expiredHandle)),
            SendPost(session, fields: SendFields(session, phone, handle: consumedHandle)),
            SendPost(session, fields: [new("login_handle", session.Handle), new("phone", phone)]),
            SendPost(session, fields: SendFields(session, phone, token: OAuthLoginTestSupport.TamperLastCharacter(session.Token))),
            SendPost(session, fields: SendFields(session, phone), withCookie: false),
            // A request token of another browser's pair never validates against this cookie.
            SendPost(session, fields: SendFields(session, phone, token: "x" + other.Token[1..])),
        };

        foreach (var request in requests)
        {
            using (request)
            using (var response = await client.SendAsync(request, TestContext.Current.CancellationToken))
            {
                await AssertLocalRejectionAsync(response);
            }
        }

        await AssertNothingHappenedAsync(host.Services, sender, app, session, phone);
        Assert.Equal(0, await CountAsync(host.Services, expiredId));
        Assert.Equal(0, await CountAsync(host.Services, consumedId));
        Assert.Equal(0, await CountAsync(host.Services, other.ContinuationId));
        Assert.Equal(Enumerable.Repeat("local_rejected", requests.Count), metrics.Outcomes);
    }

    // ---- IN-19 gate and IN-17 phone ----

    [Theory]
    [InlineData(SmsLoginMode.Disabled, ProfileKey)]
    [InlineData(SmsLoginMode.ManualApproval, null)]
    [InlineData(SmsLoginMode.AutoProvision, "   ")]
    [InlineData(SmsLoginMode.AutoProvision, "")]
    public async Task AClosedCapabilityGate_IsTheLocal400_WithNoCountLookupOrSend(SmsLoginMode mode, string? profileKey)
    {
        var sender = new FakeSmsSender();
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, mode, profileKey);
        var session = await BeginAsync(host.Services, client, app);
        var phone = NewPhone();
        await SeedIdentityAsync(host.Services, E164(phone), admission: (app.Id, SmsAccessApprovalSource.Admin, true));

        using var response = await client.SendAsync(
            SendPost(session, fields: SendFields(session, phone)), TestContext.Current.CancellationToken);

        await AssertLocalRejectionAsync(response);
        Assert.Equal(0, await CountAsync(host.Services, session.ContinuationId));
        Assert.Null(await OtpAsync(host.Services, app.Id, E164(phone)));
        Assert.Empty(await SmsHistoriesAsync(host.Services, app.AppId));
        Assert.Equal(0, sender.CallCount);
    }

    [Fact]
    public async Task AMissingOrOverLongPhone_IsTheLocal400_AndThe32UnitBoundaryIsCounted()
    {
        var sender = new FakeSmsSender();
        using var metrics = new SmsCodeMetricsCollector();
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(host.Services, client, app);
        var phone = NewPhone();

        using (var missing = await client.SendAsync(
                   SendPost(session, fields: [new("login_handle", session.Handle), new(LoginAntiforgeryDefaults.TokenFieldName, session.Token)]),
                   TestContext.Current.CancellationToken))
        {
            await AssertLocalRejectionAsync(missing);
        }

        using (var overLong = await client.SendAsync(
                   SendPost(session, fields: SendFields(session, new string(' ', 22) + phone)),
                   TestContext.Current.CancellationToken))
        {
            await AssertLocalRejectionAsync(overLong);
        }

        await AssertNothingHappenedAsync(host.Services, sender, app, session, phone);

        // Exactly 32 UTF-16 code units before normalization is admitted, normalized, and counted.
        using var boundary = await client.SendAsync(
            SendPost(session, fields: SendFields(session, new string(' ', 21) + phone)),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, boundary.StatusCode);
        Assert.Contains(EnglishSentNotice, await boundary.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
        Assert.Equal(1, await CountAsync(host.Services, session.ContinuationId));
        Assert.Equal(E164(phone), Assert.Single(sender.Calls).PhoneE164);
        Assert.Equal(["local_rejected", "local_rejected", "sent"], metrics.Outcomes);
    }

    [Fact]
    public async Task AnInvalidPhone_RendersTheFixedNotice_FromTheSubmittedStringAlone()
    {
        var sender = new FakeSmsSender();
        using var metrics = new SmsCodeMetricsCollector();
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(host.Services, client, app);

        var answers = new List<(HttpStatusCode Status, IReadOnlyList<KeyValuePair<string, string>> Headers, string Body)>();
        foreach (var invalid in new[] { "", "   ", "12345", "abc-def", "+8612345678901", "1391234567", "00861291234567" })
        {
            using var response = await client.SendAsync(
                SendPost(session, fields: SendFields(session, invalid)), TestContext.Current.CancellationToken);
            var answer = await ReadAnswerAsync(response);
            answers.Add(answer);
            Assert.Equal(HttpStatusCode.OK, answer.Status);
            Assert.Contains(EnglishInvalidPhoneNotice, answer.Body, StringComparison.Ordinal);
            OAuthLoginTestSupport.AssertFormNoticePlacement(answer.Body);
            Assert.DoesNotContain(EnglishSentNotice, answer.Body, StringComparison.Ordinal);
            if (invalid.Trim().Length > 0)
            {
                Assert.DoesNotContain(invalid.Trim(), answer.Body, StringComparison.Ordinal);
            }

            AssertRenderedFormHeaders(response);
        }

        // One fixed page for every invalid string: status, headers, and bytes.
        Assert.All(answers, answer =>
        {
            Assert.Equal(answers[0].Headers, answer.Headers);
            Assert.Equal(answers[0].Body, answer.Body);
        });
        Assert.Equal(0, await CountAsync(host.Services, session.ContinuationId));
        Assert.Empty(await SmsHistoriesAsync(host.Services, app.AppId));
        Assert.Equal(0, sender.CallCount);
        Assert.Equal(Enumerable.Repeat("invalid_phone", answers.Count), metrics.Outcomes);
    }

    // ---- EV-35 and SC-22: the fourteen counted cases answer one uniform result ----

    [Fact]
    public async Task EveryCountedCase_AnswersOneUniformResult_AndOnlyTheAuditAndMetricCarryTheCase()
    {
        var sender = new FakeSmsSender();
        var failingAudit = new FakeSmsSender();
        var failingWrite = new FakeSmsSender();
        using var metrics = new SmsCodeMetricsCollector();
        using var host = _fixture.CreateSmsHost(sender);
        using var auditFailureHost = _fixture.CreateSmsHost(failingAudit, services =>
            services.Replace(ServiceDescriptor.Scoped<IAuditService, ThrowingAuditService>()));
        using var writeFailureHost = _fixture.CreateSmsHost(failingWrite, services =>
            services.Replace(ServiceDescriptor.Scoped<IUnitOfWork, OtpWriteFailingUnitOfWork>()));
        using var client = host.CreateBrowserClient();
        using var auditFailureClient = auditFailureHost.CreateBrowserClient();
        using var writeFailureClient = writeFailureHost.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.ManualApproval);
        var session = await BeginAsync(host.Services, client, app);
        // One phone typed in one spelling; every case differs only in server-side state.
        var phone = NewPhone();
        var typed = phone[..3] + " " + phone[3..7] + "-" + phone[7..];
        var e164 = E164(phone);

        var cases = new SendCase[]
        {
            new("sent", "sent", Admitted, ProviderCalls: 1, OtpStatus.Sent, AuditEvent: OidcSmsCodeSendService.SentEventType),
            new("not_registered", "not_registered", () => Task.CompletedTask, 0, null, AccountResolved: false),
            new("not_admitted", "not_admitted", () => SeedIdentityAsync(host.Services, e164), 0, null),
            new("admission_inactive", "admission_inactive",
                () => SeedIdentityAsync(host.Services, e164, admission: (app.Id, SmsAccessApprovalSource.Admin, false)), 0, null),
            new("not_admin_approved", "not_admin_approved",
                () => SeedIdentityAsync(host.Services, e164, admission: (app.Id, SmsAccessApprovalSource.AutoProvision, true)), 0, null),
            new("account_disabled", "account_disabled",
                () => SeedIdentityAsync(host.Services, e164, accountActive: false, admission: (app.Id, SmsAccessApprovalSource.Admin, true)), 0, null),
            new("continuation_budget", "continuation_budget", async () =>
            {
                await Admitted();
                await SetCountAsync(host.Services, session.ContinuationId, IdentityConstants.MaxSmsCodeSendsPerContinuation);
            }, 0, null, AccountResolved: false, ExpectedCount: IdentityConstants.MaxSmsCodeSendsPerContinuation),
            new("otp_locked", "otp_locked", async () =>
            {
                await Admitted();
                await SeedOtpAsync(host.Services, app.Id, e164, otp => otp.LockoutUntil = DateTimeOffset.UtcNow.AddMinutes(5));
            }, 0, OtpStatus.Sent),
            new("resend_interval", "resend_interval", async () =>
            {
                await Admitted();
                await SeedOtpAsync(host.Services, app.Id, e164, otp => otp.CreatedAt = DateTimeOffset.UtcNow);
            }, 0, OtpStatus.Sent),
            new("hourly_window", "hourly_window", async () =>
            {
                await Admitted();
                await SeedOtpAsync(host.Services, app.Id, e164, otp =>
                {
                    otp.HourWindowStartedAt = DateTimeOffset.UtcNow.AddMinutes(-30);
                    otp.HourSendCount = 5;
                });
            }, 0, OtpStatus.Sent),
            new("daily_window", "daily_window", async () =>
            {
                await Admitted();
                await SeedOtpAsync(host.Services, app.Id, e164, otp => otp.DaySendCount = 10);
            }, 0, OtpStatus.Sent),
            new("profile_missing", "profile_missing", async () =>
            {
                await Admitted();
                await SetApplicationAsync(host.Services, app.Id, SmsLoginMode.ManualApproval, "unconfigured-profile");
            }, 0, null),
            new("provider_failed", "provider_failed", async () =>
            {
                await Admitted();
                sender.Behavior = (_, _) => throw new SmsDeliveryRejectedException("Rejected", "provider-detail");
            }, 1, OtpStatus.DeliveryFailed),
            // Case 14, failure after delivery: the pre-delivery state stays committed, the Sent
            // state and the audit row do not commit.
            new("persistence_failed_audit", "persistence_failed", Admitted, 1, OtpStatus.PendingDelivery,
                AuditEvent: null, Client: auditFailureClient, Sender: failingAudit),
            // Case 14, failure of the pre-delivery write: nothing but the count is written.
            new("persistence_failed_write", "persistence_failed", Admitted, 0, null,
                AuditEvent: null, Client: writeFailureClient, Sender: failingWrite),
        };

        (HttpStatusCode Status, IReadOnlyList<KeyValuePair<string, string>> Headers, string Body)? reference = null;
        foreach (var testCase in cases)
        {
            await ResetPhoneAsync(host.Services, e164);
            await SetApplicationAsync(host.Services, app.Id, SmsLoginMode.ManualApproval, ProfileKey);
            await SetCountAsync(host.Services, session.ContinuationId, 0);
            sender.Behavior = null;
            await testCase.Arrange();
            var caseSender = testCase.Sender ?? sender;
            var callsBefore = caseSender.CallCount;
            var historiesBefore = (await SmsHistoriesAsync(host.Services, app.AppId)).Count;
            var outcomesBefore = metrics.Outcomes.Count;

            using var response = await (testCase.Client ?? client).SendAsync(
                SendPost(session, fields: SendFields(session, typed)), TestContext.Current.CancellationToken);
            var answer = await ReadAnswerAsync(response);

            // The response: identical status, headers (no Set-Cookie), and bytes for every case.
            Assert.Equal(HttpStatusCode.OK, answer.Status);
            AssertRenderedFormHeaders(response);
            Assert.Contains(EnglishSentNotice, answer.Body, StringComparison.Ordinal);
            OAuthLoginTestSupport.AssertFormNoticePlacement(answer.Body);
            // The phone appears once, normalized, as the value of the page's own phone input
            // (DF-16); the submitted spelling is never echoed.
            Assert.Equal(1, CountOccurrences(answer.Body, e164));
            Assert.Contains(PhoneInput(e164), answer.Body, StringComparison.Ordinal);
            Assert.DoesNotContain(typed, answer.Body, StringComparison.Ordinal);

            reference ??= answer;
            Assert.True(reference.Value.Headers.SequenceEqual(answer.Headers), $"Headers differ for {testCase.Name}.");
            Assert.True(reference.Value.Body == answer.Body, $"Body differs for {testCase.Name}.");

            // The side effects: the count, the provider, the OTP state, the audit, and the metric.
            Assert.Equal(testCase.ExpectedCount, await CountAsync(host.Services, session.ContinuationId));
            Assert.True(testCase.ProviderCalls == caseSender.CallCount - callsBefore, $"Provider calls differ for {testCase.Name}.");
            var otp = await OtpAsync(host.Services, app.Id, e164);
            Assert.True(testCase.OtpStatus == otp?.Status, $"OTP state differs for {testCase.Name}.");
            var histories = await SmsHistoriesAsync(host.Services, app.AppId);
            if (testCase.Outcome == "persistence_failed")
            {
                Assert.Equal(historiesBefore, histories.Count);
            }
            else
            {
                Assert.Equal(historiesBefore + 1, histories.Count);
                var row = histories[^1];
                Assert.Equal("oidc_sms_login", row.AuthMethod);
                Assert.Equal(testCase.AuditEvent ?? OidcSmsCodeSendService.SuppressedEventType, row.EventType);
                Assert.Equal(testCase.Outcome == "sent" ? null : testCase.Outcome, row.FailureReason);
                Assert.Equal(e164[..3] + "****" + e164[^4..], row.Username);
                Assert.Equal(testCase.AccountResolved, row.AccountId is not null);
                Assert.Equal(FixedCorrelationId, row.CorrelationId);
            }

            Assert.Equal(testCase.Outcome, metrics.Outcomes.Skip(outcomesBefore).Single());
        }

        // The page language is the only other input of the bytes.
        await ResetPhoneAsync(host.Services, e164);
        await SetCountAsync(host.Services, session.ContinuationId, 0);
        using var chinese = await client.SendAsync(
            SendPost(session, fields: SendFields(session, typed), acceptLanguage: "zh-CN"), TestContext.Current.CancellationToken);
        var chineseBody = await chinese.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, chinese.StatusCode);
        Assert.Contains(ChineseSentNotice, chineseBody, StringComparison.Ordinal);
        Assert.StartsWith("<!DOCTYPE html><html lang=\"zh-CN\">", chineseBody, StringComparison.Ordinal);
        // Outcomes carry exactly the endpoint and outcome labels, durations the endpoint only.
        Assert.All(metrics.LabelSets, labels => Assert.Contains(labels, new[] { "endpoint", "endpoint,outcome" }));

        Task Admitted() => SeedIdentityAsync(host.Services, e164, admission: (app.Id, SmsAccessApprovalSource.Admin, true));
    }

    [Fact]
    public async Task AutoProvision_SendsToAPhoneWithoutIdentityOrAdmission_AndNeverProvisions()
    {
        var sender = new FakeSmsSender();
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(host.Services, client, app);
        var unknown = NewPhone();
        var unadmitted = NewPhone();
        await SeedIdentityAsync(host.Services, E164(unadmitted));

        foreach (var phone in new[] { unknown, unadmitted })
        {
            using var response = await client.SendAsync(
                SendPost(session, fields: SendFields(session, phone)), TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(OtpStatus.Sent, (await OtpAsync(host.Services, app.Id, E164(phone)))!.Status);
        }

        Assert.Equal([E164(unknown), E164(unadmitted)], sender.Calls.Select(call => call.PhoneE164));
        Assert.Equal(0, await PhoneIdentityRowCountAsync(host.Services, E164(unknown)));
        Assert.Equal(1, await PhoneIdentityRowCountAsync(host.Services, E164(unadmitted)));
        var rows = await SmsHistoriesAsync(host.Services, app.AppId);
        Assert.Equal(["sms_code_sent", "sms_code_sent"], rows.Select(row => row.EventType));
        Assert.Null(rows[0].AccountId);
        Assert.NotNull(rows[1].AccountId);
    }

    // ---- SC-25: the three budgets ----

    [Fact]
    public async Task TheSixthCountedSendOnOneContinuation_IsUniform_AndReachesNoProvider()
    {
        var sender = new FakeSmsSender();
        using var metrics = new SmsCodeMetricsCollector();
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(host.Services, client, app);
        var phones = Enumerable.Range(0, IdentityConstants.MaxSmsCodeSendsPerContinuation + 1).Select(_ => NewPhone()).ToList();

        var bodies = new List<string>();
        foreach (var phone in phones)
        {
            using var response = await client.SendAsync(
                SendPost(session, fields: SendFields(session, phone)), TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            bodies.Add(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }

        // Every body differs from the others only by the normalized phone it re-renders.
        Assert.Single(bodies.Select((body, index) => body.Replace(E164(phones[index]), "{phone}", StringComparison.Ordinal)).Distinct());
        Assert.Equal(phones.Take(5).Select(E164), sender.Calls.Select(call => call.PhoneE164));
        Assert.Null(await OtpAsync(host.Services, app.Id, E164(phones[^1])));
        Assert.Equal(IdentityConstants.MaxSmsCodeSendsPerContinuation, await CountAsync(host.Services, session.ContinuationId));
        Assert.Equal(
            [.. Enumerable.Repeat("sent", 5), "continuation_budget"],
            metrics.Outcomes);
        var last = (await SmsHistoriesAsync(host.Services, app.AppId))[^1];
        Assert.Equal(("sms_code_suppressed", "continuation_budget"), (last.EventType, last.FailureReason));

        // The continuation itself is untouched: still usable for a Password login.
        using var page = await client.GetAsync($"/oauth2/login?login_handle={session.Handle}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
    }

    [Fact]
    public async Task The21stRequestFromOneSourceNetwork_IsTheFixed429_WhateverClientCarrierItNames()
    {
        var sender = new FakeSmsSender();
        using var metrics = new SmsCodeMetricsCollector();
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(host.Services, client, app);
        var registeredClientId = IdentityServerFixture.GatewayAppId;

        // Twenty admitted requests: a third name a registered client in the query, a third in a
        // Basic header. None of them may move into a client partition (PS-24).
        for (var i = 0; i < IdentityConstants.OidcSmsCodeRateLimitPerMinute; i++)
        {
            var request = SendPost(
                session,
                fields: SendFields(session, "invalid"),
                query: i % 3 == 1 ? "?client_id=" + registeredClientId : null);
            if (i % 3 == 2)
            {
                request.Headers.Authorization = OidcDatabaseTestSupport.BasicHeader(registeredClientId, IdentityServerFixture.GatewayAppSecret);
            }

            using (request)
            using (var admitted = await client.SendAsync(request, TestContext.Current.CancellationToken))
            {
                Assert.Equal(i % 3 == 1 ? HttpStatusCode.BadRequest : HttpStatusCode.OK, admitted.StatusCode);
            }
        }

        var phone = NewPhone();
        foreach (var carrier in new[] { "none", "query", "basic" })
        {
            var request = SendPost(
                session,
                fields: SendFields(session, phone),
                query: carrier == "query" ? "?client_id=" + registeredClientId : null);
            if (carrier == "basic")
            {
                request.Headers.Authorization = OidcDatabaseTestSupport.BasicHeader(registeredClientId, IdentityServerFixture.GatewayAppSecret);
            }

            using (request)
            using (var rejected = await client.SendAsync(request, TestContext.Current.CancellationToken))
            {
                Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
                Assert.Equal("no-store", rejected.Headers.CacheControl?.ToString());
                Assert.False(rejected.Headers.Contains("Location"));
                Assert.False(rejected.Headers.Contains("Set-Cookie"));
                Assert.Equal(OidcRateLimitPolicies.RejectionBody,
                    await rejected.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            }
        }

        Assert.Equal(0, sender.CallCount);
        Assert.Equal(0, await CountAsync(host.Services, session.ContinuationId));
        Assert.Null(await OtpAsync(host.Services, app.Id, E164(phone)));
        Assert.Equal(["rate_limited", "rate_limited", "rate_limited"], metrics.Outcomes.TakeLast(3));
        Assert.DoesNotContain("rate_limited", metrics.Outcomes.Take(metrics.Outcomes.Count - 3));
    }

    // ---- SC-26: two sends race on one continuation ----

    [Fact]
    public async Task TwoRacingSends_CallTheProviderAtMostOnce_AndBothAnswerUniformly()
    {
        var sender = new FakeSmsSender();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        sender.Behavior = async (_, _) =>
        {
            entered.TrySetResult();
            await release.Task;
            return new SmsSendResult(FakeSmsSender.ProviderName, "raced");
        };
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(host.Services, client, app);
        var phone = NewPhone();

        // The first send holds the provider call; the second arrives while the first's
        // pre-delivery state is committed and answers without a provider call.
        var first = client.SendAsync(SendPost(session, fields: SendFields(session, phone)), TestContext.Current.CancellationToken);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
        using var second = await client.SendAsync(SendPost(session, fields: SendFields(session, phone)), TestContext.Current.CancellationToken);
        release.SetResult();
        using var firstResponse = await first;

        var firstAnswer = await ReadAnswerAsync(firstResponse);
        var secondAnswer = await ReadAnswerAsync(second);
        Assert.Equal(HttpStatusCode.OK, firstAnswer.Status);
        Assert.Equal(firstAnswer.Headers, secondAnswer.Headers);
        Assert.Equal(firstAnswer.Body, secondAnswer.Body);
        Assert.Equal(1, sender.CallCount);
        Assert.Equal(2, await CountAsync(host.Services, session.ContinuationId));
        var reasons = (await SmsHistoriesAsync(host.Services, app.AppId)).Select(row => row.FailureReason ?? row.EventType).Order();
        Assert.Equal(["resend_interval", "sms_code_sent"], reasons);

        // Truly concurrent sends for a fresh phone: at most one provider call, identical bytes.
        sender.Behavior = null;
        var racePhone = NewPhone();
        var racers = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ =>
            client.SendAsync(SendPost(session, fields: SendFields(session, racePhone)), TestContext.Current.CancellationToken)));
        try
        {
            var bodies = await Task.WhenAll(racers.Select(r => r.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)));
            Assert.All(racers, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
            Assert.Equal(bodies[0], bodies[1]);
            Assert.Equal(
                firstAnswer.Body.Replace(E164(phone), "{phone}", StringComparison.Ordinal),
                bodies[0].Replace(E164(racePhone), "{phone}", StringComparison.Ordinal));
            Assert.InRange(sender.Calls.Count(call => call.PhoneE164 == E164(racePhone)), 0, 1);
            Assert.Equal(4, await CountAsync(host.Services, session.ContinuationId));
        }
        finally
        {
            foreach (var racer in racers) racer.Dispose();
        }
    }

    // ---- AC-17: both pages of the route render the SMS region ----

    [Fact]
    public async Task TheUniformPage_FillsTheNormalizedPhone_AndTheInvalidPhonePage_LeavesItEmpty()
    {
        var sender = new FakeSmsSender();
        using var host = _fixture.CreateSmsHost(sender);
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.AutoProvision);
        var session = await BeginAsync(host.Services, client, app);
        var phone = NewPhone();

        using var sent = await client.SendAsync(
            SendPost(session, fields: SendFields(session, "0086 " + phone)), TestContext.Current.CancellationToken);
        var sentBody = await sent.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, sent.StatusCode);
        Assert.Contains(PhoneInput(E164(phone)), sentBody, StringComparison.Ordinal);
        Assert.Contains(OtpInput, sentBody, StringComparison.Ordinal);
        Assert.Contains(SmsSubmitButton, sentBody, StringComparison.Ordinal);
        Assert.Contains(SendButton, sentBody, StringComparison.Ordinal);
        Assert.DoesNotContain("0086 ", sentBody, StringComparison.Ordinal);

        using var invalid = await client.SendAsync(
            SendPost(session, fields: SendFields(session, "12345")), TestContext.Current.CancellationToken);
        var invalidBody = await invalid.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, invalid.StatusCode);
        Assert.Contains(EnglishInvalidPhoneNotice, invalidBody, StringComparison.Ordinal);
        Assert.Contains(PhoneInput(string.Empty), invalidBody, StringComparison.Ordinal);
        Assert.DoesNotContain("12345", invalidBody, StringComparison.Ordinal);

        // Apart from the notice and the phone value, the two pages and the GET page are one form.
        using var page = await client.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, $"/oauth2/login?login_handle={session.Handle}")
            {
                Headers = { { "Cookie", CookieHeader(session) } }
            },
            TestContext.Current.CancellationToken);
        // The GET render issues a fresh request token for the same cookie; align it with the posted one.
        var pageBody = OAuthLoginSmsCodeTestSupport.WithRequestToken(
            await page.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), session.Token);
        Assert.Equal(
            pageBody,
            sentBody.Replace(EnglishSentNotice, string.Empty, StringComparison.Ordinal)
                .Replace(PhoneInput(E164(phone)), PhoneInput(string.Empty), StringComparison.Ordinal)
                .Replace(" aria-describedby=\"sms-notice\"", string.Empty, StringComparison.Ordinal));
        Assert.Equal(pageBody, invalidBody.Replace(EnglishInvalidPhoneNotice, string.Empty, StringComparison.Ordinal)
            .Replace(" aria-describedby=\"sms-notice\"", string.Empty, StringComparison.Ordinal));
    }

    private static int CountOccurrences(string text, string value)
    {
        var count = 0;
        for (var index = text.IndexOf(value, StringComparison.Ordinal); index >= 0;
             index = text.IndexOf(value, index + value.Length, StringComparison.Ordinal))
        {
            count++;
        }

        return count;
    }

    // ---- Assertions ----

    private static async Task AssertLocalRejectionAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(
            OAuthLoginTestSupport.EnglishLocalErrorPage,
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
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
        Assert.Equal("text/html; charset=utf-8", response.Content.Headers.ContentType?.ToString());
    }

    private static async Task AssertNothingHappenedAsync(
        IServiceProvider services,
        FakeSmsSender sender,
        SmsApp app,
        SmsSession session,
        string phone)
    {
        Assert.Equal(0, await CountAsync(services, session.ContinuationId));
        Assert.Null(await OtpAsync(services, app.Id, E164(phone)));
        Assert.Empty(await SmsHistoriesAsync(services, app.AppId));
        Assert.Equal(0, sender.CallCount);
    }

    private sealed record SendCase(
        string Name,
        string Outcome,
        Func<Task> Arrange,
        int ProviderCalls,
        OtpStatus? OtpStatus,
        bool AccountResolved = true,
        int ExpectedCount = 1,
        string? AuditEvent = null,
        HttpClient? Client = null,
        FakeSmsSender? Sender = null);

    /// <summary>
    /// An audit writer that cannot stage a browser SMS row: the committed state before it stays as
    /// it was. Every other audit row is written as usual.
    /// </summary>
    private sealed class ThrowingAuditService(ILoginHistoryRepository histories) : IAuditService
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
    /// A unit of work that cannot commit an OTP row — the pre-delivery write fails for a reason
    /// other than a concurrent challenge — and commits everything else as usual.
    /// </summary>
    private sealed class OtpWriteFailingUnitOfWork(IdentityDbContext dbContext) : IUnitOfWork
    {
        public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default) =>
            dbContext.ChangeTracker.Entries<OtpEntity>().Any()
                ? throw new InvalidOperationException("Simulated OTP persistence failure.")
                : dbContext.SaveChangesAsync(cancellationToken);
    }
}
