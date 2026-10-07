extern alias ConsumerApp;

using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The return-URL validator extension point of the sign-in start: the default local-path rule
/// stays byte for byte, a configured whitelist decides which targets a completed sign-in may
/// land on, and every validator failure shape — rejection, a non-local answer, a throw —
/// answers the one bounded <c>invalid_return_url</c> reason with no pending sign-in created.
/// </summary>
public sealed class ClientReturnUrlValidatorTests
{
    private const string ClientId = "client-pack-app";

    /// <summary>A consumer validator with an invocation count, so no failure path can retry.</summary>
    private sealed class Validator
    {
        private int _calls;

        public int Calls => Volatile.Read(ref _calls);

        public Func<string, string?> Run { get; set; } = static _ => null;

        public string? Validate(string value)
        {
            Interlocked.Increment(ref _calls);
            return Run(value);
        }
    }

    private static async Task<(FakeIdentityProvider Authority, WebApplicationFactory<ConsumerApp.Program> Consumer, CrossServerBrowser Browser)>
        CreateAsync(Validator? validator = null, CapturingLoggerProvider? capture = null)
    {
        var authority = await FakeIdentityProvider.StartAsync();
        var consumer = ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            ClientId,
            "client-pack-test-secret",
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler(),
            loggerProvider: capture,
            configureTestServices: validator is null
                ? null
                : services => services.PostConfigure<SignaCoreHostedLoginOptions>(
                    options => options.ReturnUrlValidator = validator.Validate));
        var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));
        return (authority, consumer, browser);
    }

    /// <summary>Drives start (with one returnUrl) → authorize → callback; returns the callback
    /// response, whose location is the completed sign-in's redirect target.</summary>
    private static async Task<HttpResponseMessage> DriveToCallbackAsync(
        CrossServerBrowser browser, string returnUrl)
    {
        using var start = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(browser.ConsumerBase, "/auth/start?returnUrl=" + Uri.EscapeDataString(returnUrl)));
        using var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, startResponse.StatusCode);
        Assert.StartsWith(
            FakeIdentityProvider.BaseAddress,
            startResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        using var authorize = new HttpRequestMessage(HttpMethod.Get, startResponse.Headers.Location!);
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(
            authorize, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, authorizeResponse.StatusCode);
        using var callback = new HttpRequestMessage(HttpMethod.Get, authorizeResponse.Headers.Location!);
        return await browser.SendOnConsumerAsync(callback, TestContext.Current.CancellationToken);
    }

    private static async Task<HttpResponseMessage> StartAsync(CrossServerBrowser browser, string query)
    {
        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start" + query));
        return await browser.SendOnConsumerAsync(start, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// A rejected start answers the bounded reason, writes no cookie (no pending sign-in was
    /// created), and never reached the authority's authorize endpoint.
    /// </summary>
    private static void AssertRejectedStart(
        HttpResponseMessage response, FakeIdentityProvider authority)
    {
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(
            "/auth/signin-failed?reason=invalid_return_url",
            response.Headers.Location!.ToString());
        Assert.False(response.Headers.TryGetValues("Set-Cookie", out _));
        Assert.Empty(authority.AuthorizeRequests);
    }

    [Fact]
    public async Task WithoutAValidator_TheDefaultRuleStillCompletesTheRoundTrip()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var consumer = ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            ClientId,
            "client-pack-test-secret",
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler());
        await using var _ = consumer;
        using var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));

        using var callback = await DriveToCallbackAsync(browser, "/dashboard");
        Assert.Equal(HttpStatusCode.Found, callback.StatusCode);
        Assert.Equal("/dashboard", callback.Headers.Location!.ToString());

        using var dashboard = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/dashboard"));
        using var dashboardResponse = await browser.SendOnConsumerAsync(
            dashboard, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, dashboardResponse.StatusCode);
        Assert.Equal(
            $"dashboard:{FakeIdentityProvider.DefaultSubject}",
            await dashboardResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AWhitelistedReturnUrl_CompletesTheRoundTripToTheWhitelistedPath()
    {
        var whitelist = new HashSet<string>(StringComparer.Ordinal) { "/dashboard", "/orders" };
        var validator = new Validator { Run = value => whitelist.Contains(value) ? value : null };
        var (authority, consumer, browser) = await CreateAsync(validator);
        await using var _ = consumer;
        using var __ = browser;
        await using var ___ = authority;

        using var callback = await DriveToCallbackAsync(browser, "/dashboard");
        Assert.Equal(HttpStatusCode.Found, callback.StatusCode);
        Assert.Equal("/dashboard", callback.Headers.Location!.ToString());
        Assert.Equal(1, validator.Calls);
        Assert.Single(authority.AuthorizeRequests);
    }

    [Fact]
    public async Task ANonWhitelistedReturnUrl_IsRejectedOnceBeforeAnyWork()
    {
        var validator = new Validator { Run = value => value == "/dashboard" ? value : null };
        var (authority, consumer, browser) = await CreateAsync(validator);
        await using var _ = consumer;
        using var __ = browser;
        await using var ___ = authority;

        using var response = await StartAsync(browser, "?returnUrl=" + Uri.EscapeDataString("/admin/settings"));
        AssertRejectedStart(response, authority);
        // The validator decided once — no retry, no second opinion.
        Assert.Equal(1, validator.Calls);
    }

    [Fact]
    public async Task ANonLocalValidatorAnswer_IsRejectedByTheFinalCheck()
    {
        var validator = new Validator { Run = _ => "//evil.example/dashboard" };
        var (authority, consumer, browser) = await CreateAsync(validator);
        await using var _ = consumer;
        using var __ = browser;
        await using var ___ = authority;

        using var response = await StartAsync(browser, "?returnUrl=/dashboard");
        AssertRejectedStart(response, authority);
        Assert.Equal(1, validator.Calls);
    }

    [Fact]
    public async Task AThrowingValidator_IsARejectionWithTheBoundedLogOnly()
    {
        var capture = new CapturingLoggerProvider();
        var validator = new Validator { Run = _ => throw new InvalidOperationException("private-validator-detail") };
        var (authority, consumer, browser) = await CreateAsync(validator, capture);
        await using var _ = consumer;
        using var __ = browser;
        await using var ___ = authority;

        using var response = await StartAsync(browser, "?returnUrl=/dashboard");
        AssertRejectedStart(response, authority);
        Assert.Equal(1, validator.Calls);

        // The one bounded rejection line answers, carrying neither the validator's exception
        // detail anywhere nor the returnUrl value in the package's own bounded lines (the
        // host's request diagnostics log the URL by themselves; the package never does).
        Assert.Contains(capture.Lines, line =>
            line.Contains("rejected", StringComparison.Ordinal)
            && line.Contains("InvalidReturnUrl", StringComparison.Ordinal));
        Assert.DoesNotContain(capture.Lines, line =>
            line.Contains("private-validator-detail", StringComparison.Ordinal));
        Assert.DoesNotContain(capture.Lines, line =>
            line.StartsWith("[SignaCore.Client.AspNetCore", StringComparison.Ordinal)
            && line.Contains("returnUrl=", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnUnrelatedCancellationFromTheValidator_IsARejection()
    {
        var validator = new Validator { Run = _ => throw new OperationCanceledException() };
        var (authority, consumer, browser) = await CreateAsync(validator);
        await using var _ = consumer;
        using var __ = browser;
        await using var ___ = authority;

        // A validator's own cancellation token (the request was not cancelled) is a failure
        // shape, not the request's cancellation — the bounded rejection answers.
        using var response = await StartAsync(browser, "?returnUrl=/dashboard");
        AssertRejectedStart(response, authority);
        Assert.Equal(1, validator.Calls);
    }

    [Fact]
    public async Task ADuplicatedReturnUrl_IsRejectedWithoutCallingTheValidator()
    {
        var validator = new Validator { Run = value => value };
        var (authority, consumer, browser) = await CreateAsync(validator);
        await using var _ = consumer;
        using var __ = browser;
        await using var ___ = authority;

        // The historical multi-value rejection runs before the extension point.
        using var response = await StartAsync(browser, "?returnUrl=/dashboard&returnUrl=/orders");
        AssertRejectedStart(response, authority);
        Assert.Equal(0, validator.Calls);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AChallengeBuiltReturnUrl_PassesTheSameValidation(bool whitelisted)
    {
        var whitelist = new HashSet<string>(StringComparer.Ordinal) { whitelisted ? "/dashboard" : "/" };
        var validator = new Validator { Run = value => whitelist.Contains(value) ? value : null };
        var (authority, consumer, browser) = await CreateAsync(validator);
        await using var _ = consumer;
        using var __ = browser;
        await using var ___ = authority;

        // The authentication handler's challenge builds the returnUrl from the protected route
        // itself; the start answers by the same whitelist decision.
        using var dashboard = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/dashboard"));
        using var challenge = await browser.SendOnConsumerAsync(
            dashboard, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, challenge.StatusCode);
        Assert.Equal(
            "/auth/start?returnUrl=%2Fdashboard",
            challenge.Headers.Location!.ToString());

        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, challenge.Headers.Location!));
        using var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        if (whitelisted)
        {
            Assert.Equal(HttpStatusCode.Found, startResponse.StatusCode);
            Assert.StartsWith(
                FakeIdentityProvider.BaseAddress,
                startResponse.Headers.Location!.ToString(),
                StringComparison.Ordinal);

            // The whitelisted challenge reaches the authority's authorize endpoint and comes
            // back as a usable callback.
            using var authorize = new HttpRequestMessage(
                HttpMethod.Get, startResponse.Headers.Location!);
            using var authorizeResponse = await browser.SendOnIdentityServerAsync(
                authorize, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Found, authorizeResponse.StatusCode);
            Assert.StartsWith(
                "/auth/callback",
                authorizeResponse.Headers.Location!.PathAndQuery,
                StringComparison.Ordinal);
            Assert.Single(authority.AuthorizeRequests);
        }
        else
        {
            AssertRejectedStart(startResponse, authority);
        }

        Assert.Equal(1, validator.Calls);
    }

    [Fact]
    public async Task AMissingReturnUrl_KeepsTheRootDefault_WithoutConsultingTheValidator()
    {
        var validator = new Validator { Run = value => value == "/dashboard" ? value : null };
        var (authority, consumer, browser) = await CreateAsync(validator);
        await using var _ = consumer;
        using var __ = browser;
        await using var ___ = authority;

        // The fixed application-root default is the package's own choice, not a browser-supplied
        // target: the validator decides only presented values.
        using var response = await StartAsync(browser, "");
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.StartsWith(
            FakeIdentityProvider.BaseAddress,
            response.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        Assert.Equal(0, validator.Calls);
    }

    [Fact]
    public async Task ACancelledRequestInsideTheValidator_PropagatesCancellation()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var capture = new CapturingLoggerProvider();
        using var entered = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(
            TestContext.Current.CancellationToken);
        var consumer = ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            ClientId,
            "client-pack-test-secret",
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler(),
            loggerProvider: capture,
            configureTestServices: services => services.PostConfigure<SignaCoreHostedLoginOptions>(
                options => options.ReturnUrlValidator = value =>
                {
                    entered.Set();
                    // Park until the test has finished cancelling — by then every cancellation
                    // callback, including the server-side request abort, has run — and surface
                    // the cancellation instead of a decision.
                    release.Wait(TimeSpan.FromSeconds(10));
                    cancellation.Token.ThrowIfCancellationRequested();
                    return value;
                }));
        await using var _ = consumer;
        using var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));

        // xUnit1051: the request's own token is the cancellation behavior under test.
#pragma warning disable xUnit1051
        var start = browser.SendOnConsumerAsync(
            new HttpRequestMessage(
                HttpMethod.Get,
                new Uri(browser.ConsumerBase, "/auth/start?returnUrl=/dashboard")),
            cancellation.Token);
#pragma warning restore xUnit1051
        Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));

        await cancellation.CancelAsync();
        release.Set();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => start);

        // The cancellation propagated: the bounded rejection path never ran, so no sign-in was
        // rejected and nothing reached the authority.
        Assert.DoesNotContain(capture.Lines, line =>
            line.Contains("sign-in rejected", StringComparison.Ordinal));
        Assert.Empty(authority.AuthorizeRequests);
    }
}
