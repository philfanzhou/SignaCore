extern alias ConsumerApp;

using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The logout presentation extension points: three new <see cref="ISignaCoreHostedLoginResponseWriter"/>
/// methods (prepared logout, local-only, return-failed) each default to the byte-for-byte
/// historical presentation, a custom writer can reshape each envelope independently, and the
/// protocol outcomes underneath — revoke-first, single preparation, one-time correlation
/// consumption — never change with the presentation.
/// </summary>
public sealed class ClientLogoutResponseWriterTests
{
    private const string ClientId = "client-pack-app";
    private const string ClientSecret = "client-pack-test-secret";

    /// <summary>A writer that reshapes all three logout presentations like an SPA integration
    /// would: a 200 JSON logout URL instead of the redirect, an empty 200 for local-only, and a
    /// reason-routed redirect for a failed return.</summary>
    private sealed class SpaStyleWriter : ISignaCoreHostedLoginResponseWriter
    {
        public List<string> SeenLogoutUris { get; } = [];

        public Task WriteSignInFailureAsync(
            HttpContext context, SignaCoreSignInReason reason, CancellationToken cancellationToken) =>
            SignaCoreDefaultResponseWriter.Instance.WriteSignInFailureAsync(context, reason, cancellationToken);

        public Task WriteFailurePageAsync(
            HttpContext context, SignaCoreSignInReason? reason, CancellationToken cancellationToken) =>
            SignaCoreDefaultResponseWriter.Instance.WriteFailurePageAsync(context, reason, cancellationToken);

        public Task WriteSessionStatusAsync(
            HttpContext context, SignaCoreSessionStatus status, CancellationToken cancellationToken) =>
            SignaCoreDefaultResponseWriter.Instance.WriteSessionStatusAsync(context, status, cancellationToken);

        public async Task WriteLogoutPreparedAsync(
            HttpContext context, string logoutUri, CancellationToken cancellationToken)
        {
            SeenLogoutUris.Add(logoutUri);
            context.Response.StatusCode = StatusCodes.Status200OK;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                """{"logoutUrl":""" + JsonSerializer.Serialize(logoutUri) + "}", cancellationToken);
        }

        public async Task WriteLogoutLocalOnlyAsync(
            HttpContext context, CancellationToken cancellationToken)
        {
            context.Response.StatusCode = StatusCodes.Status200OK;
            await context.Response.WriteAsync(string.Empty, cancellationToken);
        }

        public Task WriteLogoutReturnFailedAsync(
            HttpContext context, CancellationToken cancellationToken)
        {
            context.Response.Redirect("/#/login?reason=logout_failed");
            return Task.CompletedTask;
        }
    }

    private static async Task<(WebApplicationFactory<ConsumerApp.Program> Consumer, CrossServerBrowser Browser)>
        SignInAsync(
            FakeIdentityProvider authority,
            ISignaCoreHostedLoginResponseWriter? writer = null)
    {
        var consumer = ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            ClientId,
            ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler(),
            postLogoutRedirectUri: SignaCoreHostFixture.PostLogoutRedirectUri,
            configureTestServices: services =>
            {
                if (writer is not null)
                {
                    services.PostConfigure<SignaCoreHostedLoginOptions>(
                        options => options.ResponseWriter = writer);
                }
            });
        var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));

        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start"));
        using var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        using var authorize = new HttpRequestMessage(
            HttpMethod.Get, startResponse.Headers.Location!);
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(
            authorize, TestContext.Current.CancellationToken);
        using var callback = new HttpRequestMessage(
            HttpMethod.Get, authorizeResponse.Headers.Location!);
        using var callbackResponse = await browser.SendOnConsumerAsync(
            callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Equal("/", callbackResponse.Headers.Location!.ToString());
        return (consumer, browser);
    }

    private static async Task<(HttpResponseMessage Response, string Body)> LogoutAsync(
        CrossServerBrowser browser)
    {
        using var csrf = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/csrf"));
        using var csrfResponse = await browser.SendOnConsumerAsync(
            csrf, TestContext.Current.CancellationToken);
        var token = JsonSerializer.Deserialize<JsonElement>(
            await csrfResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))
            .GetProperty("token").GetString()!;
        using var logout = new HttpRequestMessage(
            HttpMethod.Post, new Uri(browser.ConsumerBase, "/auth/logout"));
        logout.Headers.TryAddWithoutValidation(SignaCoreHostedLoginDefaults.AntiforgeryHeaderName, token);
        var response = await browser.SendOnConsumerAsync(logout, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return (response, body);
    }

    private static async Task<string> DashboardStatusAsync(CrossServerBrowser browser)
    {
        using var dashboard = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/dashboard"));
        using var response = await browser.SendOnConsumerAsync(
            dashboard, TestContext.Current.CancellationToken);
        return response.StatusCode == HttpStatusCode.Found ? "challenged" : "authenticated";
    }

    [Fact]
    public async Task TheDefaultPresentations_AreByteForByteTheHistoricalOnes()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await SignInAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        // Prepared: a bare 302 to the verified logout URI, no Cache-Control, no body.
        var (prepared, preparedBody) = await LogoutAsync(browser);
        Assert.Equal(HttpStatusCode.Found, prepared.StatusCode);
        Assert.StartsWith(
            "https://idp.localhost/oauth2/logout?logout_handle=",
            prepared.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        Assert.Empty(preparedBody);
        Assert.False(prepared.Headers.Contains("Cache-Control"));

        // Local-only (a second logout with nothing left to revoke): 200 JSON, no-store.
        var (localOnly, localOnlyBody) = await LogoutAsync(browser);
        Assert.Equal(HttpStatusCode.OK, localOnly.StatusCode);
        Assert.Equal("""{"outcome":"local_only"}""", localOnlyBody);
        Assert.Equal("no-store", localOnly.Headers.CacheControl.ToString());

        // Return-failed (an uncorrelated return): the fixed 400 English page, no-store.
        using var failedReturn = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(browser.ConsumerBase, "/auth/logout/return?state=" + Uri.EscapeDataString("an-unmatched-state-1234")));
        using var failedResponse = await browser.SendOnConsumerAsync(
            failedReturn, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, failedResponse.StatusCode);
        Assert.Equal("text/html; charset=utf-8", failedResponse.Content.Headers.ContentType?.ToString());
        Assert.Equal("no-store", failedResponse.Headers.CacheControl.ToString());
        var failedBody = await failedResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(
            """
            <!doctype html>
            <html lang="en">
            <head><title>Sign-out could not be confirmed</title></head>
            <body>
            <h1>Sign-out could not be confirmed</h1>
            <p>The sign-out result could not be matched. Sign in again if you were trying to use the application.</p>
            <p><a href="/">Back</a></p>
            </body>
            </html>
            """,
            failedBody);
    }

    [Fact]
    public async Task ACustomWriter_ReshapesAllThreeEnvelopes_WithoutChangingTheProtocol()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var writer = new SpaStyleWriter();
        var (consumer, browser) = await SignInAsync(authority, writer);
        await using var _ = consumer;
        using var __ = browser;

        // Prepared: the SPA envelope carries the package-verified URI, and the local session was
        // revoked before the preparation was attempted — exactly once.
        var (prepared, preparedBody) = await LogoutAsync(browser);
        Assert.Equal(HttpStatusCode.OK, prepared.StatusCode);
        Assert.Equal("application/json", prepared.Content.Headers.ContentType?.MediaType);
        Assert.StartsWith("""{"logoutUrl":"https://idp.localhost/oauth2/logout?logout_handle=""",
            preparedBody, StringComparison.Ordinal);
        Assert.Single(writer.SeenLogoutUris);
        Assert.Equal("challenged", await DashboardStatusAsync(browser));
        Assert.Single(authority.LogoutPrepareBodies);

        // A second logout of the same dead session: local-only through the custom envelope
        // (empty 200), and still exactly one preparation.
        var (localOnly, localOnlyBody) = await LogoutAsync(browser);
        Assert.Equal(HttpStatusCode.OK, localOnly.StatusCode);
        Assert.Equal(string.Empty, localOnlyBody);
        Assert.Single(authority.LogoutPrepareBodies);

        // Return-failed: routed by reason, never an HTML page.
        using var failedReturn = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(browser.ConsumerBase, "/auth/logout/return?state=" + Uri.EscapeDataString("an-unmatched-state-1234")));
        using var failedResponse = await browser.SendOnConsumerAsync(
            failedReturn, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, failedResponse.StatusCode);
        Assert.Equal("/#/login?reason=logout_failed", failedResponse.Headers.Location!.ToString());
    }

    [Fact]
    public async Task ACustomWriter_CompletingTheRealReturn_StillConsumesTheOneTimeState()
    {
        var writer = new SpaStyleWriter();
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await SignInAsync(authority, writer);
        await using var _ = consumer;
        using var __ = browser;

        var (prepared, preparedBody) = await LogoutAsync(browser);
        // The SPA envelope exposes the verified authority URI in its body; the browser
        // completion runs the normal chain and the return endpoint consumes the state once.
        var logoutUrl = JsonDocument.Parse(preparedBody).RootElement.GetProperty("logoutUrl").GetString()!;
        Assert.StartsWith(FakeIdentityProvider.BaseAddress + "/oauth2/logout?logout_handle=", logoutUrl, StringComparison.Ordinal);
        using var completion = new HttpRequestMessage(HttpMethod.Get, new Uri(logoutUrl));
        using var completionResponse = await browser.SendOnIdentityServerAsync(
            completion, TestContext.Current.CancellationToken);
        using var landing = new HttpRequestMessage(
            HttpMethod.Get, completionResponse.Headers.Location!);
        using var landingResponse = await browser.SendOnConsumerAsync(
            landing, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, landingResponse.StatusCode);
        Assert.Equal("/signed-out", landingResponse.Headers.Location!.ToString());

        // The one-time state is consumed; the replay answers through the custom failed writer.
        using var replay = new HttpRequestMessage(
            HttpMethod.Get, completionResponse.Headers.Location!);
        using var replayResponse = await browser.SendOnConsumerAsync(
            replay, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, replayResponse.StatusCode);
        Assert.Equal("/#/login?reason=logout_failed", replayResponse.Headers.Location!.ToString());
    }
}
