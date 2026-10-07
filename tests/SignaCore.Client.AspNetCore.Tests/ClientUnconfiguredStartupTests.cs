extern alias ConsumerApp;

using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The optional sign-in mode: with <c>AllowUnconfiguredStartup</c> the host starts with blank
/// protocol options and the sign-in surface degrades to one fixed 503 answer (through a
/// presentable writer point) while the session endpoint, logout, and CSRF keep their anonymous
/// behaviors; a challenge surfaces the same 503. The default (off) keeps the historical
/// startup failure, and configured-but-illegal values still fail startup in either mode.
/// </summary>
public sealed class ClientUnconfiguredStartupTests
{
    private static WebApplicationFactory<ConsumerApp.Program> CreateUnconfigured(
        bool allowUnconfigured,
        string? authority = "",
        string? redirectUri = "",
        string? clientSecret = "",
        string? scope = null,
        string clientId = "") =>
        ConsumerAppTestServer.Create(
            authority,
            clientId,
            clientSecret,
            redirectUri,
            new HttpClientHandler(),
            configureTestServices: services => services
                .PostConfigure<SignaCoreHostedLoginOptions>(options =>
                {
                    options.AllowUnconfiguredStartup = allowUnconfigured;
                    if (scope is not null)
                    {
                        options.Scope = scope;
                    }
                }),
            environment: "Production");

    /// <summary>An HTTPS-facing cookie-carrying client over the test server — the package's
    /// antiforgery boundary requires SSL and the antiforgery cookie pair.</summary>
    private static HttpClient CreateHttpsClient(WebApplicationFactory<ConsumerApp.Program> factory)
    {
        var container = new System.Net.CookieContainer();
        return new HttpClient(
            new ConsumerAppTestServer.SharedCookieHandler(factory.Server.CreateHandler(), container))
        {
            BaseAddress = new Uri("https://bff.localhost")
        };
    }

    private static string StartupDiagnostics(WebApplicationFactory<ConsumerApp.Program> factory)
    {
        try
        {
            using var client = CreateHttpsClient(factory);
            return string.Empty;
        }
        catch (Exception exception)
        {
            var text = exception.ToString();
            for (var inner = exception; inner is not null; inner = inner.InnerException)
            {
                text += Environment.NewLine + inner.Message;
            }

            return text;
        }
    }

    [Fact]
    public void ByDefault_BlankOptions_FailStartupExactlyAsBefore()
    {
        using var factory = CreateUnconfigured(allowUnconfigured: false);
        var diagnostics = StartupDiagnostics(factory);
        Assert.Contains("SignaCoreHostedLoginOptions.Authority is required.", diagnostics, StringComparison.Ordinal);
        Assert.Contains("SignaCoreHostedLoginOptions.ClientId is required.", diagnostics, StringComparison.Ordinal);
        Assert.Contains("SignaCoreHostedLoginOptions.ClientSecret is required.", diagnostics, StringComparison.Ordinal);
        Assert.Contains("SignaCoreHostedLoginOptions.RedirectUri is required.", diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InOptionalMode_BlankOptions_StartTheHost()
    {
        using var factory = CreateUnconfigured(allowUnconfigured: true);
        using var client = CreateHttpsClient(factory);
        Assert.NotNull(client);

        // The sign-in surface degrades to the fixed 503 presentation, no retry semantics, no
        // internal details.
        using var start = await client.GetAsync("/auth/start", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, start.StatusCode);
        Assert.Equal("no-store", start.Headers.CacheControl?.ToString());
        Assert.Equal(
            """{"outcome":"sign_in_unavailable"}""",
            await start.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        // The session endpoint keeps the anonymous expired answer.
        using var session = await client.GetAsync("/auth/session", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, session.StatusCode);
        Assert.Equal(
            """{"authenticated":false,"requiresReauthentication":true,"displayName":null,"authorization":null}""",
            await session.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        // CSRF tokens are issued exactly as usual.
        using var csrf = await client.GetAsync("/auth/csrf", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, csrf.StatusCode);
        var csrfBody = await csrf.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("\"token\":", csrfBody, StringComparison.Ordinal);

        // Logout without a session — presenting the antiforgery pair, like any caller — is the
        // fixed local-only result.
        var csrfToken = System.Text.Json.JsonSerializer
            .Deserialize<System.Text.Json.JsonElement>(csrfBody).GetProperty("token").GetString()!;
        using var logout = new HttpRequestMessage(HttpMethod.Post, "/auth/logout");
        logout.Headers.TryAddWithoutValidation(
            SignaCoreHostedLoginDefaults.AntiforgeryHeaderName, csrfToken);
        using var logoutResponse = await client.SendAsync(logout, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, logoutResponse.StatusCode);
        Assert.Equal(
            """{"outcome":"local_only"}""",
            await logoutResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        // A protected route's challenge lands on start and surfaces the same 503.
        using var dashboard = await client.GetAsync("/dashboard", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, dashboard.StatusCode);
        Assert.StartsWith("/auth/start", dashboard.Headers.Location!.ToString(), StringComparison.Ordinal);
        using var challengedStart = await client.GetAsync(
            dashboard.Headers.Location!, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, challengedStart.StatusCode);
    }

    [Fact]
    public async Task InOptionalMode_TheUnavailablePresentation_IsCustomizable()
    {
        using var factory = ConsumerAppTestServer.Create(
            "",
            "client-pack-app",
            "",
            "",
            new HttpClientHandler(),
            configureTestServices: services => services
                .PostConfigure<SignaCoreHostedLoginOptions>(options =>
                {
                    options.AllowUnconfiguredStartup = true;
                    options.ResponseWriter = new DegradedWriter();
                }),
            environment: "Production");
        using var client = CreateHttpsClient(factory);

        using var start = await client.GetAsync("/auth/start", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, start.StatusCode);
        Assert.Equal(
            "sign-in temporarily unavailable",
            await start.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    private sealed class DegradedWriter : ISignaCoreHostedLoginResponseWriter
    {
        public Task WriteSignInFailureAsync(
            HttpContext context, SignaCoreSignInReason reason, CancellationToken cancellationToken) =>
            SignaCoreDefaultResponseWriter.Instance.WriteSignInFailureAsync(context, reason, cancellationToken);

        public Task WriteFailurePageAsync(
            HttpContext context, SignaCoreSignInReason? reason, CancellationToken cancellationToken) =>
            SignaCoreDefaultResponseWriter.Instance.WriteFailurePageAsync(context, reason, cancellationToken);

        public Task WriteSessionStatusAsync(
            HttpContext context, SignaCoreSessionStatus status, CancellationToken cancellationToken) =>
            SignaCoreDefaultResponseWriter.Instance.WriteSessionStatusAsync(context, status, cancellationToken);

        public Task WriteSignInUnavailableAsync(
            HttpContext context, CancellationToken cancellationToken)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return context.Response.WriteAsync("sign-in temporarily unavailable", cancellationToken);
        }
    }

    [Theory]
    [InlineData("http://signacore.example", "", "")]         // illegal authority (plain HTTP)
    [InlineData("https://signacore.example", "https://bff.localhost/auth/callback?tenant=a", "")] // illegal redirect URI
    public void InOptionalMode_ConfiguredButIllegalValues_StillFailStartup(
        string authority,
        string redirectUri,
        string clientSecret)
    {
        using var factory = CreateUnconfigured(
            allowUnconfigured: true,
            authority: authority,
            redirectUri: redirectUri,
            clientSecret: string.IsNullOrWhiteSpace(clientSecret) ? "configured-secret" : clientSecret);
        var diagnostics = StartupDiagnostics(factory);
        Assert.Contains("SignaCoreHostedLoginOptions.", diagnostics, StringComparison.Ordinal);
        Assert.DoesNotContain("is required.", diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public void InOptionalMode_AnIllegalScope_StillFailsStartup()
    {
        using var factory = CreateUnconfigured(
            allowUnconfigured: true,
            authority: "https://signacore.example",
            redirectUri: "https://bff.localhost/auth/callback",
            clientSecret: "configured-secret",
            scope: "profile");
        var diagnostics = StartupDiagnostics(factory);
        Assert.Contains(
            "SignaCoreHostedLoginOptions.Scope must include openid.",
            diagnostics,
            StringComparison.Ordinal);
    }
}
