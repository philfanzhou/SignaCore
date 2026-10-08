extern alias ConsumerApp;

using System.Net.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The startup validation after ADR 0008 removed the package's transport policy: plain-<c>http</c>
/// Authority and RedirectUri values start in every environment name — including Production — with
/// zero list configuration, while every structural rule (no user info, no query or fragment, the
/// authority's no-path shape, the callback-path match) still fails startup naming the option and
/// never echoing the configured value. A prefixed session cookie name combined with an
/// <c>http</c> RedirectUri fails startup because the prefixes demand the Secure attribute.
/// </summary>
public sealed class ClientHttpTransportOptionsTests
{
    private const string HostOrigin = "http://192.168.55.10:5002";
    private const string ConsumerOrigin = "http://192.168.55.10:5020";
    private const string HttpRedirectUri = ConsumerOrigin + "/auth/callback";

    private static readonly HttpClientHandler Handler = new();

    private static string StartupDiagnostics(
        string authority,
        string redirectUri = HttpRedirectUri,
        string? clientSecret = "test-secret",
        Action<SignaCoreHostedLoginOptions>? configureOptions = null,
        string? environment = null)
    {
        using var factory = ConsumerAppTestServer.Create(
            authority,
            "client-pack-app",
            clientSecret!,
            redirectUri,
            Handler,
            configureTestServices: configureOptions is null
                ? null
                : services => services.PostConfigure(configureOptions),
            environment: environment);
        try
        {
            using var client = factory.CreateClient();
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

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Custom")]
    [InlineData("Development")]
    [InlineData("Testing")]
    public void AnHttpAuthorityAndRedirectUri_StartInEveryEnvironment_WithZeroListConfiguration(
        string environment)
    {
        using var factory = ConsumerAppTestServer.Create(
            HostOrigin,
            "client-pack-app",
            "test-secret",
            HttpRedirectUri,
            Handler,
            environment: environment);
        using var client = factory.CreateClient();
        Assert.NotNull(client);
    }

    [Fact]
    public void AnHttpUlaIpv6Authority_StartsInProduction()
    {
        using var factory = ConsumerAppTestServer.Create(
            "http://[fd00::10]:5002",
            "client-pack-app",
            "test-secret",
            "http://[fd00::10]:5020/auth/callback",
            Handler,
            environment: "Production");
        using var client = factory.CreateClient();
        Assert.NotNull(client);
    }

    [Theory]
    [InlineData("http://user:pass@192.168.55.10:5002", "user:pass")]
    [InlineData("http://192.168.55.10:5002/identity", "/identity")]
    [InlineData("http://192.168.55.10:5002?x=1", "?x=1")]
    [InlineData("http://192.168.55.10:5002#f", "#f")]
    [InlineData("ftp://192.168.55.10:5002", "ftp")]
    [InlineData("192.168.55.10:5002", "192.168.55.10")]
    public void EachIllegalAuthority_FailsStartupNamingTheOptionWithoutEchoingIt(
        string authority, string mustNotAppear)
    {
        var diagnostics = StartupDiagnostics(authority, environment: "Production");
        Assert.Contains("SignaCoreHostedLoginOptions.Authority", diagnostics, StringComparison.Ordinal);
        Assert.DoesNotContain(mustNotAppear, diagnostics, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(ConsumerOrigin)]
    [InlineData(ConsumerOrigin + "/auth/callback?tenant=a")]
    [InlineData(ConsumerOrigin + "/elsewhere/callback")]
    [InlineData("https://user:pass@192.168.55.10:5020/auth/callback")]
    [InlineData("http://192.168.55.10:5020/")]
    public void AnHttpOrHttpsRedirectOriginStillObeysTheFullUriRules(string redirectUri)
    {
        var diagnostics = StartupDiagnostics(
            HostOrigin,
            redirectUri: redirectUri,
            environment: "Production");
        Assert.Contains("SignaCoreHostedLoginOptions.RedirectUri", diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public void AnHttpPostLogoutOriginStillMustMatchTheLogoutReturnPath()
    {
        var diagnostics = StartupDiagnostics(
            HostOrigin,
            configureOptions: options =>
                options.PostLogoutRedirectUri = ConsumerOrigin + "/elsewhere/return",
            environment: "Production");
        Assert.Contains(
            "SignaCoreHostedLoginOptions.PostLogoutRedirectUri", diagnostics, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("__Host-orders.AdminSession")]
    [InlineData("__Secure-orders.AdminSession")]
    [InlineData("__host-orders.AdminSession")]
    public void APrefixedSessionCookieNameWithAnHttpRedirectUri_FailsStartup(string sessionCookieName)
    {
        var diagnostics = StartupDiagnostics(
            HostOrigin,
            configureOptions: options => options.SessionCookieName = sessionCookieName,
            environment: "Production");
        Assert.Contains(
            "SignaCoreHostedLoginOptions.SessionCookieName", diagnostics, StringComparison.Ordinal);
        Assert.Contains(
            "SignaCoreHostedLoginOptions.RedirectUri is an http URI",
            diagnostics,
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("__Host-orders.AdminSession")]
    [InlineData("__Secure-orders.AdminSession")]
    public void APrefixedSessionCookieNameWithAnHttpsRedirectUri_KeepsStarting(string sessionCookieName)
    {
        using var factory = ConsumerAppTestServer.Create(
            "https://signacore.example",
            "client-pack-app",
            "test-secret",
            "https://orders.example/auth/callback",
            Handler,
            configureTestServices: services => services.PostConfigure<SignaCoreHostedLoginOptions>(
                options => options.SessionCookieName = sessionCookieName),
            environment: "Production");
        using var client = factory.CreateClient();
        Assert.NotNull(client);
    }

    [Theory]
    [InlineData("http://127.0.0.1:5099", "http://127.0.0.1:5090/auth/callback")]
    [InlineData("http://localhost:5099", "http://localhost:5090/auth/callback")]
    public void ALoopbackOrLocalhostHttpDeployment_StartsInProductionLikeAnyOther(
        string authority, string redirectUri)
    {
        using var factory = ConsumerAppTestServer.Create(
            authority,
            "client-pack-app",
            "test-secret",
            redirectUri,
            Handler,
            environment: "Production");
        using var client = factory.CreateClient();
        Assert.NotNull(client);
    }
}
