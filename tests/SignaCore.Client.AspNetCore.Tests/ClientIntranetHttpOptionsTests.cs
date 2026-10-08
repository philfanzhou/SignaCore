extern alias ConsumerApp;

using System.Net.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The startup validation of the explicit intranet HTTP deployment opt-in: a legal, exact
/// private-IP HTTP origin list admits exactly its origins in every environment name — including
/// Production — while every illegal entry (public addresses, domains, user info, paths, queries,
/// fragments, HTTPS scheme, missing or out-of-range ports, duplicates) fails startup naming the
/// option and never echoing a configured value. Origin hits relax only the HTTP scheme; every
/// full-URI rule (path shape, no query/fragment/user info, the callback-path match) still applies,
/// and an origin outside the list keeps the historical HTTPS rejection and wording.
/// </summary>
public sealed class ClientIntranetHttpOptionsTests
{
    private const string HostOrigin = "http://192.168.55.10:5002";
    private const string ConsumerOrigin = "http://192.168.55.10:5020";
    private const string IntranetRedirectUri = ConsumerOrigin + "/auth/callback";

    private static readonly HttpClientHandler Handler = new();

    private static string StartupDiagnostics(
        string authority,
        string redirectUri = IntranetRedirectUri,
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

    private static Action<SignaCoreHostedLoginOptions> WithOrigins(
        params string[] origins) =>
        options => options.IntranetHttpOrigins = [.. origins];

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Custom")]
    [InlineData("Development")]
    [InlineData("Testing")]
    public void AnIntranetHttpAuthorityWithAListedOrigin_StartsInEveryEnvironment(string environment)
    {
        using var factory = ConsumerAppTestServer.Create(
            HostOrigin,
            "client-pack-app",
            "test-secret",
            IntranetRedirectUri,
            Handler,
            configureTestServices: services => services.PostConfigure(
                WithOrigins(HostOrigin, ConsumerOrigin)),
            environment: environment);
        using var client = factory.CreateClient();
        Assert.NotNull(client);
    }

    [Fact]
    public void AnIntranetHttpUlaIpv6AuthorityWithAListedOrigin_StartsInProduction()
    {
        using var factory = ConsumerAppTestServer.Create(
            "http://[fd00::10]:5002",
            "client-pack-app",
            "test-secret",
            "http://[fd00::10]:5020/auth/callback",
            Handler,
            configureTestServices: services => services.PostConfigure(
                WithOrigins("http://[fd00::10]:5002", "http://[fd00::10]:5020", "http://[FD00:0:0:0:0:0:0:1]:5030")),
            environment: "Production");
        using var client = factory.CreateClient();
        Assert.NotNull(client);
    }

    [Theory]
    [InlineData("https://192.168.55.10:5002", "192.168.55.10:5002")]
    [InlineData("http://8.8.8.8:5002", "8.8.8.8")]
    [InlineData("http://signacore.intranet:5002", "signacore.intranet")]
    [InlineData("http://user:pass@192.168.55.10:5002", "user:pass")]
    [InlineData("http://192.168.55.10:5002/identity", "/identity")]
    [InlineData("http://192.168.55.10:5002?x=1", "?x=1")]
    [InlineData("http://192.168.55.10:5002#f", "#f")]
    [InlineData("http://192.168.55.10", ":5002")]
    [InlineData("http://192.168.55.10:0", ":0")]
    [InlineData("http://192.168.55.10:65536", "65536")]
    [InlineData("http://192.168.055.10:5002", "055")]
    [InlineData("http://172.32.0.1:5002", "172.32.0.1")]
    [InlineData("http://[2001:db8::1]:5002", "2001:db8::1")]
    [InlineData("http://[::ffff:192.168.55.10]:5002", "ffff")]
    [InlineData("http://[fe80::1]:5002", "fe80")]
    [InlineData("http://127.0.0.1:5099", "5099")]
    [InlineData(" http://192.168.55.10:5002", "http://192.168.55.10:5002")]
    [InlineData("", "SignaCoreHostedLoginOptions.Authority is required")]
    public void EachIllegalListItem_FailsStartupNamingTheOptionWithoutEchoingIt(
        string origin, string mustNotAppear)
    {
        var diagnostics = StartupDiagnostics(
            HostOrigin,
            configureOptions: WithOrigins(HostOrigin, origin),
            environment: "Production");
        Assert.Contains("SignaCoreHostedLoginOptions.IntranetHttpOrigins", diagnostics, StringComparison.Ordinal);
        Assert.DoesNotContain(mustNotAppear, diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public void ANullListItem_FailsStartup()
    {
        var diagnostics = StartupDiagnostics(
            HostOrigin,
            configureOptions: options => options.IntranetHttpOrigins = [HostOrigin, null!],
            environment: "Production");
        Assert.Contains("SignaCoreHostedLoginOptions.IntranetHttpOrigins", diagnostics, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://192.168.55.10:5002", "http://192.168.55.10:5002")]
    [InlineData("HTTP://192.168.55.10:5002", "http://192.168.55.10:5002")]
    [InlineData("http://[FD00::1]:5002", "http://[fd00::1]:5002")]
    public void ADuplicateListEntry_FailsStartupWithoutEchoingIt(string duplicate, string original)
    {
        var diagnostics = StartupDiagnostics(
            HostOrigin,
            configureOptions: WithOrigins(original, duplicate),
            environment: "Production");
        Assert.Contains("SignaCoreHostedLoginOptions.IntranetHttpOrigins", diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnlistedOriginOnTheSameHost_FailsStartupWithTheHistoricalWording()
    {
        var diagnostics = StartupDiagnostics(
            "http://192.168.55.10:5003",
            configureOptions: WithOrigins(HostOrigin, ConsumerOrigin),
            environment: "Production");
        Assert.Contains(
            "SignaCoreHostedLoginOptions.Authority must be an absolute HTTPS URI without a path, query, fragment, or user info. An explicit loopback HTTP origin (127.0.0.1 or [::1]) is accepted only in the Development and Testing environments.",
            diagnostics,
            StringComparison.Ordinal);
        Assert.DoesNotContain("5003", diagnostics, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://8.8.8.8:5002")]
    [InlineData("http://orders.intranet:5020")]
    public void AnUnlistableAuthority_FailsStartup(string authority)
    {
        var diagnostics = StartupDiagnostics(
            authority,
            configureOptions: WithOrigins(HostOrigin, ConsumerOrigin),
            environment: "Production");
        Assert.Contains("SignaCoreHostedLoginOptions.Authority", diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public void AListedAuthorityStillMayNotCarryAPath()
    {
        var diagnostics = StartupDiagnostics(
            "http://192.168.55.10:5002/identity",
            configureOptions: WithOrigins(HostOrigin, ConsumerOrigin),
            environment: "Production");
        Assert.Contains("SignaCoreHostedLoginOptions.Authority", diagnostics, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(ConsumerOrigin)]
    [InlineData(ConsumerOrigin + "/auth/callback?tenant=a")]
    [InlineData(ConsumerOrigin + "/elsewhere/callback")]
    public void AListedRedirectOriginStillObeysTheFullUriRules(string redirectUri)
    {
        var diagnostics = StartupDiagnostics(
            HostOrigin,
            redirectUri: redirectUri,
            configureOptions: WithOrigins(HostOrigin, ConsumerOrigin),
            environment: "Production");
        Assert.Contains("SignaCoreHostedLoginOptions.RedirectUri", diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public void AListedPostLogoutOriginStillMustMatchTheLogoutReturnPath()
    {
        var diagnostics = StartupDiagnostics(
            HostOrigin,
            configureOptions: options =>
            {
                WithOrigins(HostOrigin, ConsumerOrigin)(options);
                options.PostLogoutRedirectUri = ConsumerOrigin + "/elsewhere/return";
            },
            environment: "Production");
        Assert.Contains("SignaCoreHostedLoginOptions.PostLogoutRedirectUri", diagnostics, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("__Host-orders.AdminSession")]
    [InlineData("__Secure-orders.AdminSession")]
    [InlineData("__host-orders.AdminSession")]
    public void APrefixedSessionCookieNameWithAConfiguredList_FailsStartup(string sessionCookieName)
    {
        var diagnostics = StartupDiagnostics(
            HostOrigin,
            configureOptions: options =>
            {
                WithOrigins(HostOrigin, ConsumerOrigin)(options);
                options.SessionCookieName = sessionCookieName;
            },
            environment: "Production");
        Assert.Contains("SignaCoreHostedLoginOptions.SessionCookieName", diagnostics, StringComparison.Ordinal);
        Assert.Contains(
            "SignaCoreHostedLoginOptions.IntranetHttpOrigins", diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEmptyListKeepsTheHistoricalProductionBehavior()
    {
        var diagnostics = StartupDiagnostics(
            HostOrigin,
            configureOptions: options => options.IntranetHttpOrigins = [],
            environment: "Production");
        Assert.Contains("SignaCoreHostedLoginOptions.Authority", diagnostics, StringComparison.Ordinal);
    }
}
