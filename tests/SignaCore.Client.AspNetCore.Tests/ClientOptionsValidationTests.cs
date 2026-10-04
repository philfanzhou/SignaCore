extern alias ConsumerApp;

using System.Net.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The startup validation of the package options: an incomplete or illegal configuration is a
/// startup failure whose diagnostics name the option — never the configured value — and the
/// mapped prefix and the registered callback path must agree exactly.
/// </summary>
public sealed class ClientOptionsValidationTests
{
    private static readonly HttpClientHandler Handler = new();

    private static string StartupDiagnostics(
        string authority,
        string redirectUri = SignaCoreHostFixture.RedirectUri,
        string? clientSecret = "test-secret",
        Action<IServiceCollection>? configureTestServices = null,
        string? environment = null)
    {
        using var factory = ConsumerAppTestServer.Create(
            authority,
            "client-pack-app",
            clientSecret!,
            redirectUri,
            Handler,
            configureTestServices: configureTestServices,
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

    [Fact]
    public void AnHttpAuthorityOutsideDevelopment_FailsStartup()
    {
        var diagnostics = StartupDiagnostics("http://signacore.example", environment: "Production");
        Assert.Contains("SignaCoreHostedLoginOptions.Authority", diagnostics, StringComparison.Ordinal);
        Assert.DoesNotContain("signacore.example", diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public void ALoopbackHttpAuthorityInProduction_FailsStartup()
    {
        var diagnostics = StartupDiagnostics("http://127.0.0.1:5099", environment: "Production");
        Assert.Contains("SignaCoreHostedLoginOptions.Authority", diagnostics, StringComparison.Ordinal);
        // The message names the option and the rule (which mentions the loopback form by name);
        // it must not echo the configured value's own port.
        Assert.DoesNotContain("5099", diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public void LocalhostHttpIsNeverAccepted() =>
        Assert.Contains(
            "SignaCoreHostedLoginOptions.Authority",
            StartupDiagnostics("http://localhost:5099", environment: "Production"),
            StringComparison.Ordinal);

    [Fact]
    public void AnAuthorityWithPath_FailsStartup() =>
        Assert.Contains(
            "SignaCoreHostedLoginOptions.Authority",
            StartupDiagnostics("https://signacore.example/identity", environment: "Production"),
            StringComparison.Ordinal);

    [Fact]
    public void AMissingClientSecret_FailsStartup()
    {
        var diagnostics = StartupDiagnostics(
            "https://signacore.example", clientSecret: null, environment: "Production");
        Assert.Contains("SignaCoreHostedLoginOptions.ClientSecret", diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public void ARedirectUriWithQuery_FailsStartup()
    {
        var diagnostics = StartupDiagnostics(
            "https://signacore.example",
            "https://bff.localhost/auth/callback?tenant=a", environment: "Production");
        Assert.Contains("SignaCoreHostedLoginOptions.RedirectUri", diagnostics, StringComparison.Ordinal);
        Assert.DoesNotContain("tenant", diagnostics, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(31)]
    public void InvalidPreSignInTimeout_FailsStartupWithoutEchoingTheValue(int seconds) =>
        Assert.Contains("SignaCoreHostedLoginOptions.PreSignInAuthorizationTimeout is invalid.",
            StartupDiagnostics("https://signacore.example",
                configureTestServices: services => services.PostConfigure<SignaCoreHostedLoginOptions>(
                    options => options.PreSignInAuthorizationTimeout = TimeSpan.FromSeconds(seconds)),
                environment: "Production"), StringComparison.Ordinal);

    [Fact]
    public void AZeroTicketCapacity_FailsStartup() =>
        Assert.Contains(
            "SignaCoreHostedLoginOptions.TicketCapacity",
            StartupDiagnostics(
                "https://signacore.example",
                configureTestServices: services => services
                    .PostConfigure<SignaCoreHostedLoginOptions>(options => options.TicketCapacity = 0),
                environment: "Production"),
            StringComparison.Ordinal);

    [Fact]
    public void AScopeWithoutOpenid_FailsStartup() =>
        Assert.Contains(
            "SignaCoreHostedLoginOptions.Scope",
            StartupDiagnostics(
                "https://signacore.example",
                configureTestServices: services => services
                    .PostConfigure<SignaCoreHostedLoginOptions>(options => options.Scope = "profile"),
                environment: "Production"),
            StringComparison.Ordinal);

    [Fact]
    public void ALoopbackHttpAuthorityInTesting_StartsSuccessfully()
    {
        using var factory = ConsumerAppTestServer.Create(
            "http://127.0.0.1:5099",
            "client-pack-app",
            "test-secret",
            "http://127.0.0.1:5090/auth/callback",
            Handler,
            environment: "Testing");
        using var client = factory.CreateClient();
        Assert.NotNull(client);
    }

    [Fact]
    public void ARedirectUriPathThatDoesNotMatchTheMappedCallback_FailsStartup()
    {
        var diagnostics = StartupDiagnostics(
            "https://signacore.example",
            redirectUri: "https://bff.localhost/elsewhere/callback",
            environment: "Production");
        Assert.Contains("RedirectUri", diagnostics, StringComparison.Ordinal);
        Assert.DoesNotContain("/elsewhere", diagnostics, StringComparison.Ordinal);
    }
}
