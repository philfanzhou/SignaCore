extern alias ConsumerApp;

using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The validation strictness policy and its five dimensions. The default (zero-configuration)
/// profile is strict: a future ID-token <c>iat</c>, an oversized token response, a duplicated
/// top-level JSON member, a scope echo beyond the requested scopes, and a token past its
/// zero-skew window each fail the sign-in through the existing closed paths, while SignaCore's
/// own normal responses (legal scope echo, no duplicates, present-day <c>iat</c>) pass
/// untouched. Each dimension relaxes independently through
/// <see cref="SignaCoreValidationOptions"/>, and an illegal configuration value fails startup
/// naming only the option.
/// </summary>
public sealed class ClientValidationStrictnessTests
{
    private const string ClientId = "client-pack-app";
    private const string ClientSecret = "client-pack-test-secret";

    private static async Task<(WebApplicationFactory<ConsumerApp.Program> Consumer, CrossServerBrowser Browser)>
        CreateAsync(
            FakeIdentityProvider authority,
            Action<SignaCoreValidationOptions>? configureValidation = null,
            bool preSignInGate = false)
    {
        var consumer = ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            ClientId,
            ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler(),
            configureTestServices: services =>
            {
                if (configureValidation is not null)
                {
                    services.PostConfigure<SignaCoreHostedLoginOptions>(
                        options => configureValidation(options.Validation));
                }

                if (preSignInGate)
                {
                    // The gated access-token checks are exercised through the pre-sign-in gate.
                    services.PostConfigure<SignaCoreHostedLoginOptions>(options =>
                        options.PreSignInAuthorizationDecision = new AllowingDecision());
                }
            });
        var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));
        return (consumer, browser);
    }

    private sealed class AllowingDecision : ISignaCorePreSignInAuthorizationDecision
    {
        public ValueTask<SignaCoreAuthorizationDecisionResult> DecideAsync(
            SignaCorePreSignInAuthorizationContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(SignaCoreAuthorizationDecisionResult.Allowed);
    }

    /// <summary>Drives one complete sign-in; returns the callback's outcome ("success" or the
    /// bounded failure reason of the redirect) without following it.</summary>
    private static async Task<string> DriveSignInAsync(CrossServerBrowser browser)
    {
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
        var location = callbackResponse.Headers.Location!.ToString();
        return location == "/" ? "success" : location.Split('=')[^1];
    }

    private static async Task<string> DriveLogoutAsync(CrossServerBrowser browser)
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
        using var logoutResponse = await browser.SendOnConsumerAsync(
            logout, TestContext.Current.CancellationToken);
        if (logoutResponse.StatusCode == HttpStatusCode.Found)
        {
            return "prepared";
        }

        var body = await logoutResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return body;
    }

    [Fact]
    public async Task ANormalSignIn_PassesTheStrictDefaultProfile()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        // The fake echoes the granted scope exactly as the real host does; no duplicates, a
        // present-day iat, and a normal-sized body all pass the strict defaults.
        Assert.Equal("success", await DriveSignInAsync(browser));
    }

    [Fact]
    public async Task AFutureIdTokenIat_IsRejectedByDefault_AndPassesWhenRelaxed()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        // Only the issued-at moves into the future; the lifetime claims stay present-day so the
        // relaxed run isolates exactly the iat dimension.
        authority.IdTokenIatOnlyOffset = TimeSpan.FromMinutes(2);
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;
        Assert.Equal("invalid_token", await DriveSignInAsync(browser));

        var (relaxedConsumer, relaxedBrowser) = await CreateAsync(
            authority, configureValidation: validation => validation.RejectFutureIssuedAt = false);
        await using var _2 = relaxedConsumer;
        using var _3 = relaxedBrowser;
        Assert.Equal("success", await DriveSignInAsync(relaxedBrowser));
    }

    [Fact]
    public async Task AnOversizedTokenResponse_IsRejectedByDefault_AndPassesWhenTheCeilingIsRaised()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        // One byte past the default 64 KB ceiling.
        authority.TokenResponseTargetBytes = 64 * 1024 + 1;
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;
        Assert.Equal("invalid_token", await DriveSignInAsync(browser));

        var (raisedConsumer, raisedBrowser) = await CreateAsync(
            authority, configureValidation: validation => validation.MaxTokenResponseBytes = 128 * 1024);
        await using var _2 = raisedConsumer;
        using var _3 = raisedBrowser;
        Assert.Equal("success", await DriveSignInAsync(raisedBrowser));
    }

    [Fact]
    public async Task ATokenResponseBodyOfExactlyTheCeiling_IsAccepted()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.TokenResponseTargetBytes = 64 * 1024;
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;
        Assert.Equal("success", await DriveSignInAsync(browser));
    }

    [Fact]
    public async Task ADuplicatedTopLevelMemberInATokenResponse_IsRejectedByDefault_AndPassesWhenRelaxed()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.TokenResponseDuplicateMember = "expires_in";
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;
        Assert.Equal("invalid_token", await DriveSignInAsync(browser));

        var (relaxedConsumer, relaxedBrowser) = await CreateAsync(
            authority, configureValidation: validation => validation.RejectDuplicateJsonMembers = false);
        await using var _2 = relaxedConsumer;
        using var _3 = relaxedBrowser;
        Assert.Equal("success", await DriveSignInAsync(relaxedBrowser));
    }

    [Theory]
    [InlineData("openid profile email")]
    [InlineData("openid offline_access")]
    public async Task AScopeEchoBeyondTheRequestedScopes_IsRejectedByDefault_AndPassesWhenRelaxed(
        string echoedScope)
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.TokenResponseScope = echoedScope;
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;
        Assert.Equal("invalid_token", await DriveSignInAsync(browser));

        var (relaxedConsumer, relaxedBrowser) = await CreateAsync(
            authority, configureValidation: validation => validation.RequireScopeEchoSubset = false);
        await using var _2 = relaxedConsumer;
        using var _3 = relaxedBrowser;
        Assert.Equal("success", await DriveSignInAsync(relaxedBrowser));
    }

    [Theory]
    [InlineData("openid profile")]
    [InlineData("openid")]
    [InlineData(null)]
    public async Task ALegalScopeEcho_EqualSubsetOrAbsent_IsAccepted(string? echoedScope)
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.TokenResponseScope = echoedScope;
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;
        Assert.Equal("success", await DriveSignInAsync(browser));
    }

    [Fact]
    public async Task ATokenPastItsZeroSkewWindow_IsRejectedByDefault_AndPassesWithSkew()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        // The ID token's not-before lies five seconds in the future: invisible to the old
        // thirty-second skew, rejected by the strict zero.
        authority.IdTokenTimeOffset = TimeSpan.FromSeconds(5);
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;
        Assert.Equal("invalid_token", await DriveSignInAsync(browser));

        var (skewedConsumer, skewedBrowser) = await CreateAsync(
            authority, configureValidation: validation => validation.ClockSkew = TimeSpan.FromSeconds(30));
        await using var _2 = skewedConsumer;
        using var _3 = skewedBrowser;
        Assert.Equal("success", await DriveSignInAsync(skewedBrowser));
    }

    [Fact]
    public async Task AGatedAccessTokenWithAFutureIat_IsRejectedByDefault()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.SignedAccessToken = true;
        var (consumer, browser) = await CreateAsync(authority, preSignInGate: true);
        await using var _ = consumer;
        using var __ = browser;
        Assert.Equal("success", await DriveSignInAsync(browser));

        // The same authority five seconds ahead on its access-token clock fails the strict zero
        // skew before the decision is called.
        authority.AccessTimeOffset = TimeSpan.FromSeconds(5);
        var (strictConsumer, strictBrowser) = await CreateAsync(authority, preSignInGate: true);
        await using var _2 = strictConsumer;
        using var _3 = strictBrowser;
        Assert.Equal("invalid_token", await DriveSignInAsync(strictBrowser));
    }

    [Fact]
    public async Task ALargeLogoutResponse_EndsLocalOnlyByDefault_AndPreparesWhenTheCeilingIsRaised()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.LogoutPrepare = FakeIdentityProvider.LogoutPrepareShape.OversizedBody;
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;
        Assert.Equal("success", await DriveSignInAsync(browser));
        Assert.Equal("""{"outcome":"local_only"}""", await DriveLogoutAsync(browser));

        var (raisedConsumer, raisedBrowser) = await CreateAsync(
            authority, configureValidation: validation => validation.MaxLogoutResponseBytes = 16 * 1024);
        await using var _2 = raisedConsumer;
        using var _3 = raisedBrowser;
        Assert.Equal("success", await DriveSignInAsync(raisedBrowser));
        Assert.Equal("prepared", await DriveLogoutAsync(raisedBrowser));
    }

    [Fact]
    public async Task ADuplicatedLogoutUriMember_EndsLocalOnlyByDefault()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.LogoutPrepare = FakeIdentityProvider.LogoutPrepareShape.DuplicatedUriMember;
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;
        Assert.Equal("success", await DriveSignInAsync(browser));
        Assert.Equal("""{"outcome":"local_only"}""", await DriveLogoutAsync(browser));
    }

    private static readonly HttpClientHandler SharedHandler = new();

    [Theory]
    [InlineData(-0.001)]
    [InlineData(31)]
    public void ANegativeOrOversizedClockSkew_FailsStartupNamingOnlyTheOption(double seconds) =>
        Assert.Contains(
            "SignaCoreHostedLoginOptions.Validation.ClockSkew is invalid",
            StartupDiagnostics(services => services.PostConfigure<SignaCoreHostedLoginOptions>(
                options => options.Validation.ClockSkew = TimeSpan.FromSeconds(seconds))),
            StringComparison.Ordinal);

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void NonPositiveResponseCeilings_FailStartupNamingOnlyTheOption(int bytes) =>
        Assert.Contains(
            "SignaCoreHostedLoginOptions.Validation.MaxTokenResponseBytes must be positive.",
            StartupDiagnostics(services => services.PostConfigure<SignaCoreHostedLoginOptions>(
                options => options.Validation.MaxTokenResponseBytes = bytes)),
            StringComparison.Ordinal);

    [Fact]
    public void ANonPositiveLogoutCeiling_FailsStartupNamingOnlyTheOption() =>
        Assert.Contains(
            "SignaCoreHostedLoginOptions.Validation.MaxLogoutResponseBytes must be positive.",
            StartupDiagnostics(services => services.PostConfigure<SignaCoreHostedLoginOptions>(
                options => options.Validation.MaxLogoutResponseBytes = 0)),
            StringComparison.Ordinal);

    private static string StartupDiagnostics(Action<IServiceCollection> configure)
    {
        using var factory = ConsumerAppTestServer.Create(
            "https://signacore.example",
            ClientId,
            ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            SharedHandler,
            configureTestServices: configure,
            environment: "Production");
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
}
