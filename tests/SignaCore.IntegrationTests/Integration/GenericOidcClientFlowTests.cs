using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host;
using SignaCore.Host.Security;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// ADR 0010 stage 4: the generic-path acceptance. A consumer built on nothing but the
/// framework's own OpenID Connect handler 鈥?the <c>samples/SignaCore.GenericOidc</c> application,
/// which references no SignaCore package 鈥?completes the whole interactive lifecycle against the
/// real host: Discovery, the code + PKCE S256 authorization request, the hosted login form, the
/// token redemption, the local cookie session, and the standard RP-Initiated Logout published by
/// stage 1. The test runs on every CI build, so any future regression of the standard surfaces
/// fails here instead of in a downstream consumer.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class GenericOidcClientFlowTests : IClassFixture<IdentityServerFixture>
{
    private const string Username = "generic_oidc_flow_user";
    private const string Password = "GenericOidcFlow-123!";
    private const string ClientId = "generic-oidc-flow-app";
    private const string ClientSecret = "generic-oidc-flow-secret-canary";

    /// <summary>The consumer's external origin; only the in-memory browser uses it.</summary>
    private const string ConsumerBase = "https://consumer.generic.test";

    private const string RedirectUri = ConsumerBase + "/signin-oidc";
    private const string PostLogoutUri = ConsumerBase + "/signout-callback-oidc";

    /// <summary>
    /// The fixture's completed installation seeds <c>http://localhost</c> as both the public base
    /// URL and the token issuer, so the generic handler must be pointed there and opt out of the
    /// framework's HTTPS-metadata default 鈥?the same plain-HTTP decision ADR 0008 documents.
    /// </summary>
    private const string Authority = "http://localhost";

    private readonly IdentityServerFixture _fixture;

    public GenericOidcClientFlowTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task TheGenericHandler_CompletesSignInAndStandardSignOut_AgainstTheRealHost()
    {
        var accountId = await SeedUserAndApplicationAsync();
        using var identity = _fixture.WithTestServices(_ => { });
        using var consumer = CreateConsumerFactory(identity.Server.CreateHandler());
        using var browser = new CrossOriginBrowser(identity.Server.CreateHandler(), consumer.Server.CreateHandler());

        // ---- Sign-in: challenge 鈫?authorize 鈫?hosted login 鈫?callback 鈫?local session ----
        using var challenge = await browser.GetConsumerAsync("/challenge");
        Assert.Equal(HttpStatusCode.Found, challenge.StatusCode);
        var authorizeUrl = ToIdentityBrowserUrl(challenge.Headers.Location!);
        Assert.StartsWith("https://localhost/oauth2/authorize?", authorizeUrl, StringComparison.Ordinal);
        // The generic handler sends exactly the standard shape SignaCore stage 2 delivers.
        Assert.Contains("response_type=code", authorizeUrl, StringComparison.Ordinal);
        Assert.Contains("code_challenge_method=S256", authorizeUrl, StringComparison.Ordinal);
        Assert.Contains("scope=openid", authorizeUrl, StringComparison.Ordinal);

        using var authorize = await browser.GetIdentityAsync(authorizeUrl);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var loginLocation = authorize.Headers.Location!.ToString();
        Assert.StartsWith("/oauth2/login?login_handle=", loginLocation, StringComparison.Ordinal);

        // The hosted login form: parse the antiforgery token, submit the credentials, and follow
        // the committed redirect back to the consumer's callback.
        using var form = await browser.GetIdentityAsync(loginLocation);
        Assert.Equal(HttpStatusCode.OK, form.StatusCode);
        var formBody = await form.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var token = new Regex("name=\"__RequestVerificationToken\" value=\"([^\"]+)\"")
            .Match(formBody).Groups[1].Value;
        Assert.False(string.IsNullOrEmpty(token));
        const string loginHandlePrefix = "/oauth2/login?login_handle=";
        var handle = loginLocation[loginHandlePrefix.Length..];

        using var loginResponse = await browser.PostIdentityFormAsync(
            "/oauth2/login",
            new Dictionary<string, string>
            {
                ["login_handle"] = handle,
                ["__RequestVerificationToken"] = token,
                ["username"] = Username,
                ["password"] = Password
            });
        Assert.Equal(HttpStatusCode.Found, loginResponse.StatusCode);
        var callbackUrl = ToIdentityBrowserUrl(loginResponse.Headers.Location!);
        Assert.StartsWith(RedirectUri, callbackUrl, StringComparison.Ordinal);
        Assert.Contains("code=", callbackUrl, StringComparison.Ordinal);

        using var callback = await browser.GetConsumerAsync(
            new Uri(callbackUrl).PathAndQuery);
        Assert.Equal(HttpStatusCode.Found, callback.StatusCode);

        using var me = await browser.GetConsumerAsync("/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        var meBody = await me.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains(Username, meBody, StringComparison.Ordinal);

        // ---- Sign-out: local cookie first, then the standard end_session_endpoint ----
        using var signout = await browser.PostConsumerAsync("/signout");
        Assert.Equal(HttpStatusCode.Found, signout.StatusCode);
        var endSessionUrl = ToIdentityBrowserUrl(signout.Headers.Location!);
        Assert.StartsWith("https://localhost/oauth2/session/end?", endSessionUrl, StringComparison.Ordinal);
        Assert.Contains("id_token_hint=", endSessionUrl, StringComparison.Ordinal);
        Assert.Contains(
            "post_logout_redirect_uri=" + Uri.EscapeDataString(PostLogoutUri),
            endSessionUrl,
            StringComparison.Ordinal);

        using var endSession = await browser.GetIdentityAsync(endSessionUrl);
        Assert.Equal(HttpStatusCode.Found, endSession.StatusCode);
        var signedOutLocation = endSession.Headers.Location!.ToString();
        Assert.StartsWith(PostLogoutUri, signedOutLocation, StringComparison.Ordinal);

        using var signedOut = await browser.GetConsumerAsync(
            new Uri(signedOutLocation).PathAndQuery);
        Assert.Equal(HttpStatusCode.OK, signedOut.StatusCode);

        // EV-06: the standard logout revoked the SignaCore identity session of this account.
        var session = await QuerySessionAsync(accountId);
        Assert.NotNull(session);
        Assert.NotNull(session!.RevokedAt);
        Assert.Equal("logout", session.RevocationReason);

        // The consumer's own session cookie is gone with it.
        using var meAfter = await browser.GetConsumerAsync("/me");
        Assert.Equal(HttpStatusCode.Redirect, meAfter.StatusCode);
    }

    // ---- The consumer host ----

    private WebApplicationFactory<GenericOidc.Program> CreateConsumerFactory(
        HttpMessageHandler identityHandler) =>
        new WebApplicationFactory<GenericOidc.Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("GenericOidc:Authority", Authority);
            builder.UseSetting("GenericOidc:ClientId", ClientId);
            builder.UseSetting("GenericOidc:ClientSecret", ClientSecret);
            builder.UseSetting("GenericOidc:RedirectUri", RedirectUri);
            builder.UseSetting("GenericOidc:PostLogoutRedirectUri", PostLogoutUri);
            builder.UseSetting("GenericOidc:RequireHttpsMetadata", "false");
            builder.ConfigureTestServices(services =>
            {
                // Route the handler's Discovery/JWKS/token backchannel to the in-memory identity
                // host instead of the network. The built-in OpenIdConnect post-configure runs
                // first and has already built a ConfigurationManager around a real HttpClient, so
                // the injection replaces that manager with one over the in-memory handler — the
                // standard pattern for testing this handler against an in-memory authority.
                services
                    .AddOptions<Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectOptions>("oidc")
                    .PostConfigure(options =>
                    {
                        var backchannel = new HttpClient(identityHandler);
                        options.Backchannel = backchannel;
                        // The same metadata address convention the built-in post-configure uses:
                        // the explicit MetadataAddress when present, otherwise the authority plus
                        // the well-known discovery path.
                        var metadataAddress = options.MetadataAddress
                            ?? options.Authority!.TrimEnd('/') + "/.well-known/openid-configuration";
                        options.ConfigurationManager =
                            new Microsoft.IdentityModel.Protocols.ConfigurationManager<Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration>(
                                metadataAddress,
                                new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfigurationRetriever(),
                                new Microsoft.IdentityModel.Protocols.HttpDocumentRetriever(backchannel)
                                {
                                    RequireHttps = false
                                });
                    });
            });
        });

    // ---- Seeding ----

    private async Task<Guid> SeedUserAndApplicationAsync()
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var credential = await dbContext.PasswordCredentials.AsNoTracking()
            .FirstOrDefaultAsync(item => item.Username == Username, TestContext.Current.CancellationToken);
        Guid accountId;
        if (credential is null)
        {
            accountId = Guid.NewGuid();
            dbContext.Accounts.Add(new AccountEntity
            {
                Id = accountId,
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            });
            dbContext.PasswordCredentials.Add(new PasswordCredentialEntity
            {
                Id = Guid.NewGuid(),
                AccountId = accountId,
                Username = Username,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(Password),
                CreatedAt = DateTimeOffset.UtcNow
            });
        }
        else
        {
            accountId = credential.AccountId;
            var account = await dbContext.Accounts
                .SingleAsync(row => row.Id == accountId, TestContext.Current.CancellationToken);
            account.IsActive = true;
        }

        var application = await dbContext.AppRegistrations
            .Include(app => app.RedirectUris)
            .FirstOrDefaultAsync(app => app.AppId == ClientId, TestContext.Current.CancellationToken);
        if (application is null)
        {
            application = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = ClientId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword(ClientSecret),
                AppName = "Generic OIDC Flow App",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = AudienceMode.PerApplication,
                ClientType = OidcClientType.Confidential,
                AllowAuthorizationCode = true,
                AllowedScopes = "openid profile",
                AllowRefreshToken = false
            };
            dbContext.AppRegistrations.Add(application);
        }

        application.IsActive = true;
        application.AllowAuthorizationCode = true;
        application.AllowedScopes = "openid profile";
        application.AudienceMode = AudienceMode.PerApplication;
        application.ClientType = OidcClientType.Confidential;
        dbContext.AppRedirectUris.RemoveRange(
            dbContext.AppRedirectUris.Where(registration => registration.AppRegistrationId == application.Id));
        dbContext.AppRedirectUris.Add(new AppRedirectUriEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = application.Id,
            Kind = RedirectUriKind.Redirect,
            CanonicalUri = RedirectUri
        });
        dbContext.AppRedirectUris.Add(new AppRedirectUriEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = application.Id,
            Kind = RedirectUriKind.PostLogout,
            CanonicalUri = PostLogoutUri
        });
        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        return accountId;
    }

    private async Task<IdentitySessionEntity?> QuerySessionAsync(Guid accountId)
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        return await dbContext.IdentitySessions.AsNoTracking()
            .Where(row => row.AccountId == accountId)
            .OrderByDescending(row => row.AuthTime)
            .ThenByDescending(row => row.Id)
            .FirstOrDefaultAsync(TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// The handler composes its redirects from the HTTP authority, while the identity-side
    /// browser addresses the same in-memory host over HTTPS so the Secure identity-cookie
    /// profile applies exactly as in every other test. Both schemes reach one server.
    /// </summary>
    private static string ToIdentityBrowserUrl(Uri location) =>
        location.ToString().Replace(Authority + "/", "https://localhost/", StringComparison.Ordinal);

    // ---- One browser over both in-memory hosts, sharing one cookie container ----

    private sealed class CrossOriginBrowser : IDisposable
    {
        private readonly CookieContainer _cookies = new();
        private readonly HttpClient _identity;
        private readonly HttpClient _consumer;

        public CrossOriginBrowser(HttpMessageHandler identityHandler, HttpMessageHandler consumerHandler)
        {
            _identity = NewClient(identityHandler, new Uri("https://localhost"), _cookies);
            _consumer = NewClient(consumerHandler, new Uri(ConsumerBase), _cookies);
        }

        private static HttpClient NewClient(HttpMessageHandler handler, Uri baseAddress, CookieContainer cookies) =>
            new(new CookieSharingHandler(handler, cookies)) { BaseAddress = baseAddress };

        public void Dispose()
        {
            _identity.Dispose();
            _consumer.Dispose();
        }

        public Task<HttpResponseMessage> GetIdentityAsync(string url) =>
            SendAsync(_identity, HttpMethod.Get, url);
        public Task<HttpResponseMessage> GetConsumerAsync(string pathAndQuery) =>
            SendAsync(_consumer, HttpMethod.Get, pathAndQuery);
        public Task<HttpResponseMessage> PostConsumerAsync(string path) =>
            SendAsync(_consumer, HttpMethod.Post, path);

        public async Task<HttpResponseMessage> PostIdentityFormAsync(
            string path, IReadOnlyDictionary<string, string> fields)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, path)
            {
                Content = new FormUrlEncodedContent(fields)
            };
            return await _identity.SendAsync(request, TestContext.Current.CancellationToken);
        }

        private async Task<HttpResponseMessage> SendAsync(HttpClient client, HttpMethod method, string url)
        {
            using var request = new HttpRequestMessage(method, url);
            return await SendAsync(client, request);
        }

        private async Task<HttpResponseMessage> SendAsync(HttpClient client, HttpRequestMessage request)
        {
            var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            return response;
        }

        private sealed class CookieSharingHandler(HttpMessageHandler inner, CookieContainer cookies)
            : DelegatingHandler(inner)
        {
            protected override async Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
            {
                request.Headers.TryAddWithoutValidation(
                    "Cookie", cookies.GetCookieHeader(request.RequestUri!));
                var response = await base.SendAsync(request, cancellationToken);
                if (response.Headers.NonValidated.TryGetValues("Set-Cookie", out var setCookies))
                {
                    foreach (var cookie in setCookies)
                    {
                        try
                        {
                            cookies.SetCookies(request.RequestUri!, cookie);
                        }
                        catch (CookieException)
                        {
                            // A cookie the container refuses (for example a __Host- cookie on a
                            // non-default port) is replayed manually by the assertions instead.
                        }
                    }
                }

                return response;
            }
        }
    }
}
