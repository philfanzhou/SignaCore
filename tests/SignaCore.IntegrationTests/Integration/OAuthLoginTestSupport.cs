using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host;
using SignaCore.Host.Security;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Shared seeding, request, and assertion helpers of the <c>/oauth2/login</c> suites. The
/// continuation canary values are deliberately identifiable so a test can prove the rendered page
/// carries none of the stored authorization-request snapshot values.
/// </summary>
internal static partial class OAuthLoginTestSupport
{
    public const string AppId = "login-contract-app";
    public const string RegisteredUri = "https://bff.login.test/callback?canary=redirect-uri";
    public const string CanaryScope = "openid canary-scope-value";
    public const string CanaryState = "login-canary-state-0123456789";
    public const string CanaryNonce = "login-canary-nonce-0123456789";
    public const string CanaryChallenge = "login-canary-challenge-abcdefghij0123456789";
    public const string FixedCorrelationId = "e2e-correlation-1234567890abcdef";

    // The EV-02 cancel revalidation runs the real validator over the stored snapshot, so its
    // continuations need a legally shaped snapshot and a client the current registration still
    // trusts: a dedicated app whose redirect registration matches the stored URI verbatim. The
    // RFC 7636 appendix B vector doubles as the legal S256 challenge.
    public const string LegalAppId = "login-cancel-app";
    public const string LegalRegisteredUri = "https://bff.cancel.test/callback?tenant=unit";
    public const string LegalScope = "openid profile";
    public const string LegalState = "cancel-legal-state-0123456789abcdef";
    public const string LegalNonce = "cancel-legal-nonce-0123456789abcdef";
    public const string LegalChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    // The EV-01 success flow is driven through the real GET /oauth2/authorize, so its canaries
    // cover every value the accepted request carries: the redirect URI query, the state, the
    // nonce, and the challenge. The RFC 7636 appendix B vector doubles as the legal S256
    // challenge.
    public const string SuccessAppId = "login-success-app";
    public const string SuccessRegisteredUri = "https://bff.success.test/callback?canary=success-redirect";
    public const string SuccessScope = "openid profile";
    public const string SuccessState = "success-canary-state-0123456789";
    public const string SuccessNonce = "success-canary-nonce-0123456789";
    public const string SuccessChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    public const string ExpectedContentSecurityPolicy =
        "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

    public const string ActionFieldName = "action";
    public const string LoginActionValue = "login";
    public const string CancelActionValue = "cancel";

    private static readonly SemaphoreSlim AppSeedLock = new(1, 1);

    public static string CookieName => LoginAntiforgeryDefaults.CookieName;

    public sealed record LoginSession(string Handle, string CookieValue, string Token);

    [GeneratedRegex("name=\"__RequestVerificationToken\" value=\"([^\"]*)\"")]
    private static partial Regex TokenPattern();

    // ---- Seeding ----

    public static async Task<string> SeedContinuationAsync(
        IServiceProvider services,
        DateTimeOffset? createdAt = null,
        bool consumed = false)
    {
        var applicationId = await SeedApplicationAsync(services);
        using var scope = services.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IAuthorizationRequestStore>();
        var creation = await store.CreateAsync(
            new OidcAuthorizationValidationResult.Accepted(
                AppId,
                applicationId,
                RegisteredUri,
                CanaryScope,
                CanaryState,
                CanaryNonce,
                CanaryChallenge),
            createdAt ?? DateTimeOffset.UtcNow.AddMinutes(-1),
            TestContext.Current.CancellationToken);
        if (consumed)
        {
            var consumedResult = await store.TryConsumeAsync(
                creation.LoginHandle,
                DateTimeOffset.UtcNow,
                TestContext.Current.CancellationToken);
            Assert.True(consumedResult);
        }

        return creation.LoginHandle;
    }

    /// <summary>
    /// Seeds a continuation whose stored snapshot revalidates: the client registration still
    /// trusts the exact redirect URI and the snapshot values are all legally shaped, so the
    /// <c>EV-02</c> revalidation reaches the redirect decision instead of a local rejection.
    /// </summary>
    public static async Task<string> SeedLegalContinuationAsync(
        IServiceProvider services,
        DateTimeOffset? createdAt = null)
    {
        var applicationId = await SeedLegalApplicationAsync(services);
        using var scope = services.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IAuthorizationRequestStore>();
        var creation = await store.CreateAsync(
            new OidcAuthorizationValidationResult.Accepted(
                LegalAppId,
                applicationId,
                LegalRegisteredUri,
                LegalScope,
                LegalState,
                LegalNonce,
                LegalChallenge),
            createdAt ?? DateTimeOffset.UtcNow.AddMinutes(-1),
            TestContext.Current.CancellationToken);
        return creation.LoginHandle;
    }

    /// <summary>Begins a browser session over a revalidatable continuation and returns its form values.</summary>
    public static async Task<LoginSession> BeginLegalLoginAsync(
        IServiceProvider services,
        HttpClient client)
    {
        var handle = await SeedLegalContinuationAsync(services);
        using var response = await client.GetAsync(
            $"/oauth2/login?login_handle={handle}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var setCookie = GetSetCookieHeader(response, CookieName);
        Assert.NotNull(setCookie);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var token = TokenPattern().Match(body).Groups[1].Value;
        Assert.False(string.IsNullOrEmpty(token));
        return new LoginSession(handle, CookieValueFromHeader(setCookie!, CookieName), token);
    }

    private static async Task<Guid> SeedLegalApplicationAsync(IServiceProvider services)
    {
        await AppSeedLock.WaitAsync(TestContext.Current.CancellationToken);
        try
        {
            using var scope = services.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var existing = await dbContext.AppRegistrations
                .AsNoTracking()
                .FirstOrDefaultAsync(app => app.AppId == LegalAppId, TestContext.Current.CancellationToken);
            if (existing is not null)
            {
                return existing.Id;
            }

            var app = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = LegalAppId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword("login-cancel-secret"),
                AppName = "Login Cancel App",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = AudienceMode.PerApplication,
                ClientType = OidcClientType.Confidential,
                AllowAuthorizationCode = true,
                AllowedScopes = "openid profile",
                AllowRefreshToken = false
            };
            app.RedirectUris =
            [
                new AppRedirectUriEntity
                {
                    Id = Guid.NewGuid(),
                    AppRegistrationId = app.Id,
                    Kind = RedirectUriKind.Redirect,
                    CanonicalUri = LegalRegisteredUri
                }
            ];
            dbContext.AppRegistrations.Add(app);
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
            return app.Id;
        }
        finally
        {
            AppSeedLock.Release();
        }
    }

    public static async Task<Guid> SeedSuccessApplicationAsync(IServiceProvider services)
    {
        await AppSeedLock.WaitAsync(TestContext.Current.CancellationToken);
        try
        {
            using var scope = services.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var existing = await dbContext.AppRegistrations
                .AsNoTracking()
                .FirstOrDefaultAsync(app => app.AppId == SuccessAppId, TestContext.Current.CancellationToken);
            if (existing is not null)
            {
                return existing.Id;
            }

            var app = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = SuccessAppId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword("login-success-secret"),
                AppName = "Login Success App",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = AudienceMode.PerApplication,
                ClientType = OidcClientType.Confidential,
                AllowAuthorizationCode = true,
                AllowedScopes = SuccessScope,
                AllowRefreshToken = false
            };
            app.RedirectUris =
            [
                new AppRedirectUriEntity
                {
                    Id = Guid.NewGuid(),
                    AppRegistrationId = app.Id,
                    Kind = RedirectUriKind.Redirect,
                    CanonicalUri = SuccessRegisteredUri
                }
            ];
            dbContext.AppRegistrations.Add(app);
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
            return app.Id;
        }
        finally
        {
            AppSeedLock.Release();
        }
    }

    /// <summary>
    /// Drives the real browser front half of <c>SC-01</c>: <c>GET /oauth2/authorize</c> validates
    /// the request, persists the continuation, and redirects to the login page; the login GET
    /// renders the form and issues the antiforgery pair. The client must not auto-redirect. The
    /// optional state/nonce overrides let one browser run two independent continuations whose
    /// snapshots stay distinguishable (<c>SC-07</c>); a browser that already holds a usable
    /// antiforgery cookie is not re-issued one (<c>PS-19</c>), so its value is passed in.
    /// </summary>
    public static async Task<LoginSession> BeginSuccessLoginViaAuthorizeAsync(
        IServiceProvider services,
        HttpClient client,
        string? state = null,
        string? nonce = null,
        string? existingCookieValue = null)
    {
        await SeedSuccessApplicationAsync(services);
        var authorizeUrl = BuildSuccessAuthorizeUrl(state, nonce);

        using var authorize = await client.GetAsync(authorizeUrl, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var location = authorize.Headers.Location!.ToString();
        const string loginPrefix = "/oauth2/login?login_handle=";
        Assert.StartsWith(loginPrefix, location, StringComparison.Ordinal);
        var handle = location[loginPrefix.Length..];

        using var form = await client.GetAsync(
            $"{loginPrefix}{handle}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, form.StatusCode);
        var body = await form.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var token = TokenPattern().Match(body).Groups[1].Value;
        Assert.False(string.IsNullOrEmpty(token));

        var setCookie = GetSetCookieHeader(form, CookieName);
        var cookieValue = setCookie is not null
            ? CookieValueFromHeader(setCookie, CookieName)
            : existingCookieValue;
        Assert.NotNull(cookieValue);
        return new LoginSession(handle, cookieValue!, token);
    }

    /// <summary>
    /// Builds the browser URL of a legal authorize request against the success application; the
    /// optional overrides keep two independent browser runs distinguishable.
    /// </summary>
    public static string BuildSuccessAuthorizeUrl(string? state = null, string? nonce = null) =>
        "/oauth2/authorize?" + string.Join('&', new[]
        {
            ("response_type", "code"),
            ("client_id", SuccessAppId),
            ("redirect_uri", SuccessRegisteredUri),
            ("scope", SuccessScope),
            ("state", state ?? SuccessState),
            ("nonce", nonce ?? SuccessNonce),
            ("code_challenge", SuccessChallenge),
            ("code_challenge_method", "S256"),
        }.Select(pair => $"{Uri.EscapeDataString(pair.Item1)}={Uri.EscapeDataString(pair.Item2)}"));

    /// <summary>
    /// Completes the browser front half of one successful login over the real authorize → login
    /// flow and returns the raw <c>name=value</c> segment of the issued <c>PS-18</c> identity
    /// cookie, for manual replay on later requests; the caller's client must not auto-redirect.
    /// </summary>
    public static async Task<string> CompleteSuccessLoginAndGetIdentityCookieValueAsync(
        IServiceProvider services,
        HttpClient client,
        string username,
        string password)
    {
        var login = await BeginSuccessLoginViaAuthorizeAsync(services, client);
        using var response = await client.SendAsync(
            CreateLoginPost(
                fields: LoginFields(login, username, password),
                cookieHeader: CookieHeaderFor(login)),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var setCookie = GetSetCookieHeader(response, IdentitySessionDefaults.CookieName);
        Assert.NotNull(setCookie);
        return CookieValueFromHeader(setCookie!, IdentitySessionDefaults.CookieName);
    }

    private static async Task<Guid> SeedApplicationAsync(IServiceProvider services)
    {
        await AppSeedLock.WaitAsync(TestContext.Current.CancellationToken);
        try
        {
            using var scope = services.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var existing = await dbContext.AppRegistrations
                .AsNoTracking()
                .FirstOrDefaultAsync(app => app.AppId == AppId, TestContext.Current.CancellationToken);
            if (existing is not null)
            {
                return existing.Id;
            }

            var app = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = AppId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword("login-contract-secret"),
                AppName = "Login Contract App",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = AudienceMode.PerApplication,
                ClientType = OidcClientType.Confidential,
                AllowAuthorizationCode = true,
                AllowedScopes = "openid profile",
                AllowRefreshToken = false
            };
            dbContext.AppRegistrations.Add(app);
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
            return app.Id;
        }
        finally
        {
            AppSeedLock.Release();
        }
    }

    public static async Task<Guid> SeedUserAsync(
        IServiceProvider services,
        string username,
        string password,
        bool isActive = true)
    {
        using var scope = services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var accountId = Guid.NewGuid();
        dbContext.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = isActive,
            CreatedAt = DateTimeOffset.UtcNow
        });
        dbContext.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            Username = username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(password),
            CreatedAt = DateTimeOffset.UtcNow
        });
        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        return accountId;
    }

    /// <summary>Pre-arms the shared failed-attempt counter without going through any route.</summary>
    public static async Task SeedLoginAttemptAsync(
        IServiceProvider services,
        string username,
        int failedAttempts,
        DateTimeOffset? lockoutUntil = null)
    {
        using var scope = services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        dbContext.LoginAttempts.Add(new LoginAttemptEntity
        {
            Id = Guid.NewGuid(),
            Username = username,
            LastAttemptAt = DateTimeOffset.UtcNow,
            FailedAttempts = failedAttempts,
            LockoutUntil = lockoutUntil
        });
        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    // ---- Requests ----

    public static async Task<LoginSession> BeginLoginAsync(
        IServiceProvider services,
        HttpClient client)
    {
        var handle = await SeedContinuationAsync(services);
        using var response = await client.GetAsync(
            $"/oauth2/login?login_handle={handle}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var setCookie = GetSetCookieHeader(response, CookieName);
        Assert.NotNull(setCookie);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var token = TokenPattern().Match(body).Groups[1].Value;
        Assert.False(string.IsNullOrEmpty(token));
        return new LoginSession(handle, CookieValueFromHeader(setCookie!, CookieName), token);
    }

    public static IReadOnlyList<KeyValuePair<string, string>> LoginFields(
        LoginSession session,
        string username,
        string password) =>
    [
        new("login_handle", session.Handle),
        new("username", username),
        new("password", password),
        new(LoginAntiforgeryDefaults.TokenFieldName, session.Token),
        new(ActionFieldName, LoginActionValue),
    ];

    public static IReadOnlyList<KeyValuePair<string, string>> CancelFields(LoginSession session) =>
    [
        new("login_handle", session.Handle),
        new(LoginAntiforgeryDefaults.TokenFieldName, session.Token),
        new(ActionFieldName, CancelActionValue),
    ];

    public static string BuildRawBody(params (string Name, string Value)[] components) =>
        string.Join('&', components.Select(component => $"{component.Name}={component.Value}"));

    public static string BuildEscapedBody(
        IReadOnlyList<KeyValuePair<string, string>> fields) =>
        string.Join('&', fields.Select(field =>
            $"{field.Key}={Uri.EscapeDataString(field.Value)}"));

    public static HttpRequestMessage CreateLoginPost(
        string? rawBody = null,
        IReadOnlyList<KeyValuePair<string, string>>? fields = null,
        byte[]? rawBodyBytes = null,
        string? contentType = "application/x-www-form-urlencoded",
        string? cookieHeader = null,
        string? query = null,
        string? correlationId = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/login" + (query ?? string.Empty));
        var bodyBytes = rawBodyBytes
            ?? Encoding.UTF8.GetBytes(rawBody
                ?? BuildEscapedBody(fields
                    ?? throw new ArgumentException("A raw body or a field list is required.")));
        var content = new ByteArrayContent(bodyBytes);
        if (contentType is not null)
        {
            content.Headers.TryAddWithoutValidation("Content-Type", contentType);
        }

        request.Content = content;
        if (cookieHeader is not null)
        {
            request.Headers.TryAddWithoutValidation("Cookie", cookieHeader);
        }

        if (correlationId is not null)
        {
            request.Headers.TryAddWithoutValidation("x-correlation-id", correlationId);
        }

        return request;
    }

    public static string CookieHeaderFor(LoginSession session) =>
        $"{CookieName}={session.CookieValue}";

    // ---- Response inspection ----

    public static string? GetSetCookieHeader(HttpResponseMessage response, string cookieName)
    {
        if (!response.Headers.NonValidated.TryGetValues("Set-Cookie", out var values))
        {
            return null;
        }

        return values.FirstOrDefault(value =>
            value.StartsWith(cookieName + "=", StringComparison.Ordinal));
    }

    public static string CookieValueFromHeader(string setCookieHeader, string cookieName) =>
        setCookieHeader.Split(';')[0][(cookieName.Length + 1)..];

    public static void AssertLoginSecurityHeaders(HttpResponseMessage response)
    {
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Contains("no-cache", response.Headers.Pragma.ToString(), StringComparison.Ordinal);
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal(
            ExpectedContentSecurityPolicy,
            response.Headers.GetValues("Content-Security-Policy").Single());
        Assert.False(response.Headers.Contains("Location"));
    }

    /// <summary>
    /// The comparable projection of the response header set: everything except the transport
    /// timestamp, so a fixed correlation id makes identical answers produce identical snapshots.
    /// </summary>
    public static IReadOnlyList<KeyValuePair<string, string>> HeaderSnapshot(
        HttpResponseMessage response) =>
        response.Headers
            .Concat(response.Content.Headers)
            .Where(header => !string.Equals(header.Key, "Date", StringComparison.OrdinalIgnoreCase))
            .Select(header => new KeyValuePair<string, string>(
                header.Key,
                string.Join(',', header.Value)))
            .OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .ToList();

    public static string RandomHandle()
    {
        Span<byte> entropy = stackalloc byte[32];
        RandomNumberGenerator.Fill(entropy);
        return Convert.ToBase64String(entropy)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public static IReadOnlyList<string> MalformedHandles(string validHandle) =>
    [
        validHandle[..42],
        validHandle + "a",
        validHandle[..42] + ".",
        validHandle[..42] + "+",
        validHandle[..42] + " ",
        validHandle[..42] + "é",
        string.Empty,
    ];

    public static string TamperLastCharacter(string value)
    {
        var replacement = value[^1] == 'A' ? 'B' : 'A';
        return value[..^1] + replacement;
    }

    // ---- Database inspection ----

    /// <summary>
    /// A deterministic full dump of every table this route may touch, used both as the zero-write
    /// proof and as the sensitive-value scan surface.
    /// </summary>
    public static async Task<string> DumpLoginTablesAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var dump = new StringBuilder();

        foreach (var attempt in await dbContext.LoginAttempts.AsNoTracking()
                     .OrderBy(row => row.Id).ToListAsync(TestContext.Current.CancellationToken))
        {
            dump.Append("attempt|").Append(attempt.Id).Append('|').Append(attempt.Username)
                .Append('|').Append(attempt.UsernameNormalized).Append('|')
                .Append(attempt.FailedAttempts).Append('|')
                .Append(attempt.LockoutUntil?.UtcTicks).AppendLine();
        }

        foreach (var history in await dbContext.LoginHistories.AsNoTracking()
                     .OrderBy(row => row.Id).ToListAsync(TestContext.Current.CancellationToken))
        {
            dump.Append("history|").Append(history.Id).Append('|').Append(history.AccountId)
                .Append('|').Append(history.Username).Append('|').Append(history.AuthMethod)
                .Append('|').Append(history.EventType).Append('|').Append(history.FailureReason)
                .Append('|').Append(history.AppId).Append('|').Append(history.CorrelationId)
                .AppendLine();
        }

        foreach (var audit in await dbContext.AuditLogs.AsNoTracking()
                     .OrderBy(row => row.Id).ToListAsync(TestContext.Current.CancellationToken))
        {
            dump.Append("audit|").Append(audit.Id).Append('|').Append(audit.Action).Append('|')
                .Append(audit.TargetType).Append('|').Append(audit.TargetId).Append('|')
                .Append(audit.Description).AppendLine();
        }

        foreach (var continuation in await dbContext.AuthorizationRequests.AsNoTracking()
                     .OrderBy(row => row.Id).ToListAsync(TestContext.Current.CancellationToken))
        {
            dump.Append("continuation|").Append(continuation.Id).Append('|')
                .Append(continuation.ConsumedAt?.UtcTicks).AppendLine();
        }

        return dump.ToString();
    }

    public static async Task<List<LoginHistoryEntity>> GetLoginHistoriesAsync(
        IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        return await dbContext.LoginHistories.AsNoTracking()
            .OrderBy(row => row.CreatedAt).ThenBy(row => row.Id)
            .ToListAsync(TestContext.Current.CancellationToken);
    }

    public static async Task<List<LoginAttemptEntity>> GetLoginAttemptsAsync(
        IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        return await dbContext.LoginAttempts.AsNoTracking()
            .OrderBy(row => row.Id)
            .ToListAsync(TestContext.Current.CancellationToken);
    }

    // ---- Derived hosts ----

    public static WebApplicationFactory<Program> CreateHostWithCountingValidator(
        this IdentityServerFixture fixture,
        CountingPasswordValidator counter) =>
        fixture.WithTestServices(services =>
        {
            services.RemoveAll<IIdentityValidator>();
            services.AddSingleton<IIdentityValidator>(counter);
        });
}

/// <summary>
/// The counting stand-in that replaces every <see cref="IIdentityValidator"/> on a derived host:
/// a call counter plus the last received request, so a test can prove both that the shared
/// Password validator was never reached and, when it was reached, which raw values it saw.
/// </summary>
internal sealed class CountingPasswordValidator : IIdentityValidator
{
    private int _calls;

    public ValidationRequest? LastRequest { get; private set; }

    public int Calls => Volatile.Read(ref _calls);

    public string GrantType => IdentityConstants.GrantTypePassword;

    public Task<ValidationResult> ValidateAsync(ValidationRequest request)
    {
        LastRequest = request;
        Interlocked.Increment(ref _calls);
        return Task.FromResult(ValidationResult.Failure("Wrong username or password"));
    }
}
