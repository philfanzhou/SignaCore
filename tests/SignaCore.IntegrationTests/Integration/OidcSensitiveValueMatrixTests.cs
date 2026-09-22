using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Domain.Services;
using SignaCore.Host;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The per-carrier scan harness of the sensitive-value matrix (issue #306): one place that holds
/// every captured carrier — logs (with their structured properties rendered), response bodies and
/// headers, the database dump, and the metric labels — answers whether any raw canary value
/// reached any of them, and proves the detection itself is not a tautology.
/// </summary>
internal sealed class CarrierScan
{
    private readonly string[] _canaries;

    public CarrierScan(params string[] canaries)
    {
        _canaries = canaries;
    }

    public List<string> Logs { get; } = [];

    public List<(string Label, string BodyOrHeader)> HttpSurfaces { get; } = [];

    public string DatabaseDump { get; set; } = string.Empty;

    public List<string> MetricLabelValues { get; } = [];

    /// <summary>Every canary that appeared in a captured carrier, with the carrier named.</summary>
    public List<string> FindViolations()
    {
        var violations = new List<string>();
        foreach (var canary in _canaries)
        {
            if (Logs.Any(text => text.Contains(canary, StringComparison.Ordinal)))
            {
                violations.Add($"{canary}: logs");
            }

            if (HttpSurfaces.Any(surface => surface.BodyOrHeader.Contains(canary, StringComparison.Ordinal)))
            {
                violations.Add($"{canary}: http");
            }

            if (DatabaseDump.Contains(canary, StringComparison.Ordinal))
            {
                violations.Add($"{canary}: database");
            }

            if (MetricLabelValues.Any(value => value.Contains(canary, StringComparison.Ordinal)))
            {
                violations.Add($"{canary}: metric-labels");
            }
        }

        return violations;
    }

    public void AssertClean() => Assert.Empty(FindViolations());
}

/// <summary>
/// The sensitive-value canary matrix over every interactive OIDC path (issue #306): authorize,
/// login, token redemption, UserInfo, logout preparation and completion, and the interactive
/// refresh grant. Each DF-named sensitive value gets a unique synthetic canary, is carried
/// through the real endpoints, and then must not appear — raw — in any tested carrier: the
/// captured structured logs and exception messages, the response bodies and headers outside
/// their contracted surfaces, the <c>audit_logs</c>/<c>login_histories</c> dump, or any metric
/// label value. The browser boundary headers and the login page's final framing value are
/// asserted centrally, and the matrix's detection power is proven by an injected violation.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed partial class OidcSensitiveValueMatrixTests : IClassFixture<IdentityServerFixture>
{
    private const string ClientId = "scan-matrix-app";
    private const string ClientSecret = "scan-matrix-secret-canary";
    private const string Username = "scan_matrix_user";
    private const string RedirectUri = "https://bff.scan-matrix.test/callback";

    private static readonly string CanaryPassword = $"pw-{Guid.NewGuid():N}";
    private static readonly string CanaryVerifier = $"vf-{Guid.NewGuid():N}";
    private static readonly string CanaryCode = $"cd-{Guid.NewGuid():N}";
    private static readonly string CanaryBearer = $"br-{Guid.NewGuid():N}";
    private static readonly string CanaryRefresh = $"rf-{Guid.NewGuid():N}";
    private static readonly string CanaryHandle = $"hd-{Guid.NewGuid():N}";
    private static readonly string CanaryNonce = $"nc-{Guid.NewGuid():N}";
    private static readonly string CanaryState = $"st-{Guid.NewGuid():N}";
    private static readonly string CanaryHint = $"ih-{Guid.NewGuid():N}";

    private readonly IdentityServerFixture _fixture;

    public OidcSensitiveValueMatrixTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task EveryInteractivePath_KeepsEveryCanaryOutOfEveryCarrier()
    {
        await SeedAsync();
        var capture = new CapturingLoggerProvider();
        var metricLabels = new MetricLabelCapture();
        using var host = CreateHost(capture, metricLabels.Configure);
        using var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        var scan = new CarrierScan(
            CanaryPassword,
            CanaryVerifier,
            CanaryCode,
            CanaryBearer,
            CanaryRefresh,
            CanaryHandle,
            CanaryNonce,
            CanaryState,
            CanaryHint,
            ClientSecret);

        // ---- authorize: canary state/nonce ride the request; the challenge is not submitted ----
        using var authorize = await client.GetAsync(
            "/oauth2/authorize?" + string.Join('&',
                $"client_id={ClientId}",
                $"redirect_uri={Uri.EscapeDataString(RedirectUri)}",
                "response_type=code",
                "scope=openid",
                $"state={CanaryState}",
                $"nonce={CanaryNonce}",
                "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method=S256"),
            TestContext.Current.CancellationToken);
        scan.HttpSurfaces.Add(("authorize-location", authorize.Headers.Location?.ToString() ?? string.Empty));

        // ---- token: canary code, verifier, Basic client secret, and canary refresh member ----
        using var tokenClient = host.CreateClient();
        tokenClient.DefaultRequestHeaders.Authorization = BasicHeader(ClientId, ClientSecret);
        using var redeem = await tokenClient.PostAsync(
            "/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = CanaryCode,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = CanaryVerifier
            }),
            TestContext.Current.CancellationToken);
        scan.HttpSurfaces.Add(("redeem-body", await redeem.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)));

        using var refresh = await tokenClient.PostAsync(
            "/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = CanaryRefresh
            }),
            TestContext.Current.CancellationToken);
        scan.HttpSurfaces.Add(("refresh-body", await refresh.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)));

        // ---- userinfo: canary bearer, the signature-failure exception path included ----
        using var userinfo = await client.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, "/oauth2/userinfo")
            {
                Headers = { Authorization = new AuthenticationHeaderValue("Bearer", CanaryBearer) }
            },
            TestContext.Current.CancellationToken);
        scan.HttpSurfaces.Add(("userinfo-headers", string.Join(';', userinfo.Headers.ToString())));

        // ---- logout: canary id_token_hint on prepare, canary handle on complete ----
        using var prepared = await tokenClient.PostAsync(
            "/oauth2/logout/requests",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["id_token_hint"] = CanaryHint,
                ["state"] = CanaryState
            }),
            TestContext.Current.CancellationToken);
        scan.HttpSurfaces.Add(("prepare-body", await prepared.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)));

        using var completed = await client.GetAsync(
            $"/oauth2/logout?handle={CanaryHandle}", TestContext.Current.CancellationToken);
        scan.HttpSurfaces.Add(("complete-body", await completed.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)));

        // ---- login: the canary password through the local failure paths ----
        var handle = await SeedContinuationAsync(host.Services);
        using var form = await client.GetAsync(
            $"/oauth2/login?login_handle={handle}", TestContext.Current.CancellationToken);
        var html = await form.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var token = TokenPattern().Match(html).Groups[1].Value;
        var setCookie = GetSetCookieHeader(form, CookieName);
        Assert.NotNull(setCookie);
        var session = new LoginSession(handle, CookieValueFromHeader(setCookie!, CookieName), token);
        using var failure = await client.SendAsync(
            CreateLoginPost(
                fields: LoginFields(session, Username, CanaryPassword + "-wrong"),
                cookieHeader: CookieHeaderFor(session)),
            TestContext.Current.CancellationToken);
        scan.HttpSurfaces.Add(("login-failure-body", await failure.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)));

        // ---- the exception path: a persistence (audit) failure inside the committed login ----
        using var faultHost = CreateHost(capture, metricLabels.Configure, faultingAudit: true);
        using var faultClient = faultHost.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        var faultHandle = await SeedContinuationAsync(faultHost.Services);
        using var faultForm = await faultClient.GetAsync(
            $"/oauth2/login?login_handle={faultHandle}", TestContext.Current.CancellationToken);
        var faultHtml = await faultForm.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var faultToken = TokenPattern().Match(faultHtml).Groups[1].Value;
        var faultCookie = GetSetCookieHeader(faultForm, CookieName);
        var faultSession = new LoginSession(
            faultHandle,
            CookieValueFromHeader(faultCookie!, CookieName),
            faultToken);
        using var faultPost = await faultClient.SendAsync(
            CreateLoginPost(
                fields: LoginFields(faultSession, Username, CanaryPassword),
                cookieHeader: CookieHeaderFor(faultSession)),
            TestContext.Current.CancellationToken);
        // The rolled-back unit answers non-2xx; the logged exception is a tested carrier.
        Assert.False(faultPost.IsSuccessStatusCode);

        // ---- gather the carriers ----
        scan.Logs.AddRange(capture.Messages);
        scan.DatabaseDump = await DumpAsync(host.Services);
        metricLabels.CopyValuesInto(scan.MetricLabelValues);

        // The captures are proven non-empty: the flow wrote logs, audit/history rows, and metrics.
        Assert.NotEmpty(scan.Logs);
        Assert.Contains("oidc_login", scan.DatabaseDump, StringComparison.Ordinal);
        Assert.NotEmpty(scan.MetricLabelValues);

        scan.AssertClean();
    }

    [Theory]
    [InlineData("/oauth2/authorize?client_id=scan-matrix-app&redirect_uri=https%3A%2F%2Fbff.scan-matrix.test%2Fcallback&response_type=code&scope=openid&state=st&nonce=nc&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")]
    [InlineData("/oauth2/login?login_handle=unknown-handle-value-0123456789")]
    [InlineData("/oauth2/logout?handle=unknown-handle-value-0123456789")]
    [InlineData("/oauth2/userinfo")]
    public async Task BrowserFacingResponses_CarryTheCentralSecurityHeaders(string path)
    {
        using var host = CreateHost(new CapturingLoggerProvider(), _ => { });
        using var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using var response = await client.GetAsync(path, TestContext.Current.CancellationToken);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());

        // The login page's final framing value: the antiforgery middleware's own header wins
        // over any conflicting directive — the assertion pins the effective value documented
        // in LoginAntiforgeryDefaults, whatever the final resolution turns out to be.
        if (path.StartsWith("/oauth2/login", StringComparison.Ordinal))
        {
            Assert.Equal(
                "DENY",
                response.Headers.GetValues("X-Frame-Options").Single());
        }
    }

    [Fact]
    public void TheScanDetectsAnInjectedViolation()
    {
        // The negative self-check: a canary deliberately placed in each carrier must be found,
        // so a green matrix is evidence of absence, not of a blind assertion.
        var scan = new CarrierScan(CanaryPassword);
        scan.Logs.Add($"info: login failed with {CanaryPassword}");
        Assert.Contains($"{CanaryPassword}: logs", scan.FindViolations());

        scan = new CarrierScan(CanaryCode);
        scan.HttpSurfaces.Add(("body", $"error: {CanaryCode}"));
        Assert.Contains($"{CanaryCode}: http", scan.FindViolations());

        scan = new CarrierScan(CanaryNonce);
        scan.DatabaseDump = $"nonce={CanaryNonce}";
        Assert.Contains($"{CanaryNonce}: database", scan.FindViolations());

        scan = new CarrierScan(CanaryBearer);
        scan.MetricLabelValues.Add(CanaryBearer);
        Assert.Contains($"{CanaryBearer}: metric-labels", scan.FindViolations());

        // And the untouched harness stays clean.
        Assert.Empty(new CarrierScan(CanaryPassword).FindViolations());
    }

    // ---- Helpers ----

    [System.Text.RegularExpressions.GeneratedRegex("name=\"__RequestVerificationToken\" value=\"([^\"]*)\"")]
    private static partial System.Text.RegularExpressions.Regex TokenPattern();

    private WebApplicationFactory<Program> CreateHost(
        CapturingLoggerProvider capture,
        Action<IServiceCollection> extra,
        bool faultingAudit = false) =>
        _fixture.WithTestServices(services =>
        {
            services.RemoveAll<ILoggerFactory>();
            services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
            {
                logging.AddProvider(capture);
                logging.SetMinimumLevel(LogLevel.Information);
                // The production Serilog composition keeps the framework hosting category at
                // Warning and serves the access-log carrier through the request-logging
                // middleware, which records method and path only — never the query string. The
                // scan asserts the same shape: whatever request lines appear in the capture
                // carry no raw query value.
                logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
                logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning);
            }));
            if (faultingAudit)
            {
                services.RemoveAll<IAuditService>();
                services.AddSingleton<IAuditService>(new ThrowingAuditService());
            }

            extra(services);
        });

    private sealed class ThrowingAuditService : IAuditService
    {
        public Task RecordLoginAsync(
            Guid? accountId, string username, string authMethod, string eventType,
            string? clientIp, string? userAgent, string? failureReason = null, string? appId = null,
            string? correlationId = null, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task RecordActionAsync(
            string action, string targetType, string targetId, Guid? actorId, string? actorName,
            string? description, string? clientIp = null, string? correlationId = null,
            object? before = null, object? after = null,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Injected persistence failure.");
    }

    private async Task SeedAsync()
    {
        using var scope = _fixture.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var application = await context.AppRegistrations
            .FirstOrDefaultAsync(row => row.AppId == ClientId, TestContext.Current.CancellationToken);
        if (application is null)
        {
            application = new Database.Entity.AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = ClientId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword(ClientSecret),
                AppName = "Scan Matrix App",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = Database.Entity.AudienceMode.PerApplication,
                ClientType = Database.Entity.OidcClientType.Confidential,
                AllowAuthorizationCode = true,
                AllowedScopes = "openid profile",
                AllowRefreshToken = true
            };
            context.AppRegistrations.Add(application);
            context.AppRedirectUris.Add(new Database.Entity.AppRedirectUriEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = application.Id,
                Kind = Database.Entity.RedirectUriKind.Redirect,
                CanonicalUri = RedirectUri
            });
        }

        application.IsActive = true;
        application.AllowAuthorizationCode = true;
        application.AllowRefreshToken = true;

        var credential = await context.PasswordCredentials
            .FirstOrDefaultAsync(row => row.Username == Username, TestContext.Current.CancellationToken);
        if (credential is null)
        {
            var accountId = Guid.NewGuid();
            context.Accounts.Add(new Database.Entity.AccountEntity
            {
                Id = accountId,
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            });
            context.PasswordCredentials.Add(new Database.Entity.PasswordCredentialEntity
            {
                Id = Guid.NewGuid(),
                AccountId = accountId,
                Username = Username,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(CanaryPassword),
                CreatedAt = DateTimeOffset.UtcNow
            });
        }

        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();
    }

    private static async Task<string> DumpAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var audits = (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                context, TestContext.Current.CancellationToken))
            .OrderBy(row => row.Id)
            .ToList();
        var histories = await context.LoginHistories.AsNoTracking()
            .OrderBy(row => row.Id)
            .ToListAsync(TestContext.Current.CancellationToken);
        var builder = new StringBuilder();
        foreach (var row in audits)
        {
            builder.Append("audit:").Append(row.Action).Append('|').Append(row.TargetType)
                .Append('|').Append(row.TargetId).Append('|').Append(row.SecurityDescription)
                .Append('|').Append(row.OperatorDisplayName)
                .AppendLine();
        }

        foreach (var row in histories)
        {
            builder.Append("history:").Append(row.Username).Append('|').Append(row.AuthMethod)
                .Append('|').Append(row.EventType).Append('|').Append(row.FailureReason).AppendLine();
        }

        return builder.ToString();
    }

    private static AuthenticationHeaderValue BasicHeader(string id, string secret) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}")));

    /// <summary>
    /// Captures every log message — including the rendered structured properties and the full
    /// exception text, which is the exception-message carrier.
    /// </summary>
    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<string> _messages = new();

        public IReadOnlyCollection<string> Messages => _messages;

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, _messages);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(
            string categoryName,
            ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                var message = formatter(state, exception);
                messages.Enqueue(exception is null
                    ? $"[{logLevel}] {categoryName}: {message}"
                    : $"[{logLevel}] {categoryName}: {message}{Environment.NewLine}{exception}");
            }
        }
    }

    /// <summary>Collects every label value the process's SignaCore meter records.</summary>
    private sealed class MetricLabelCapture : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly ConcurrentQueue<string> _values = new();

        public MetricLabelCapture()
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == "SignaCore")
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };
            _listener.SetMeasurementEventCallback<int>((_, _, tags, _) => Record(tags));
            _listener.SetMeasurementEventCallback<double>((_, _, tags, _) => Record(tags));
            _listener.SetMeasurementEventCallback<long>((_, _, tags, _) => Record(tags));
            _listener.Start();
        }

        public Action<IServiceCollection> Configure => _ => { };

        public void CopyValuesInto(List<string> target)
        {
            _listener.RecordObservableInstruments();
            target.AddRange(_values);
        }

        private void Record(ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            foreach (var tag in tags)
            {
                if (tag.Value is not null)
                {
                    _values.Enqueue(tag.Value.ToString()!);
                }
            }
        }

        public void Dispose() => _listener.Dispose();
    }
}
