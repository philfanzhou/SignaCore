using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Net;
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
using SignaCore.Domain.Services.Sms;
using SignaCore.Host;
using SignaCore.Host.Security;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Seeding, request, and inspection helpers of the browser SMS send route and SMS login suites
/// (#444, #445). Every
/// application, continuation, and phone is unique per test, so tests sharing one fixture database
/// never observe each other's rows.
/// </summary>
internal static partial class OAuthLoginSmsCodeTestSupport
{
    public const string SendPath = "/oauth2/login/sms-code";
    public const string ProfileKey = "sms-send-test";
    public const string RedirectUri = "https://bff.sms-send.test/callback";
    public const string FixedCorrelationId = "sms-send-correlation-0123456789abcdef";

    public const string EnglishSentNotice =
        "<p role=\"status\" id=\"sms-notice\" class=\"notice\">If this phone number can sign in to this application, a verification code has been sent.</p>";

    public const string ChineseSentNotice = "<p role=\"status\" id=\"sms-notice\" class=\"notice\">如果此手机号可以登录该应用，验证码已发送。</p>";

    public const string EnglishInvalidPhoneNotice = "<p role=\"alert\" id=\"sms-notice\" class=\"notice\">Enter a valid mainland China mobile number.</p>";

    public const string EnglishSmsFailureNotice =
        "<p role=\"alert\" id=\"sms-notice\" class=\"notice\">Sign-in failed. Check your mobile number and verification code and try again, or request a new code.</p>";

    public const string ChineseSmsFailureNotice = "<p role=\"alert\" id=\"sms-notice\" class=\"notice\">登录失败。请检查手机号和验证码后重试，或重新获取验证码。</p>";

    /// <summary>The always empty one-time-code input of the SMS region (<c>DF-17</c>).</summary>
    public const string OtpInput =
        "<input type=\"text\" id=\"otp\" name=\"otp\" inputmode=\"numeric\" autocomplete=\"one-time-code\" maxlength=\"16\" required>";

    /// <summary>The unnamed send button: it posts the SMS form to the send route without validation.</summary>
    public const string SendButton = "<button type=\"submit\" formaction=\"/oauth2/login/sms-code\" formnovalidate>";

    public const string SmsSubmitButton = "<button type=\"submit\" name=\"action\" value=\"sms_login\">";

    /// <summary>The phone input of the SMS region re-rendered with <paramref name="value"/>.</summary>
    public static string PhoneInput(string value) =>
        "<input type=\"tel\" id=\"phone\" name=\"phone\" autocomplete=\"tel\" maxlength=\"32\" value=\"" + value + "\" required>";

    public sealed record SmsApp(Guid Id, string AppId);

    public sealed record SmsSession(string Handle, string CookieValue, string Token, Guid ContinuationId);

    [GeneratedRegex("name=\"__RequestVerificationToken\" value=\"([^\"]*)\"")]
    private static partial Regex TokenPattern();

    /// <summary>Replaces every rendered request token of <paramref name="body"/> with <paramref name="token"/>.</summary>
    public static string WithRequestToken(string body, string token) =>
        TokenPattern().Replace(body, "name=\"__RequestVerificationToken\" value=\"" + token + "\"");

    /// <summary>A fresh mainland mobile number, unique per call, in its bare 11-digit form.</summary>
    public static string NewPhone() =>
        "139" + Random.Shared.NextInt64(0, 100_000_000).ToString("D8", System.Globalization.CultureInfo.InvariantCulture);

    public static string E164(string phone) => "+86" + phone;

    public static SmsOptions CreateSmsOptions() => new()
    {
        OtpHmacKey = Convert.ToBase64String(Enumerable.Range(7, 32).Select(value => (byte)value).ToArray()),
        MinSendIntervalSeconds = 60,
        MaxSendsPerHour = 5,
        MaxSendsPerDay = 10,
        Profiles = new Dictionary<string, SmsProviderProfile>(StringComparer.OrdinalIgnoreCase)
        {
            [ProfileKey] = new() { Provider = FakeSmsSender.ProviderName }
        }
    };

    /// <summary>
    /// A derived host of the shared fixture database whose SMS profile resolves to
    /// <paramref name="sender"/>. Each host starts with empty limiter state.
    /// </summary>
    public static WebApplicationFactory<Program> CreateSmsHost(
        this IdentityServerFixture fixture,
        FakeSmsSender sender,
        Action<IServiceCollection>? configure = null) =>
        fixture.WithTestServices(services =>
        {
            services.Replace(ServiceDescriptor.Singleton(CreateSmsOptions()));
            services.AddSingleton<ISmsSender>(sender);
            configure?.Invoke(services);
        });

    public static HttpClient CreateBrowserClient(this WebApplicationFactory<Program> host) =>
        host.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = false
        });

    public static async Task<SmsApp> SeedSmsAppAsync(
        IServiceProvider services,
        SmsLoginMode mode,
        string? profileKey = ProfileKey,
        string? clientSecret = null)
    {
        using var scope = services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "sms-send-" + Guid.NewGuid().ToString("N")[..16],
            AppSecretHash = clientSecret is null ? "unused-sms-send-hash" : BCrypt.Net.BCrypt.HashPassword(clientSecret, 4),
            AppName = "SMS Send App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = AudienceMode.PerApplication,
            ClientType = OidcClientType.Confidential,
            AllowAuthorizationCode = true,
            AllowedScopes = "openid profile",
            AllowRefreshToken = false,
            SmsLoginMode = mode,
            SmsProfileKey = profileKey
        };
        app.RedirectUris =
        [
            new AppRedirectUriEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = app.Id,
                Kind = RedirectUriKind.Redirect,
                CanonicalUri = RedirectUri
            }
        ];
        dbContext.AppRegistrations.Add(app);
        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        return new SmsApp(app.Id, app.AppId);
    }

    public static async Task<(string Handle, Guid Id)> SeedContinuationAsync(
        IServiceProvider services,
        SmsApp app,
        DateTimeOffset? createdAt = null,
        string scopeValue = "openid")
    {
        using var scope = services.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IAuthorizationRequestStore>();
        var creation = await store.CreateAsync(
            new OidcAuthorizationValidationResult.Accepted(
                app.AppId,
                app.Id,
                RedirectUri,
                scopeValue,
                "sms-send-state-" + Guid.NewGuid().ToString("N"),
                "sms-send-nonce-" + Guid.NewGuid().ToString("N"),
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
            createdAt ?? DateTimeOffset.UtcNow.AddMinutes(-1),
            TestContext.Current.CancellationToken);
        return (creation.LoginHandle, creation.Id);
    }

    /// <summary>Renders the login page for a fresh continuation and returns its form values.</summary>
    public static async Task<SmsSession> BeginAsync(
        IServiceProvider services, HttpClient client, SmsApp app, string scope = "openid")
    {
        var (handle, id) = await SeedContinuationAsync(services, app, scopeValue: scope);
        using var response = await client.GetAsync(
            $"/oauth2/login?login_handle={handle}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var setCookie = OAuthLoginTestSupport.GetSetCookieHeader(response, LoginAntiforgeryDefaults.CookieName);
        Assert.NotNull(setCookie);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var token = TokenPattern().Match(body).Groups[1].Value;
        Assert.False(string.IsNullOrEmpty(token));
        return new SmsSession(
            handle,
            OAuthLoginTestSupport.CookieValueFromHeader(setCookie!, LoginAntiforgeryDefaults.CookieName),
            token,
            id);
    }

    public static IReadOnlyList<KeyValuePair<string, string>> SendFields(
        SmsSession session,
        string phone,
        string? handle = null,
        string? token = null) =>
    [
        new("login_handle", handle ?? session.Handle),
        new(LoginAntiforgeryDefaults.TokenFieldName, token ?? session.Token),
        new("phone", phone),
    ];

    /// <summary>The fields the SMS form posts with its <c>sms_login</c> button.</summary>
    public static IReadOnlyList<KeyValuePair<string, string>> SmsLoginFields(
        SmsSession session,
        string phone,
        string otp,
        string? handle = null,
        string? token = null) =>
    [
        new("login_handle", handle ?? session.Handle),
        new(LoginAntiforgeryDefaults.TokenFieldName, token ?? session.Token),
        new("phone", phone),
        new("otp", otp),
        new("action", "sms_login"),
    ];

    public static string CookieHeader(SmsSession session) =>
        $"{LoginAntiforgeryDefaults.CookieName}={session.CookieValue}";

    public static HttpRequestMessage SendPost(
        SmsSession? session,
        IReadOnlyList<KeyValuePair<string, string>>? fields = null,
        string? rawBody = null,
        byte[]? rawBodyBytes = null,
        string? contentType = "application/x-www-form-urlencoded",
        string? query = null,
        bool withCookie = true,
        string? acceptLanguage = null,
        string correlationId = FixedCorrelationId,
        string path = SendPath)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path + (query ?? string.Empty));
        var bytes = rawBodyBytes ?? Encoding.UTF8.GetBytes(rawBody
            ?? OAuthLoginTestSupport.BuildEscapedBody(fields ?? throw new ArgumentException("A body is required.")));
        var content = new ByteArrayContent(bytes);
        if (contentType is not null)
        {
            content.Headers.TryAddWithoutValidation("Content-Type", contentType);
        }

        request.Content = content;
        if (withCookie && session is not null)
        {
            request.Headers.TryAddWithoutValidation("Cookie", CookieHeader(session));
        }

        if (acceptLanguage is not null)
        {
            request.Headers.TryAddWithoutValidation("Accept-Language", acceptLanguage);
        }

        request.Headers.TryAddWithoutValidation("x-correlation-id", correlationId);
        return request;
    }

    // ---- Database arrangement ----

    public static async Task WithDbAsync(IServiceProvider services, Func<IdentityDbContext, Task> action)
    {
        using var scope = services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        await action(dbContext);
    }

    public static async Task<T> QueryDbAsync<T>(IServiceProvider services, Func<IdentityDbContext, Task<T>> query)
    {
        using var scope = services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        return await query(dbContext);
    }

    /// <summary>Removes every identity, admission, and OTP row of one normalized phone.</summary>
    public static Task ResetPhoneAsync(IServiceProvider services, string phoneE164) =>
        WithDbAsync(services, async db =>
        {
            var ct = TestContext.Current.CancellationToken;
            var logins = await db.UserLogins.Where(row => row.ProviderUserId == phoneE164)
                .Select(row => new { row.Id, row.AccountId }).ToListAsync(ct);
            var loginIds = logins.Select(row => row.Id).ToList();
            var accountIds = logins.Select(row => row.AccountId).ToList();
            await db.AppSmsAccesses.Where(row => loginIds.Contains(row.UserLoginId)).ExecuteDeleteAsync(ct);
            await db.Otps.Where(row => row.Phone == phoneE164).ExecuteDeleteAsync(ct);
            await db.UserLogins.Where(row => loginIds.Contains(row.Id)).ExecuteDeleteAsync(ct);
            await db.Accounts.Where(row => accountIds.Contains(row.Id)).ExecuteDeleteAsync(ct);
        });

    public static Task<Guid> SeedIdentityAsync(
        IServiceProvider services,
        string phoneE164,
        bool accountActive = true,
        (Guid AppRegistrationId, SmsAccessApprovalSource Source, bool Active)? admission = null) =>
        QueryDbAsync(services, async db =>
        {
            var accountId = Guid.NewGuid();
            var loginId = Guid.NewGuid();
            db.Accounts.Add(new AccountEntity { Id = accountId, IsActive = accountActive, CreatedAt = DateTimeOffset.UtcNow });
            db.UserLogins.Add(new UserLoginEntity
            {
                Id = loginId,
                AccountId = accountId,
                ProviderName = IdentityConstants.AuthMethodSms,
                ProviderUserId = phoneE164
            });
            if (admission is { } row)
            {
                db.AppSmsAccesses.Add(new AppSmsAccessEntity
                {
                    Id = Guid.NewGuid(),
                    AppRegistrationId = row.AppRegistrationId,
                    UserLoginId = loginId,
                    ApprovalSource = row.Source,
                    IsActive = row.Active,
                    CreatedAt = DateTimeOffset.UtcNow
                });
            }

            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
            return accountId;
        });

    public static Task SeedOtpAsync(IServiceProvider services, Guid appRegistrationId, string phoneE164, Action<OtpEntity> shape) =>
        WithDbAsync(services, async db =>
        {
            var now = DateTimeOffset.UtcNow;
            var otp = new OtpEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = appRegistrationId,
                Phone = phoneE164,
                CodeMac = new string('A', 64),
                Status = OtpStatus.Sent,
                ExpiresAt = now.AddMinutes(5),
                LockoutUntil = DateTimeOffset.UnixEpoch,
                CreatedAt = now.AddHours(-2),
                HourWindowStartedAt = now.AddHours(-2),
                HourSendCount = 1,
                DayWindowStartedAt = now.AddHours(-2),
                DaySendCount = 1,
                Provider = FakeSmsSender.ProviderName,
                ProfileKey = ProfileKey,
                Version = 1
            };
            shape(otp);
            db.Otps.Add(otp);
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        });

    public static Task SetApplicationAsync(IServiceProvider services, Guid appRegistrationId, SmsLoginMode mode, string? profileKey) =>
        WithDbAsync(services, db => db.AppRegistrations.Where(row => row.Id == appRegistrationId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.SmsLoginMode, mode)
                .SetProperty(row => row.SmsProfileKey, profileKey), TestContext.Current.CancellationToken));

    public static Task SetCountAsync(IServiceProvider services, Guid continuationId, int count) =>
        WithDbAsync(services, db => db.AuthorizationRequests.Where(row => row.Id == continuationId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.SmsCodeSendCount, count),
                TestContext.Current.CancellationToken));

    public static Task<int> CountAsync(IServiceProvider services, Guid continuationId) =>
        QueryDbAsync(services, db => db.AuthorizationRequests.AsNoTracking()
            .Where(row => row.Id == continuationId)
            .Select(row => row.SmsCodeSendCount)
            .SingleAsync(TestContext.Current.CancellationToken));

    public static Task<OtpEntity?> OtpAsync(IServiceProvider services, Guid appRegistrationId, string phoneE164) =>
        QueryDbAsync(services, db => db.Otps.AsNoTracking()
            .SingleOrDefaultAsync(row => row.AppRegistrationId == appRegistrationId && row.Phone == phoneE164,
                TestContext.Current.CancellationToken));

    public static Task<List<LoginHistoryEntity>> SmsHistoriesAsync(IServiceProvider services, string appId) =>
        QueryDbAsync(services, db => db.LoginHistories.AsNoTracking()
            .Where(row => row.AppId == appId)
            .OrderBy(row => row.CreatedAt).ThenBy(row => row.Id)
            .ToListAsync(TestContext.Current.CancellationToken));

    public static Task<int> PhoneIdentityRowCountAsync(IServiceProvider services, string phoneE164) =>
        QueryDbAsync(services, async db =>
            await db.UserLogins.CountAsync(row => row.ProviderUserId == phoneE164, TestContext.Current.CancellationToken)
            + await db.AppSmsAccesses.CountAsync(
                row => db.UserLogins.Any(login => login.Id == row.UserLoginId && login.ProviderUserId == phoneE164),
                TestContext.Current.CancellationToken));

    /// <summary>The comparable answer of one request: status, headers (without Date), and body.</summary>
    public static async Task<(HttpStatusCode Status, IReadOnlyList<KeyValuePair<string, string>> Headers, string Body)> ReadAnswerAsync(
        HttpResponseMessage response) =>
        (response.StatusCode,
            OAuthLoginTestSupport.HeaderSnapshot(response),
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
}

/// <summary>
/// The SMS provider stand-in: records every delivery request and answers with a configurable
/// behavior. Its provider name is registered only by the test profile.
/// </summary>
internal sealed class FakeSmsSender : ISmsSender
{
    public const string ProviderName = "IntegrationFake";

    private readonly ConcurrentQueue<SmsVerificationMessage> _calls = new();

    public string Provider => ProviderName;

    public Func<SmsVerificationMessage, CancellationToken, Task<SmsSendResult>>? Behavior { get; set; }

    public IReadOnlyCollection<SmsVerificationMessage> Calls => _calls;

    public int CallCount => _calls.Count;

    public Task<SmsSendResult> SendAsync(
        SmsProviderProfile profile,
        SmsVerificationMessage message,
        CancellationToken cancellationToken)
    {
        _calls.Enqueue(message);
        return Behavior?.Invoke(message, cancellationToken)
            ?? Task.FromResult(new SmsSendResult(ProviderName, "fake-" + Guid.NewGuid().ToString("N")));
    }
}

/// <summary>
/// Collects the outcome and duration observations of one browser SMS endpoint label
/// (<c>login-sms-code</c> by default, or <c>login-sms</c>), and every tag value.
/// </summary>
internal sealed class SmsCodeMetricsCollector : IDisposable
{
    private readonly string _endpoint;

    private readonly MeterListener _listener;
    private readonly ConcurrentQueue<string> _outcomes = new();
    private readonly ConcurrentQueue<double> _durations = new();
    private readonly ConcurrentQueue<string> _tagValues = new();
    private readonly ConcurrentQueue<string> _labelSets = new();

    public SmsCodeMetricsCollector(string endpoint = "login-sms-code")
    {
        _endpoint = endpoint;
        _listener = new MeterListener
        {
            InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == "SignaCore")
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            }
        };
        _listener.SetMeasurementEventCallback<int>((instrument, _, tags, _) => Record(instrument, 0, tags));
        _listener.SetMeasurementEventCallback<long>((instrument, _, tags, _) => Record(instrument, 0, tags));
        _listener.SetMeasurementEventCallback<double>((instrument, value, tags, _) => Record(instrument, value, tags));
        _listener.Start();
    }

    public IReadOnlyList<string> Outcomes => _outcomes.ToArray();

    public IReadOnlyCollection<double> Durations => _durations;

    public IReadOnlyCollection<string> TagValues => _tagValues;

    /// <summary>The sorted label keys of every observation of the collected endpoint.</summary>
    public IReadOnlyCollection<string> LabelSets => _labelSets;

    public void Dispose() => _listener.Dispose();

    private void Record(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        string? endpoint = null;
        string? outcome = null;
        var keys = new List<string>();
        foreach (var tag in tags)
        {
            _tagValues.Enqueue(tag.Value?.ToString() ?? string.Empty);
            keys.Add(tag.Key);
            if (tag.Key == "endpoint") endpoint = tag.Value?.ToString();
            if (tag.Key == "outcome") outcome = tag.Value?.ToString();
        }

        if (endpoint != _endpoint)
        {
            return;
        }

        // Only the closed endpoint and outcome labels: never a client, phone, or other value.
        _labelSets.Enqueue(string.Join(',', keys.Order(StringComparer.Ordinal)));

        if (instrument.Name == "oidc.endpoint.outcome" && outcome is not null)
        {
            _outcomes.Enqueue(outcome);
        }
        else if (instrument.Name == "oidc.endpoint.duration")
        {
            _durations.Enqueue(value);
        }
    }
}

/// <summary>Pauses exactly the first verifier before the real read, after continuation validation.</summary>
internal sealed class SmsVerificationBarrier
{
    private int _entered;
    private readonly TaskCompletionSource _reached = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public Task Reached => _reached.Task;
    public void Release() => _release.TrySetResult();

    public void Configure(IServiceCollection services) =>
        services.Replace(ServiceDescriptor.Scoped<IOtpService>(provider => new PausedOtpService(
            ActivatorUtilities.CreateInstance<DbOtpService>(provider), this)));

    private sealed class PausedOtpService(DbOtpService inner, SmsVerificationBarrier barrier) : IOtpService
    {
        public Task<string> GenerateAndSendAsync(Guid appRegistrationId, string phoneE164, string profileKey,
            CancellationToken cancellationToken = default) =>
            inner.GenerateAndSendAsync(appRegistrationId, phoneE164, profileKey, cancellationToken);
        public Task<OtpSendOutcome> TrySendAsync(Guid appRegistrationId, string phoneE164, string profileKey,
            CancellationToken cancellationToken = default) =>
            inner.TrySendAsync(appRegistrationId, phoneE164, profileKey, cancellationToken);
        public Task InvalidateAsync(Guid appRegistrationId, string phoneE164, CancellationToken cancellationToken = default) =>
            inner.InvalidateAsync(appRegistrationId, phoneE164, cancellationToken);
        public async Task<OtpVerificationResult> VerifyAsync(Guid appRegistrationId, string phoneE164, string code,
            CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref barrier._entered) == 1)
            {
                barrier._reached.TrySetResult();
                await barrier._release.Task.WaitAsync(cancellationToken);
            }
            return await inner.VerifyAsync(appRegistrationId, phoneE164, code, cancellationToken);
        }
    }
}
