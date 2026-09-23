using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Host.Security;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The sensitive-value scan of the login surface (<c>DF-01</c>, <c>DF-03</c>, <c>DF-05</c>,
/// <c>DF-06</c>, <c>DF-11</c>, <c>PS-19</c>): with identifiable canaries for the password, the
/// handle, both antiforgery values, and the full success-flow snapshot (state, nonce, challenge,
/// redirect URI), every local path plus the committed <c>EV-01</c> success is exercised under the
/// default log configuration, and none of the secrets may appear in the captured SignaCore logs,
/// in the full <c>service_audit_logs</c> / <c>login_histories</c> dump, or in an error body. The handle
/// and the request token appear only where the contract puts them — the login URL, the hidden form
/// fields of the two form renders, and the <c>Set-Cookie</c> of the first render — the plaintext
/// code appears only in the success redirect's <c>Location</c>, and the password never appears in
/// any response at all. The capture is proven non-empty through the fixed correlation id the
/// controller logs with every local outcome.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class OAuthLoginSensitiveValueScanTests : IClassFixture<IdentityServerFixture>
{
    private const string CanaryPassword = "Sup3rSecret-Canary-Pw!";
    private const string ActiveUser = "scan_active_user";
    private const string DisabledUser = "scan_disabled_user";
    private const string DisabledPassword = "Scan-Disabled-123!";
    private const string LockedUser = "scan_locked_user";
    private const string UnknownUser = "scan-unknown-user";
    private const string SuccessUser = "scan_success_user";

    private readonly IdentityServerFixture _fixture;

    public OAuthLoginSensitiveValueScanTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task SecretsNeverReachLogsAuditsOrErrorBodies()
    {
        await SeedUserAsync(_fixture.Services, ActiveUser, CanaryPassword);
        await SeedUserAsync(_fixture.Services, DisabledUser, DisabledPassword, isActive: false);
        await SeedUserAsync(_fixture.Services, LockedUser, CanaryPassword);
        await SeedUserAsync(_fixture.Services, SuccessUser, CanaryPassword);
        await SeedLoginAttemptAsync(
            _fixture.Services,
            LockedUser,
            failedAttempts: IdentityConstants.MaxFailedLoginAttempts,
            lockoutUntil: DateTimeOffset.UtcNow.AddMinutes(IdentityConstants.LoginLockoutMinutes));

        var capture = new CapturingLoggerProvider();
        using var factory = _fixture.WithTestServices(services =>
        {
            // A per-factory plain logger factory records deterministically (the shared Serilog
            // pipeline is process-wide), at the default configuration's levels: Information for
            // SignaCore categories, Warning for the framework's hosting and EF Core loggers.
            services.RemoveAll<ILoggerFactory>();
            services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
            {
                logging.AddProvider(capture);
                logging.SetMinimumLevel(LogLevel.Information);
                logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
                logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning);
            }));
        });
        using var client = factory.CreateClient(
            new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false
            });

        var bodies = new List<(string Label, string Body)>();
        var setCookieHeaders = new List<string>();

        async Task<string> CaptureAsync(HttpResponseMessage response, string label)
        {
            var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            bodies.Add((label, body));
            var setCookie = GetSetCookieHeader(response, CookieName);
            if (setCookie is not null)
            {
                setCookieHeaders.Add(setCookie);
            }

            return body;
        }

        // Path: the successful render (the form legitimately carries handle and token).
        var handle = await SeedContinuationAsync(factory.Services);
        using var getResponse = await client.GetAsync(
            $"/oauth2/login?login_handle={handle}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);
        var formBody = await CaptureAsync(getResponse, "form");
        var token = ExtractToken(formBody);
        var setCookie = GetSetCookieHeader(getResponse, CookieName);
        Assert.NotNull(setCookie);
        var cookieValue = CookieValueFromHeader(setCookie!, CookieName);
        var session = new LoginSession(handle, cookieValue, token);

        // Path: EV-03 local 400 with a canary-shaped unknown handle.
        using var unknownHandle = await client.GetAsync(
            $"/oauth2/login?login_handle={RandomHandle()}", TestContext.Current.CancellationToken);
        await CaptureAsync(unknownHandle, "error");

        // Path: structure failure carrying the canary password in a known field.
        using var structurePost = await client.SendAsync(CreateLoginPost(
            rawBody: BuildEscapedBody(LoginFields(session, "scan_structure_user", CanaryPassword)) + "&extra=1",
            cookieHeader: CookieHeaderFor(session),
            correlationId: FixedCorrelationId), TestContext.Current.CancellationToken);
        await CaptureAsync(structurePost, "error");

        // Path: antiforgery failure with a canary-shaped token.
        using var antiforgeryPost = await client.SendAsync(CreateLoginPost(
            fields: LoginFields(new LoginSession(handle, cookieValue, TamperLastCharacter(token)), "scan_csrf_user", CanaryPassword),
            cookieHeader: CookieHeaderFor(session),
            correlationId: FixedCorrelationId), TestContext.Current.CancellationToken);
        await CaptureAsync(antiforgeryPost, "error");

        // Path: cancel with the canary password present in the unread fields.
        using var cancelPost = await client.SendAsync(CreateLoginPost(
            fields:
            [
                new("login_handle", handle),
                new("username", "scan_cancel_user"),
                new("password", CanaryPassword),
                new(LoginAntiforgeryDefaults.TokenFieldName, token),
                new(ActionFieldName, CancelActionValue),
            ],
            cookieHeader: CookieHeaderFor(session),
            correlationId: FixedCorrelationId), TestContext.Current.CancellationToken);
        await CaptureAsync(cancelPost, "error");

        // Path: over-limit password built from the canary.
        using var overLimitPost = await client.SendAsync(CreateLoginPost(
            fields: LoginFields(
                session,
                "scan_overlimit_user",
                CanaryPassword + new string('x', 1025 - CanaryPassword.Length + 1)),
            cookieHeader: CookieHeaderFor(session),
            correlationId: FixedCorrelationId), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, overLimitPost.StatusCode);
        await CaptureAsync(overLimitPost, "error");

        // Paths: the four EV-17 credential failures, each with the canary password submitted.
        foreach (var (username, password) in new (string, string)[]
                 {
                     (UnknownUser, CanaryPassword),
                     (ActiveUser, CanaryPassword + "-wrong"),
                     (DisabledUser, DisabledPassword),
                     (LockedUser, CanaryPassword),
                 })
        {
            using var failurePost = await client.SendAsync(CreateLoginPost(
                fields: LoginFields(session, username, password),
                cookieHeader: CookieHeaderFor(session),
                correlationId: FixedCorrelationId), TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, failurePost.StatusCode);
            await CaptureAsync(failurePost, "form");
        }

        // Path: the passing credential check whose canary continuation revalidates to a local
        // rejection (the canary client never registered the stored redirect URI).
        using var passPost = await client.SendAsync(CreateLoginPost(
            fields: LoginFields(session, ActiveUser, CanaryPassword),
            cookieHeader: CookieHeaderFor(session),
            correlationId: FixedCorrelationId), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, passPost.StatusCode);
        await CaptureAsync(passPost, "error");

        // Path: the committed EV-01 success, driven through the real authorize endpoint with the
        // canary state/nonce/challenge and the canary redirect URI.
        var successSession = await BeginSuccessLoginViaAuthorizeAsync(
            factory.Services, client, existingCookieValue: cookieValue);
        using var successPost = await client.SendAsync(CreateLoginPost(
            fields: LoginFields(successSession, SuccessUser, CanaryPassword),
            cookieHeader: CookieHeaderFor(successSession),
            correlationId: FixedCorrelationId), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, successPost.StatusCode);
        var successLocation = successPost.Headers.Location!.ToString();
        var successCode = ExtractParameter(successLocation, "code");
        var identitySetCookie = GetSetCookieHeader(successPost, IdentitySessionDefaults.CookieName);
        Assert.NotNull(identitySetCookie);
        await CaptureAsync(successPost, "redirect");

        // ---- The scan ----

        var logText = string.Join(Environment.NewLine, capture.Messages);
        // The capture is proven non-empty by the fixed correlation id of the local outcomes.
        Assert.Contains(FixedCorrelationId, logText, StringComparison.Ordinal);
        Assert.DoesNotContain(CanaryPassword, logText, StringComparison.Ordinal);
        Assert.DoesNotContain(handle, logText, StringComparison.Ordinal);
        Assert.DoesNotContain(token, logText, StringComparison.Ordinal);
        Assert.DoesNotContain(cookieValue, logText, StringComparison.Ordinal);
        Assert.DoesNotContain(successSession.Handle, logText, StringComparison.Ordinal);
        Assert.DoesNotContain(successSession.Token, logText, StringComparison.Ordinal);
        Assert.DoesNotContain(successCode, logText, StringComparison.Ordinal);
        Assert.DoesNotContain(SuccessState, logText, StringComparison.Ordinal);
        Assert.DoesNotContain(SuccessNonce, logText, StringComparison.Ordinal);
        Assert.DoesNotContain(SuccessChallenge, logText, StringComparison.Ordinal);
        Assert.DoesNotContain("canary=success-redirect", logText, StringComparison.Ordinal);

        // The success redirect is the contract's only code surface: it carries the registered URI,
        // the state, and the issuer — and none of the other snapshot or credential values.
        Assert.Contains(SuccessRegisteredUri, successLocation, StringComparison.Ordinal);
        Assert.Contains($"state={SuccessState}", successLocation, StringComparison.Ordinal);
        Assert.DoesNotContain(successSession.Handle, successLocation, StringComparison.Ordinal);
        Assert.DoesNotContain(SuccessNonce, successLocation, StringComparison.Ordinal);
        Assert.DoesNotContain(SuccessChallenge, successLocation, StringComparison.Ordinal);
        Assert.DoesNotContain(CanaryPassword, successLocation, StringComparison.Ordinal);

        // The identity cookie carries the protected session id and nothing readable.
        Assert.DoesNotContain(successCode, identitySetCookie!, StringComparison.Ordinal);
        Assert.DoesNotContain(successSession.Handle, identitySetCookie!, StringComparison.Ordinal);

        // The dump is proven non-empty by the committed EV-17 audit rows of the failure paths and
        // the login_success row of the committed EV-01 transaction.
        var dump = await DumpLoginTablesAsync(factory.Services);
        Assert.Contains("oidc_login", dump, StringComparison.Ordinal);
        Assert.Contains("login_success", dump, StringComparison.Ordinal);
        Assert.DoesNotContain(CanaryPassword, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(handle, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(token, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(cookieValue, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(successSession.Handle, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(successSession.Token, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(successCode, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(SuccessState, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(SuccessNonce, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(SuccessChallenge, dump, StringComparison.Ordinal);
        Assert.DoesNotContain("canary=success-redirect", dump, StringComparison.Ordinal);

        foreach (var (label, body) in bodies)
        {
            // DF-01: the password exists inside the request only — never in any response.
            Assert.DoesNotContain(CanaryPassword, body, StringComparison.Ordinal);
            Assert.DoesNotContain(cookieValue, body, StringComparison.Ordinal);
            if (label == "form")
            {
                // The hidden fields are the contract's only handle/token surface in a body.
                continue;
            }

            Assert.DoesNotContain(handle, body, StringComparison.Ordinal);
            Assert.DoesNotContain(token, body, StringComparison.Ordinal);
        }

        // The cookie value exists on the wire only inside the single Set-Cookie of the render.
        Assert.All(setCookieHeaders, header => Assert.Contains(cookieValue, header, StringComparison.Ordinal));
    }

    private static string ExtractToken(string body)
    {
        var match = System.Text.RegularExpressions.Regex.Match(
            body, "name=\"__RequestVerificationToken\" value=\"([^\"]*)\"");
        Assert.True(match.Success);
        return match.Groups[1].Value;
    }

    private static string ExtractParameter(string location, string name)
    {
        var value = System.Web.HttpUtility.ParseQueryString(new Uri(location).Query)[name];
        Assert.False(string.IsNullOrEmpty(value));
        return value!;
    }

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
}
