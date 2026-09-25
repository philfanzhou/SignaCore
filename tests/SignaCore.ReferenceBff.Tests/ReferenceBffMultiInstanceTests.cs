extern alias BffSample;

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using BffOperationLog = BffSample::SignaCore.ReferenceBff.BffOperationLog;
using Microsoft.IdentityModel.Tokens;
using SignaCore.ReferenceBff.Database;
using Xunit;
using MemoryTicketStore = BffSample::SignaCore.ReferenceBff.MemoryTicketStore;

namespace SignaCore.ReferenceBff.Tests;

/// <summary>Real BFF handshake with explicit A-login, B-authorization, A-token routing (#77).</summary>
[Collection("BFF logging console")]
public sealed class ReferenceBffMultiInstanceTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task CompleteFlow_IsRepeatableAcrossBothInstanceDirections(bool swap, bool cancelUserInfo)
    {
        var phase = new Phase();
        try { await RunFlowAsync(swap, cancelUserInfo, phase); }
        catch (OperationCanceledException) when (TestContext.Current.CancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error)
        {
            var line = Regex.Match(error.StackTrace ?? "", @"ReferenceBffMultiInstanceTests.cs:line (\d+)").Groups[1].Value;
            throw new InvalidOperationException("BFF multi-instance acceptance failed at " + phase.Name + " (" + error.GetType().Name + ", assertion " + line + ").");
        }
    }

    private static async Task RunFlowAsync(bool swap, bool cancelUserInfo, Phase phase)
    {
        var ct = TestContext.Current.CancellationToken;
        using var capture = new ConsoleCapture();
        var outputs = new List<BrowserOutput>();
        var secrets = new List<string> { SignaCoreHostFixture.Password, SignaCoreHostFixture.ClientSecret };
        OperationLogCapture? events = null;
        await using var identity = new SignaCoreHostFixture();
        await identity.InitializeAsync();
        // Same database/bootstrap and DP ring, distinct host/service provider, as in #102.
        await using var peer = identity.Host.WithWebHostBuilder(_ => { });
        using var peerClient = peer.CreateClient();
        var a = swap ? peer : identity.Host;
        var b = swap ? identity.Host : peer;
        Assert.NotSame(a.Services, b.Services);
        var databasePath = Path.Combine(Path.GetTempPath(), $"bff-multi-{Guid.NewGuid():N}.db");
        var connection = $"Data Source={databasePath};Pooling=false";
        try
        {
            await using (var db = Context(connection))
            {
                await db.Database.MigrateAsync(ct);
                await new ServiceMantle.Persistence.EntityFrameworkCore.EfCoreServiceInstallationStore<ReferenceBffDbContext>(db)
                    .CreatePendingAsync(ReferenceBffServiceMantle.ServiceId, ct);
            }
            using var routing = new RoutedAuthority(a.Server.CreateHandler(), b.Server.CreateHandler());
            using var backchannel = new HttpClient(routing);
            using var userInfoRouting = new RoutedAuthority(a.Server.CreateHandler(), b.Server.CreateHandler());
            await using var bff = BffTestServer.Create(SignaCoreHostFixture.Authority,
                SignaCoreHostFixture.ClientId, SignaCoreHostFixture.ClientSecret,
                SignaCoreHostFixture.RedirectUri, backchannel,
                userInfoRouting,
                databaseProvider: "SQLite", databaseConnectionString: connection,
                configureTestServices: services => services.AddSingleton<ILogger<BffOperationLog>>(provider =>
                    events = new OperationLogCapture(new Logger<BffOperationLog>(provider.GetRequiredService<ILoggerFactory>()))));
            using var browserRouting = new RoutedAuthority(a.Server.CreateHandler(), b.Server.CreateHandler());
            using var browser = BffTestServer.CreateBrowserOverAuthority(bff,
                browserRouting,
                new Uri(SignaCoreHostFixture.Authority));

            // First login establishes the real identity cookie on A. The second challenge is
            // answered on B directly from that shared session, without another password POST.
            phase.Name = "initial challenge";
            var first = await ChallengeAsync(browser, outputs);
            using var authorize = await browser.IdentityServer.GetAsync(first, ct);
            Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
            Assert.StartsWith("/oauth2/login?login_handle=", authorize.Headers.Location!.ToString());
            using var login = await SignaCoreLoginDriver.PostCredentialsAsync(browser,
                authorize.Headers.Location.ToString(), SignaCoreHostFixture.Username,
                SignaCoreHostFixture.Password, ct);
            Assert.Equal(HttpStatusCode.Found, login.StatusCode);
            await CallbackAsync(browser, login.Headers.Location!, outputs);

            if (cancelUserInfo)
            {
                phase.Name = "cancelled UserInfo";
                userInfoRouting.HoldUserInfo = true;
                using var caller = CancellationTokenSource.CreateLinkedTokenSource(ct);
                var before = events!.Events.Count;
                var request = browser.Bff.GetAsync("/bff/me", caller.Token);
                await userInfoRouting.UserInfoEntered.Task.WaitAsync(TimeSpan.FromSeconds(15), ct);
                caller.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request);
                Assert.True(caller.IsCancellationRequested);
                Assert.Equal(before, events.Events.Count);
                phase.Name = "cancelled request cleanup";
                return;
            }
            for (var iteration = 0; iteration < 2; iteration++)
            {
                phase.Name = "peer authorization and token exchange";
                using var next = await browser.IdentityServer.GetAsync(await ChallengeAsync(browser, outputs), ct);
                Assert.Equal(HttpStatusCode.Found, next.StatusCode);
                Assert.True(next.Headers.Location!.AbsoluteUri.StartsWith(SignaCoreHostFixture.RedirectUri, StringComparison.Ordinal),
                    "Authorization on the peer must reuse the identity session.");
                await CallbackAsync(browser, next.Headers.Location, outputs);

                var cookie = browser.Cookies.GetCookies(browser.BffBase)["signacore-bff-session"]!.Value;
                var options = bff.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get("Cookies");
                var stub = options.TicketDataFormat.Unprotect(cookie)!;
                var ticketKey = stub.Principal.FindFirst("Microsoft.AspNetCore.Authentication.Cookies-SessionId")!.Value;
                var ticket = (await bff.Services.GetRequiredService<MemoryTicketStore>().RetrieveAsync(ticketKey))!;
                var access = ticket.Properties.GetTokenValue("access_token")!;
                var id = ticket.Properties.GetTokenValue("id_token")!;
                secrets.AddRange([cookie, access, id]);
                var idJwt = new JwtSecurityTokenHandler().ReadJwtToken(id);
                var accessJwt = new JwtSecurityTokenHandler().ReadJwtToken(access);
                Assert.True(idJwt.Subject == accessJwt.Subject, "Token subjects must agree.");
                Assert.Equal("JWT", idJwt.Header.Typ);
                Assert.Equal("at+jwt", accessJwt.Header.Typ);

                phase.Name = "UserInfo and local binding";
                using var me = await browser.Bff.GetAsync("/bff/me", ct);
                Assert.Equal(HttpStatusCode.OK, me.StatusCode);
                var profile = await me.Content.ReadFromJsonAsync<JsonElement>(ct);
                Assert.True(profile.GetProperty("sub").GetString() == idJwt.Subject, "UserInfo subject must match the verified ID token.");
                Assert.True(profile.GetProperty("name").GetString() == SignaCoreHostFixture.Username);
                outputs.Add(await BrowserOutput.ReadAsync(me, "profile"));

                // A local binding is required even for a correctly authenticated upstream user.
                if (iteration == 0)
                {
                    using var denied = await browser.Bff.GetAsync("/bff/admin", ct);
                    Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
                    outputs.Add(await BrowserOutput.ReadAsync(denied, "unbound administrator"));
                    await using var db = Context(connection);
                    await new ManagementRoleBindingStore(db).StageInitialAdministratorAsync(idJwt.Issuer, idJwt.Subject, ct);
                    await db.SaveChangesAsync(ct);
                }
                using var admin = await browser.Bff.GetAsync("/bff/admin", ct);
                Assert.Equal(HttpStatusCode.OK, admin.StatusCode);
                outputs.Add(await BrowserOutput.ReadAsync(admin, "bound administrator"));

                // The resource validator accepts only this application's audience. The same
                // signature-valid token is rejected by a resource in another application.
                using var jwksClient = b.CreateClient();
                var jwks = await jwksClient.GetStringAsync("/.well-known/jwks", ct);
                var parameters = new TokenValidationParameters
                {
                    ValidIssuer = SignaCoreHostFixture.Authority, ValidAudience = SignaCoreHostFixture.ClientId,
                    IssuerSigningKeys = new JsonWebKeySet(jwks).GetSigningKeys(), ValidTypes = ["at+jwt"]
                };
                phase.Name = "signature and audience";
                var handler = new JwtSecurityTokenHandler();
                Assert.NotNull(handler.ValidateToken(access, parameters, out _));
                var idParameters = parameters.Clone();
                idParameters.ValidTypes = ["JWT"];
                Assert.NotNull(handler.ValidateToken(id, idParameters, out _));
                parameters.ValidAudience = "other-resource";
                Assert.Throws<SecurityTokenInvalidAudienceException>(() => handler.ValidateToken(access, parameters, out _));
            }
            Assert.Contains("A:/oauth2/login", browserRouting.Stages);
            Assert.Contains("B:/oauth2/authorize", browserRouting.Stages);
            Assert.Contains("A:/oauth2/token", routing.Stages);
            Assert.Contains("B:/.well-known/jwks", routing.Stages);
            Assert.Contains("B:/.well-known/openid-configuration", routing.Stages);
            Assert.Equal(1, browserRouting.Stages.Count(stage => stage == "A:POST:/oauth2/login"));
            Assert.Contains("B:/oauth2/userinfo", userInfoRouting.Stages);
            phase.Name = "browser and owned-event scans";
            foreach (var path in new[] { "/", "/bff/me", "/bff/admin", "/bff/diagnostics" })
            {
                using var response = await browser.Bff.GetAsync(path, ct);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                outputs.Add(await BrowserOutput.ReadAsync(response, path, allowFormCsrf: path == "/"));
            }
            foreach (Cookie cookie in browser.Cookies.GetAllCookies()) if (cookie.Value.Length > 1) secrets.Add(cookie.Value);
            var allSecrets = secrets.Concat(routing.Secrets).Concat(browserRouting.Secrets)
                .Concat(userInfoRouting.Secrets).Concat(outputs.SelectMany(x => x.RequiredValues))
                .Where(value => !string.IsNullOrEmpty(value)).Distinct(StringComparer.Ordinal).ToArray();
            foreach (var output in outputs) { phase.Name = output.Stage + " browser scans"; output.Scan(allSecrets); }
            phase.Name = "owned-event scans";
            Assert.NotNull(events);
            AssertCompleteAndScan(events.Events, allSecrets);
            phase.Name = "cleanup";
        }
        finally { File.Delete(databasePath); }
    }

    private static ReferenceBffDbContext Context(string connection) =>
        new(new DbContextOptionsBuilder<ReferenceBffDbContext>().UseReferenceBffSqlite(connection).Options);

    private static async Task<Uri> ChallengeAsync(CrossServerBrowser browser, List<BrowserOutput> outputs)
    {
        using var response = await browser.Bff.GetAsync("/bff/login", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.True(response.Headers.Location!.AbsolutePath == "/oauth2/authorize", "Discovery must resolve Authorization.");
        outputs.Add(await BrowserOutput.ReadAsync(response, "login challenge", locationFields: ["state", "nonce", "code_challenge"], allowProtocolCookies: true));
        return response.Headers.Location;
    }

    private static async Task CallbackAsync(CrossServerBrowser browser, Uri callback, List<BrowserOutput> outputs)
    {
        using var response = await browser.Bff.GetAsync(callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal("/", response.Headers.Location!.ToString());
        outputs.Add(await BrowserOutput.ReadAsync(response, "OIDC callback", requestFields: ["code", "state"], allowProtocolCookies: true));
    }

    private sealed class RoutedAuthority(HttpMessageHandler a, HttpMessageHandler b) : HttpMessageHandler
    {
        private readonly HttpMessageInvoker first = new(a);
        private readonly HttpMessageInvoker second = new(b);
        public List<string> Stages { get; } = [];
        public List<string> Secrets { get; } = [];
        public bool HoldUserInfo;
        public TaskCompletionSource UserInfoEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            var useA = path is "/oauth2/login" or "/oauth2/token";
            Stages.Add((useA ? "A:" : "B:") + path);
            if (path == "/oauth2/login" && request.Method == HttpMethod.Post) Stages.Add("A:POST:/oauth2/login");
            if (path == "/oauth2/userinfo" && HoldUserInfo)
            {
                UserInfoEntered.TrySetResult();
                await Task.Delay(Timeout.Infinite, ct);
            }
            var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(request.RequestUri.Query);
            foreach (var key in new[] { "state", "nonce", "code_challenge", "login_handle" })
                if (query.TryGetValue(key, out var value)) Secrets.Add(value.ToString());
            if (path == "/oauth2/token")
            {
                var form = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync(ct));
                foreach (var key in new[] { "code", "code_verifier" })
                    if (form.TryGetValue(key, out var value)) Secrets.Add(value.ToString());
            }
            var response = await (useA ? first : second).SendAsync(request, ct);
            if (path == "/oauth2/token" && response.IsSuccessStatusCode)
            {
                var tokens = JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync(ct));
                foreach (var key in new[] { "access_token", "id_token", "refresh_token" })
                    if (tokens.TryGetProperty(key, out var token)) Secrets.Add(token.GetString()!);
            }
            return response;
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) { first.Dispose(); second.Dispose(); }
            base.Dispose(disposing);
        }
    }

    private sealed class Phase { public string Name = "host initialization"; }

    private sealed record BrowserOutput(string Stage, string Body, string Headers, string Location, string Url, string[] RequiredValues)
    {
        public static async Task<BrowserOutput> ReadAsync(HttpResponseMessage response, string stage,
            string[]? locationFields = null, string[]? requestFields = null,
            bool allowProtocolCookies = false, bool allowFormCsrf = false)
        {
            var required = new List<string>();
            string RemoveProtocolFields(string text, string[]? fields)
            {
                if (fields is null || !Uri.TryCreate(text, UriKind.Absolute, out var uri)) return text;
                var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query);
                foreach (var field in fields)
                    if (query.Remove(field, out var values))
                    {
                        Assert.Single(values);
                        required.Add(values[0]!);
                    }
                return Microsoft.AspNetCore.WebUtilities.QueryHelpers.AddQueryString(uri.GetLeftPart(UriPartial.Path), query);
            }
            var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            if (allowFormCsrf)
            {
                var match = Regex.Match(body, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
                Assert.True(match.Success, "The home page must carry its required logout CSRF field.");
                required.Add(WebUtility.HtmlDecode(match.Groups[1].Value));
                body = body.Remove(match.Groups[1].Index, match.Groups[1].Length).Insert(match.Groups[1].Index, "[required form CSRF]");
            }
            var headers = new List<string>();
            foreach (var header in response.Headers)
            {
                if (header.Key.Equals("Location", StringComparison.OrdinalIgnoreCase)) continue;
                if ((allowProtocolCookies || allowFormCsrf) && header.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (var cookie in header.Value)
                    {
                        var name = cookie[..cookie.IndexOf('=')];
                        Assert.True((allowProtocolCookies && (name == "signacore-bff-session" || name.StartsWith(".AspNetCore.OpenIdConnect.Nonce.", StringComparison.Ordinal)
                            || name.StartsWith("signacore-bff-correlation", StringComparison.Ordinal)))
                            || (allowFormCsrf && name.StartsWith(".AspNetCore.Antiforgery.", StringComparison.Ordinal)), "Unexpected protocol cookie name.");
                        var end = cookie.IndexOf(';');
                        var value = cookie[(cookie.IndexOf('=') + 1)..(end < 0 ? cookie.Length : end)];
                        if (value.Length > 0 && value != "N") required.Add(value);
                        if (name != "signacore-bff-session")
                        {
                            required.Add(name);
                            name = "[required OIDC cookie name]";
                        }
                        // Cookie attributes remain scanned; only this required carrier value is removed.
                        headers.Add(name + "=[required cookie]" + (end < 0 ? "" : cookie[end..]));
                    }
                    continue;
                }
                headers.Add(header.Key + ":" + string.Join(",", header.Value));
            }
            headers.Add(response.Content.Headers.ToString());
            var location = RemoveProtocolFields(response.Headers.Location?.ToString() ?? "", locationFields);
            var url = RemoveProtocolFields(response.RequestMessage?.RequestUri?.ToString() ?? "", requestFields);
            return new BrowserOutput(stage, body, string.Join("\n", headers), location, url, required.ToArray());
        }
        public void Scan(string[] canaries)
        {
            BffCanaryAssertions.Absent(Body, canaries, Stage + " body");
            BffCanaryAssertions.Absent(Headers, canaries, Stage + " headers");
            BffCanaryAssertions.Absent(Location, canaries, Stage + " Location");
            BffCanaryAssertions.Absent(Url, canaries, Stage + " URL");
        }
    }

    // A tee for this exact emitter, registered through the existing test-service seam. Every
    // event still goes unchanged to the real shared Console pipeline. Capture happens before
    // that pipeline, so its sanitizer cannot hide a BffOperationLog leak from this assertion.
    private sealed class OperationLogCapture(ILogger<BffOperationLog> inner) : ILogger<BffOperationLog>
    {
        private readonly AsyncLocal<Scope?> scope = new();
        public ConcurrentQueue<OwnedEvent> Events { get; } = new();
        public bool IsEnabled(LogLevel level) => inner.IsEnabled(level);
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            var next = new Scope(this, scope.Value, state, inner.BeginScope(state));
            scope.Value = next;
            return next;
        }
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            var properties = new Dictionary<string, object?>();
            for (var current = scope.Value; current is not null; current = current.Parent) Copy(current.State);
            Copy(state);
            Events.Enqueue(new OwnedEvent(typeof(BffOperationLog).FullName!, level.ToString(), id.Id,
                formatter(state, exception), properties, exception?.ToString()));
            inner.Log(level, id, state, exception, formatter);
            void Copy(object? value)
            {
                if (value is IEnumerable<KeyValuePair<string, object?>> fields)
                    foreach (var field in fields) properties.TryAdd(field.Key, field.Value);
            }
        }
        private sealed class Scope(OperationLogCapture owner, Scope? parent, object state, IDisposable? inner) : IDisposable
        {
            public Scope? Parent { get; } = parent;
            public object State { get; } = state;
            public void Dispose() { owner.scope.Value = Parent; inner?.Dispose(); }
        }
    }
    // Canary comparisons are test assertions, separate from the ILogger capture/forwarding API.
    private static void AssertCompleteAndScan(IEnumerable<OwnedEvent> events, IEnumerable<string> canaries)
    {
        Assert.NotEmpty(events);
        foreach (var (operation, outcome) in new[] { ("WebHost", "Started"), ("Login", "Succeeded"), ("UserInfo", "Confirmed"), ("Authorization", "Forbidden"), ("Authorization", "Authorized") })
            Assert.True(events.Any(e => Equals(e.Properties.GetValueOrDefault("Operation"), operation)
                && Equals(e.Properties.GetValueOrDefault("Outcome"), outcome)), "Missing expected owned operation/outcome: " + operation + "/" + outcome);
        Assert.True(events.Count(e => Equals(e.Properties.GetValueOrDefault("Operation"), "Login")) >= 3);
        foreach (var entry in events) ScanOwnedEvent(entry, canaries);
    }
    private static void ScanOwnedEvent(OwnedEvent entry, IEnumerable<string> canaries) =>
        BffCanaryAssertions.Absent(JsonSerializer.Serialize(entry), canaries, "BffOperationLog complete event");

    private sealed record OwnedEvent(string Emitter, string Level, int EventId, string Message, Dictionary<string, object?> Properties, string? Exception);

    [Theory]
    [InlineData("message")]
    [InlineData("property")]
    [InlineData("exception")]
    public void OwnedEventScanner_RejectsInjectedCanaryWithoutDisclosingValue(string carrier)
    {
        var canary = "synthetic-event-canary-" + Guid.NewGuid().ToString("N");
        var capture = new OperationLogCapture(NullLogger<BffOperationLog>.Instance);
        using var scope = capture.BeginScope(new Dictionary<string, object?> { ["Operation"] = "Login", ["Outcome"] = "Succeeded", ["Injected"] = carrier == "property" ? canary : "safe" });
        capture.Log(LogLevel.Information, new EventId(1), "state", carrier == "exception" ? new Exception(canary) : null,
            (_, _) => carrier == "message" ? canary : "Reference BFF operation completed.");
        var entry = Assert.Single(capture.Events);
        var failure = Assert.Throws<Xunit.Sdk.FalseException>(() => ScanOwnedEvent(entry, [canary]));
        Assert.False(failure.Message.Contains(canary, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("challenge")]
    [InlineData("callback")]
    [InlineData("form")]
    public async Task RequiredProtocolCarrier_DoesNotExemptTheSameValueElsewhere(string carrier)
    {
        var canary = "synthetic-carrier-" + Guid.NewGuid().ToString("N");
        using var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            RequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://bff.localhost/"),
            Content = new StringContent(carrier == "form"
                ? "<input name=\"__RequestVerificationToken\" value=\"" + canary + "\"><p>" + canary + "</p>"
                : canary)
        };
        if (carrier == "challenge") response.Headers.Location = new Uri("https://localhost/oauth2/authorize?state=" + canary);
        if (carrier == "callback") response.Headers.Add("Set-Cookie", "signacore-bff-session=" + canary + "; secure; httponly");
        var output = await BrowserOutput.ReadAsync(response, "scanner self-check",
            locationFields: carrier == "challenge" ? ["state"] : null,
            allowProtocolCookies: carrier == "callback", allowFormCsrf: carrier == "form");
        Assert.Contains(canary, output.RequiredValues);
        var failure = Assert.Throws<Xunit.Sdk.FalseException>(() => output.Scan([canary]));
        Assert.False(failure.Message.Contains(canary, StringComparison.Ordinal));
    }

    private sealed class ConsoleCapture : IDisposable
    {
        private readonly TextWriter original = Console.Out;
        private readonly StringWriter buffer = new();
        private readonly TextWriter writer;
        public ConsoleCapture() { writer = TextWriter.Synchronized(buffer); Console.SetOut(writer); }
        public string Text { get { lock (writer) return buffer.ToString(); } }
        public void Dispose() { Console.SetOut(original); writer.Dispose(); }
    }
}
