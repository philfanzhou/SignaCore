extern alias BffSample;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using BffSample::SignaCore.ReferenceBff;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ServiceMantle.Audit;
using SignaCore.ReferenceBff.Database;
using Xunit;

namespace SignaCore.ReferenceBff.Tests;

[CollectionDefinition("BFF logging console", DisableParallelization = true)]
public sealed class BffLoggingConsoleCollection;

[Collection("BFF logging console")]
public sealed class ReferenceBffLoggingTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SharedConsole_IdentityAndFailClosedFieldsWorkInBothHostShapes(bool configured)
    {
        await using var database = await LogDatabase.CreateAsync();
        await using var authority = await FakeAuthority.StartAsync();
        using var capture = new ConsoleCapture();
        await using var host = CreateHost(authority, configured ? database : null);
        using var client = host.CreateClient();
        using var response = await client.GetAsync("/", TestContext.Current.CancellationToken);
        Assert.Equal(configured ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK, response.StatusCode);
        if (!configured)
        {
            Assert.Empty(response.Headers);
            Assert.Equal(new[] { "Content-Length", "Content-Type" }, response.Content.Headers.Select(header => header.Key).Order(StringComparer.Ordinal));
            Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
            using var missingSetup = await client.GetAsync("/management/v1/setup", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.NotFound, missingSetup.StatusCode);
            Assert.Empty(missingSetup.Headers);
        }
        var log = host.Services.GetRequiredService<BffOperationLog>();
        var canary = Guid.NewGuid().ToString("N");
        log.WriteFields(new Dictionary<string, object?>
        {
            ["Operation"] = "projection-contract", ["Outcome"] = "Rejected",
            ["Unexpected"] = canary, ["password"] = canary, ["code"] = canary,
            ["Headers"] = new Dictionary<string, object?> { ["Authorization"] = canary, [BffSetupHosting.CsrfHeader] = canary },
            ["cookie"] = canary, ["access_token"] = canary, ["id_token"] = canary,
            ["client_secret"] = canary, ["root_key"] = canary, ["connection"] = canary
        }, TestContext.Current.CancellationToken);
        var output = capture.Text;
        Assert.False(output.Contains(canary, StringComparison.Ordinal));
        Assert.False(output.Contains("Unexpected", StringComparison.Ordinal));
        var entries = output.Split('\n').Where(line => line.Contains("Reference BFF operation completed.", StringComparison.Ordinal)).ToArray();
        Assert.True(entries.Length >= 2);
        Assert.All(entries, AssertIdentity);
        Assert.Contains(entries, line => line.Contains("projection-contract", StringComparison.Ordinal));
        // Cancellation is observed immediately before emission, including an otherwise successful result.
        var before = capture.Text.Split('\n').Count(line => line.Contains("Reference BFF operation completed.", StringComparison.Ordinal));
        Assert.ThrowsAny<OperationCanceledException>(() => log.Record(BffLogOperation.Login, BffLogOutcome.Succeeded, new CancellationToken(true)));
        Assert.Equal(before, capture.Text.Split('\n').Count(line => line.Contains("Reference BFF operation completed.", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task BrowserFlow_AllConsoleEntriesExcludeCanariesAndExceptions(bool configured, bool failAudit)
    {
        await using var database = await LogDatabase.CreateAsync();
        var terminal = new ReferenceBffSetupCodeTests.SilentTerminal();
        Assert.Equal(0, await RunCode(database, "create", terminal));
        await using var identity = new SignaCoreHostFixture();
        await identity.InitializeAsync();
        var fault = new LogAuditFailure();
        using var capture = new ConsoleCapture();
        using var recorder = new VerifierRecorder(identity.Host.Server.CreateHandler());
        using var backchannel = new HttpClient(recorder);
        await using var host = BffTestServer.Create(SignaCoreHostFixture.Authority, SignaCoreHostFixture.ClientId,
            SignaCoreHostFixture.ClientSecret, SignaCoreHostFixture.RedirectUri, backchannel,
            identity.Host.Server.CreateHandler(), databaseProvider: configured ? "SQLite" : null,
            databaseConnectionString: configured ? database.ConnectionString : null,
            configureTestServices: services => { if (failAudit) services.AddScoped<IManagementAuditWriter>(_ => fault); });
        using var browser = BffTestServer.CreateBrowser(identity.Host, host);
        using var challenge = await browser.Bff.GetAsync("/bff/login", TestContext.Current.CancellationToken);
        using var authorize = await browser.SendOnIdentityServerAsync(new HttpRequestMessage(HttpMethod.Get, challenge.Headers.Location), TestContext.Current.CancellationToken);
        using var login = await SignaCoreLoginDriver.PostCredentialsAsync(browser, authorize.Headers.Location!.ToString(),
            SignaCoreHostFixture.Username, SignaCoreHostFixture.Password, TestContext.Current.CancellationToken);
        using var callback = await browser.SendOnBffAsync(new HttpRequestMessage(HttpMethod.Get, login.Headers.Location), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callback.StatusCode);
        using var me = await browser.Bff.GetAsync("/bff/me", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        using var before = await browser.Bff.GetAsync("/bff/admin", TestContext.Current.CancellationToken);
        Assert.Equal(configured ? HttpStatusCode.Forbidden : HttpStatusCode.ServiceUnavailable, before.StatusCode);
        using var form = await browser.Bff.GetAsync(configured ? "/bff/setup" : "/", TestContext.Current.CancellationToken);
        var html = await form.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var csrf = WebUtility.HtmlDecode(Regex.Match(html, configured
            ? "id=\"csrf\" type=\"hidden\" value=\"([^\"]+)\""
            : "name=\"__RequestVerificationToken\" value=\"([^\"]+)\"").Groups[1].Value);
        Assert.NotEmpty(csrf);
        var cookie = browser.Cookies.GetCookies(browser.BffBase)["signacore-bff-session"]!.Value;
        var options = host.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get("Cookies");
        var stub = options.TicketDataFormat.Unprotect(cookie)!;
        var key = stub.Principal.FindFirst("Microsoft.AspNetCore.Authentication.Cookies-SessionId")!.Value;
        var ticket = (await host.Services.GetRequiredService<MemoryTicketStore>().RetrieveAsync(key))!;
        var access = ticket.Properties.GetTokenValue("access_token")!;
        var canaries = new[] { SignaCoreHostFixture.Password, SignaCoreHostFixture.ClientSecret, terminal.Code!.Reveal(), cookie,
            access, ticket.Properties.GetTokenValue("id_token")!, recorder.Verifier, csrf, "Bearer " + access,
            database.ConnectionString, BffTestServer.DatabaseRootKey };
        fault.Text = string.Join('|', canaries);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/management/v1/setup")
        { Content = new StringContent(JsonSerializer.Serialize(new { code = terminal.Code.Reveal() }), Encoding.UTF8, "application/json") };
        request.Headers.Add("X-ServiceMantle-Request", "1");
        request.Headers.Add(BffSetupHosting.CsrfHeader, csrf);
        using var setup = await browser.Bff.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(!configured ? HttpStatusCode.NotFound : failAudit ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.NoContent, setup.StatusCode);
        using var admin = await browser.Bff.GetAsync("/bff/admin", TestContext.Current.CancellationToken);
        Assert.Equal(!configured ? HttpStatusCode.ServiceUnavailable : failAudit ? HttpStatusCode.Forbidden : HttpStatusCode.OK, admin.StatusCode);
        var browserCanaries = canaries.Where(value => value != csrf).ToArray();
        foreach (var response in new[] { me, before, form, setup, admin })
            await BffCanaryAssertions.ResponseAsync(response, browserCanaries);
        foreach (var path in new[] { "/", "/bff/me", "/bff/diagnostics" })
        {
            using var response = await browser.Bff.GetAsync(path, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            await BffCanaryAssertions.ResponseAsync(response, browserCanaries);
            BffCanaryAssertions.Absent(response.RequestMessage!.RequestUri!.AbsoluteUri, browserCanaries, "browser URL");
        }
        foreach (var reason in new[] { "authority_unreachable", "configuration_incomplete", "access_denied",
                     "sign_in_failed", "session_expired", "", "unrecognized" })
        {
            using var error = await browser.Bff.GetAsync("/error?reason=" + Uri.EscapeDataString(reason), TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, error.StatusCode);
            await BffCanaryAssertions.ResponseAsync(error, browserCanaries);
        }
        // Callback must issue the session cookie, but every other secret is forbidden in its headers.
        await BffCanaryAssertions.ResponseAsync(callback, browserCanaries.Where(value => value != cookie));
        await BffCanaryAssertions.ResponseAsync(challenge, browserCanaries);
        using var home = await browser.Bff.GetAsync("/", TestContext.Current.CancellationToken);
        var homeHtml = await home.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var logoutCsrf = WebUtility.HtmlDecode(Regex.Match(homeHtml, "name=\"__RequestVerificationToken\" value=\"([^\"]+)\"").Groups[1].Value);
        using var logout = await browser.Bff.PostAsync("/bff/logout", new FormUrlEncodedContent(new Dictionary<string, string>
            { ["__RequestVerificationToken"] = logoutCsrf }), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, logout.StatusCode);
        var output = capture.Text;
        await BffCanaryAssertions.ResponseAsync(home, browserCanaries);
        await BffCanaryAssertions.ResponseAsync(logout, browserCanaries);
        BffCanaryAssertions.Absent(output, canaries.Append(logoutCsrf), "console");
        var events = output.Split('\n').Where(line => line.Contains("Reference BFF operation completed.", StringComparison.Ordinal)).ToArray();
        Assert.All(events, AssertIdentity);
        foreach (var operation in configured ? new[] { "Login", "UserInfo", "Authorization", "Setup", "Logout" }
                     : new[] { "Login", "UserInfo", "Authorization", "Logout" })
            Assert.Contains(events, entry => Field(entry, "Operation") == operation);
        if (configured)
            Assert.Contains(events, entry => entry.Contains(failAudit ? "Unavailable" : "Committed", StringComparison.Ordinal));
        // Unknown caller-controlled reason values must not be reflected. These deliberately
        // poisoned input URLs are outside the BFF-owned operation-log contract: framework
        // free-text request logging is explicitly outside the sample's guarantee.
        foreach (var reason in browserCanaries)
        {
            using var error = await browser.Bff.GetAsync("/error?reason=" + Uri.EscapeDataString(reason), TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, error.StatusCode);
            await BffCanaryAssertions.ResponseAsync(error, browserCanaries);
        }
    }

    [Fact]
    public async Task CanceledUserInfoRequestEmitsNoCompletedOperation()
    {
        await using var authority = await FakeAuthority.StartAsync();
        using var capture = new ConsoleCapture();
        await using var host = CreateHost(authority, null);
        using var browser = BffTestServer.CreateBrowserOverAuthority(host, authority.Server.CreateHandler(), new Uri(FakeAuthority.BaseAddress));
        var signedIn = await browser.FollowFromBffAsync("/bff/login", TestContext.Current.CancellationToken);
        using var signedInResponse = signedIn.Response;
        var gate = authority.HoldUserInfoRequests();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var operation = browser.Bff.GetAsync("/bff/me", cancellation.Token);
        await authority.UserInfoArrived.WaitAsync(TestContext.Current.CancellationToken);
        await cancellation.CancelAsync();
        try { await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation); }
        finally { gate.TrySetResult(); }
        var events = capture.Text.Split('\n').Where(line => line.Contains("Reference BFF operation completed.", StringComparison.Ordinal));
        Assert.DoesNotContain(events, entry => Field(entry, "Operation") == "UserInfo");
        Assert.Equal(1, host.Services.GetRequiredService<MemoryTicketStore>().Count);
    }

    [Fact]
    public async Task LocalCommands_SuccessRotationFailureAndCancellationNeverCreateStructuredOutput()
    {
        await using var database = await LogDatabase.CreateAsync();
        using var capture = new ConsoleCapture();
        var terminal = new ReferenceBffSetupCodeTests.SilentTerminal();
        Assert.Equal(0, await RunCode(database, "create", terminal));
        Assert.Equal(0, await RunCode(database, "rotate", terminal));
        Assert.Equal(2, terminal.Displays);
        Assert.Equal(130, await SetupCodeCommand.RunAsync(["--setup-code", "rotate"], terminal,
            () => throw new InvalidOperationException(), new CancellationToken(true)));
        using var absent = new ConfigurationManager();
        Assert.Equal(4, await SetupCodeCommand.RunAsync(["--setup-code", "create"], terminal,
            () => SetupCodeCommand.CreateSession(absent), TestContext.Current.CancellationToken));
        await using (var context = database.Context())
        {
            await new ManagementRoleBindingStore(context).StageInitialAdministratorAsync("https://example.test", "synthetic", TestContext.Current.CancellationToken);
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        }
        Assert.Equal(3, await RunCode(database, "rotate", terminal));
        Assert.DoesNotContain("ServiceName", capture.Text);
        Assert.DoesNotContain("Reference BFF operation", capture.Text);
    }

    [Theory]
    [InlineData(false, "create")]
    [InlineData(true, "create")]
    [InlineData(false, "rotate")]
    [InlineData(true, "rotate")]
    public async Task ProgramCommandBranch_RejectsRedirectedTerminalBeforeBuildingHost(bool configured, string operation)
    {
        var start = new ProcessStartInfo("dotnet") { RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true };
        start.ArgumentList.Add(typeof(BffSample::Program).Assembly.Location);
        start.ArgumentList.Add("--setup-code"); start.ArgumentList.Add(operation);
        var connectionCanary = $"Data Source=synthetic-{Guid.NewGuid():N}.db";
        var rootCanary = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        if (configured)
        {
            start.Environment["ReferenceBffDatabase__Provider"] = "SQLite";
            start.Environment["ReferenceBffDatabase__ConnectionString"] = connectionCanary;
            start.Environment["ReferenceBffDatabase__DataProtectionRootKey"] = rootCanary;
        }
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var stderr = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        await process.WaitForExitAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2, process.ExitCode);
        var output = await stdout;
        var error = await stderr;
        BffCanaryAssertions.Absent(output, [connectionCanary, rootCanary], "command stdout");
        BffCanaryAssertions.Absent(error, [connectionCanary, rootCanary], "command stderr");
        Assert.Equal("", output);
        Assert.Equal("Setup code usage or terminal rejected.", error.Trim());
    }

    private static string? Field(string entry, string name)
    {
        using var json = JsonDocument.Parse(entry[entry.IndexOf('{')..]);
        return json.RootElement.TryGetProperty(name, out var value) ? value.GetString() : null;
    }

    private static void AssertIdentity(string entry)
    {
        Assert.True(Field(entry, "ServiceName") == "reference-bff");
        Assert.True(Field(entry, "InstanceId") == "reference-bff-local");
        Assert.True(!string.IsNullOrWhiteSpace(Field(entry, "ServiceVersion")));
    }

    private static Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<BffSample::Program> CreateHost(FakeAuthority authority, LogDatabase? database) =>
        BffTestServer.Create(FakeAuthority.BaseAddress, "reference-bff", "reference-bff-test-secret", SignaCoreHostFixture.RedirectUri,
            authority.CreateClient(), authority.Server.CreateHandler(), databaseProvider: database is null ? null : "SQLite", databaseConnectionString: database?.ConnectionString);

    private static async Task<int> RunCode(LogDatabase database, string operation, ReferenceBffSetupCodeTests.SilentTerminal terminal)
    {
        using var config = new ConfigurationManager();
        config["ReferenceBffDatabase:Provider"] = "SQLite";
        config["ReferenceBffDatabase:ConnectionString"] = database.ConnectionString;
        // Keep this command fixture compatible with the independent key-ring configuration slice.
        config["ReferenceBffDatabase:DataProtectionRootKey"] = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        return await SetupCodeCommand.RunAsync(["--setup-code", operation], terminal, () => SetupCodeCommand.CreateSession(config), TestContext.Current.CancellationToken);
    }

    private sealed class VerifierRecorder(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        public string Verifier { get; private set; } = "";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Content is not null)
            {
                var form = await request.Content.ReadAsStringAsync(cancellationToken);
                var field = form.Split('&').SingleOrDefault(part => part.StartsWith("code_verifier=", StringComparison.Ordinal));
                if (field is not null) Verifier = Uri.UnescapeDataString(field["code_verifier=".Length..]);
            }
            return await base.SendAsync(request, cancellationToken);
        }
    }

    private sealed class LogAuditFailure : IManagementAuditWriter
    {
        public string Text { get; set; } = "";
        public ValueTask<ManagementAuditRecord> RecordAsync(ManagementAuditEvent auditEvent, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException(Text, new Exception(Text));
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

    private sealed class LogDatabase(string path) : IAsyncDisposable
    {
        public string ConnectionString => $"Data Source={path};Pooling=false";
        public ReferenceBffDbContext Context() => new(new DbContextOptionsBuilder<ReferenceBffDbContext>().UseReferenceBffSqlite(ConnectionString).Options);
        public static async Task<LogDatabase> CreateAsync()
        {
            var database = new LogDatabase(Path.Combine(Path.GetTempPath(), $"bff-logging-{Guid.NewGuid():N}.db"));
            await using var context = database.Context();
            await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
            return database;
        }
        public ValueTask DisposeAsync() { File.Delete(path); return ValueTask.CompletedTask; }
    }
}
