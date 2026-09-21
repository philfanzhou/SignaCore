extern alias BffSample;
using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using BffSample::SignaCore.ReferenceBff;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ServiceMantle.Audit;
using Xunit;
using SilentTerminal = SignaCore.ReferenceBff.Tests.ReferenceBffSetupCodeTests.SilentTerminal;

namespace SignaCore.ReferenceBff.Tests;

public sealed partial class ReferenceBffDatabaseContractTests
{
    [Fact]
    public async Task SetupHttp_ExactLimitHeadersEncodingAndRateLimitAreSharedGates()
    {
        await using var database = await BffDatabase.CreateMigratedAsync("SQLite");
        var terminal = new SilentTerminal();
        Assert.Equal(0, await RunCode(database, "create", terminal));
        await using var authority = await FakeAuthority.StartAsync();
        foreach (var kind in new[] { "exact", "oversize", "missing-header", "double-header", "wrong-header", "wrong-type", "utf16", "encoding", "query" })
        {
            await using var bff = SetupHost(database, "SQLite", authority);
            using var client = bff.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://bff.localhost"), AllowAutoRedirect = false });
            var body = JsonSerializer.Serialize(new { code = terminal.Code!.Reveal() });
            body = body.PadRight(kind == "oversize" ? 4097 : 4096);
            using var request = new HttpRequestMessage(HttpMethod.Post, "/management/v1/setup" + (kind == "query" ? "?code=x" : ""))
            { Content = new StringContent(body, kind == "utf16" ? Encoding.Unicode : Encoding.UTF8, kind == "wrong-type" ? "text/plain" : "application/json") };
            if (kind != "missing-header") request.Headers.Add("X-ServiceMantle-Request", kind == "wrong-header" ? "2" : "1");
            if (kind == "double-header") request.Headers.Add("X-ServiceMantle-Request", "1");
            if (kind == "encoding") request.Content.Headers.ContentEncoding.Add("gzip");
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            Assert.Equal(kind == "exact" ? HttpStatusCode.Unauthorized : HttpStatusCode.BadRequest, response.StatusCode);
        }
        await using var rateHost = SetupHost(database, "SQLite", authority);
        using var rateClient = rateHost.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://bff.localhost"), AllowAutoRedirect = false });
        for (var i = 0; i < 6; i++)
        {
            using var response = await SendSetup(rateClient, terminal.Code!.Reveal(), null);
            Assert.Equal(i < 5 ? HttpStatusCode.Unauthorized : HttpStatusCode.TooManyRequests, response.StatusCode);
        }
        Assert.Equal(0, authority.UserInfoCalls);
        await using var read = database.CreateContext();
        Assert.Empty(await read.ManagementRoleBindings.ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal(0, await CountSharedAuditRowsAsync(read));
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/error")]
    [InlineData("/bff/setup")]
    [InlineData("/bff/login")]
    [InlineData("/management/v1/setup")]
    [InlineData("/MANAGEMENT/v1/setup/")]
    [InlineData("/signout-callback-oidc")]
    public async Task SetupHttp_CallbackConflictsFailStartup(string path)
    {
        await using var database = await BffDatabase.CreateMigratedAsync("SQLite");
        await using var context = database.CreateContext();
        await using var authority = await FakeAuthority.StartAsync();
        await using var bff = BffTestServer.Create(FakeAuthority.BaseAddress, "reference-bff", "reference-bff-test-secret",
            "https://bff.localhost" + path, authority.CreateClient(), databaseProvider: "SQLite",
            databaseConnectionString: context.Database.GetConnectionString());
        Assert.Throws<OptionsValidationException>(() => bff.CreateClient());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SetupHttp_ActualAuditLogsAndFailureOutputsExcludeAllCanaries(bool failAudit)
    {
        await using var database = await BffDatabase.CreateMigratedAsync("SQLite");
        var terminal = new SilentTerminal();
        Assert.Equal(0, await RunCode(database, "create", terminal));
        await using var authority = await FakeAuthority.StartAsync();
        authority.Subject = "setup-subject-canary-91b87";
        var logs = new SetupCaptureLogger();
        var fault = new SetupThrowingAudit();
        await using var bff = SetupHost(database, "SQLite", authority, services =>
        {
            services.AddLogging(builder => builder.AddProvider(logs));
            if (failAudit) services.AddScoped<IManagementAuditWriter>(_ => fault);
        });
        using var browser = BffTestServer.CreateBrowserOverAuthority(bff, authority.Server.CreateHandler(), new Uri(FakeAuthority.BaseAddress));
        var form = await browser.FollowFromBffAsync("/bff/setup", TestContext.Current.CancellationToken);
        using var formResponse = form.Response;
        var html = await formResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var csrf = WebUtility.HtmlDecode(Regex.Match(html, "id=\"csrf\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value);
        var cookie = browser.Cookies.GetCookies(browser.BffBase)["signacore-bff-session"]!.Value;
        var options = bff.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get("Cookies");
        var stub = options.TicketDataFormat.Unprotect(cookie)!;
        var key = stub.Principal.FindFirst("Microsoft.AspNetCore.Authentication.Cookies-SessionId")!.Value;
        var ticket = (await bff.Services.GetRequiredService<MemoryTicketStore>().RetrieveAsync(key))!;
        var canaries = new[] { terminal.Code!.Reveal(), ticket.Properties.GetTokenValue("access_token")!,
            ticket.Properties.GetTokenValue("id_token")!, cookie, authority.Subject, csrf, "reference-bff-test-secret",
            SignaCoreHostFixture.Password, BffTestServer.DatabaseRootKey,
            bff.Services.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>()["ReferenceBffDatabase:ConnectionString"]! };
        fault.Text = string.Join("|", canaries);
        logs.Entries.Clear();
        using var response = await SendSetup(browser.Bff, terminal.Code.Reveal(), csrf);
        Assert.Equal(failAudit ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.NoContent, response.StatusCode);
        var output = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)
            + response.Headers + response.Content.Headers + string.Join("\n", logs.Entries);
        BffCanaryAssertions.Absent(output, canaries, "Setup response and logs");
        await using var read = database.CreateContext();
        Assert.Equal(failAudit ? 0 : 1, await read.ManagementRoleBindings.CountAsync(TestContext.Current.CancellationToken));
        Assert.Equal(failAudit ? 0 : 1, await CountSharedAuditRowsAsync(read));
        if (!failAudit)
        {
            await read.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
            await using var command = read.Database.GetDbConnection().CreateCommand();
            command.CommandText = "SELECT * FROM service_audit_logs";
            await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
            Assert.True(await reader.ReadAsync(TestContext.Current.CancellationToken));
            for (var i = 0; i < reader.FieldCount; i++)
                if (reader.GetValue(i) is string value)
                    BffCanaryAssertions.Absent(value, canaries, "Setup audit column");
        }
    }

    private sealed class SetupThrowingAudit : IManagementAuditWriter
    {
        public string Text { get; set; } = "";
        public ValueTask<ManagementAuditRecord> RecordAsync(ManagementAuditEvent auditEvent, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException(Text, new Exception(Text));
    }

    private sealed class SetupCaptureLogger : ILoggerProvider, ILogger
    {
        public ConcurrentQueue<string> Entries { get; } = new();
        public ILogger CreateLogger(string categoryName) => this;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Entries.Enqueue(formatter(state, exception) + exception);
        public void Dispose() { }
    }
}
