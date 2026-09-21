extern alias BffSample;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using BffSample::SignaCore.ReferenceBff;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Mvc.Testing;
using ServiceMantle.AspNetCore.ManagementApi.Setup;
using ServiceMantle.Installation;
using SignaCore.ReferenceBff.Database;
using Xunit;
using SilentTerminal = SignaCore.ReferenceBff.Tests.ReferenceBffSetupCodeTests.SilentTerminal;

namespace SignaCore.ReferenceBff.Tests;

public sealed partial class ReferenceBffDatabaseContractTests
{
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task SetupHttp_CreateLoginBindReplayAndRevoke_UseOneDurableFact(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        var terminal = new SilentTerminal();
        Assert.Equal(0, await RunCode(database, "create", terminal));
        await using var authority = await FakeAuthority.StartAsync();
        await using var bff = SetupHost(database, provider, authority);
        using var browser = BffTestServer.CreateBrowserOverAuthority(bff, authority.Server.CreateHandler(), new Uri(FakeAuthority.BaseAddress));
        using (var status = await browser.Bff.GetAsync("/management/v1/setup", TestContext.Current.CancellationToken))
            Assert.Equal(HttpStatusCode.OK, status.StatusCode);
        var form = await browser.FollowFromBffAsync("/bff/setup", TestContext.Current.CancellationToken);
        using var formResponse = form.Response;
        Assert.Equal("/bff/setup", form.FinalUri.AbsolutePath);
        var html = await formResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain(FakeAuthority.DefaultSubject, html);
        var csrf = WebUtility.HtmlDecode(Regex.Match(html, "id=\"csrf\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value);
        Assert.NotEmpty(csrf);
        using (var response = await SendSetup(browser.Bff, terminal.Code!.Reveal(), csrf))
        {
            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        }
        await using (var read = database.CreateContext())
        {
            Assert.False(read.Database.HasPendingModelChanges());
            var binding = await read.ManagementRoleBindings.SingleAsync(TestContext.Current.CancellationToken);
            Assert.True(binding.Issuer == FakeAuthority.BaseAddress && binding.Subject == FakeAuthority.DefaultSubject);
            var installation = await read.ServiceInstallations.SingleAsync(TestContext.Current.CancellationToken);
            Assert.Equal(InstallationStatus.Completed, installation.Status);
            Assert.Null(installation.SetupCodeDigest);
            Assert.Equal(1, await CountSharedAuditRowsAsync(read));
            await AssertSetupAuditSafe(read, binding.Id, terminal.Code.Reveal());
        }
        using (var admin = await browser.Bff.GetAsync("/bff/admin", TestContext.Current.CancellationToken))
            Assert.Equal(HttpStatusCode.OK, admin.StatusCode);
        // A malformed body is not parsed after Completed; no credential is required for replay.
        using (var replay = new HttpRequestMessage(HttpMethod.Post, "/management/v1/setup") { Content = new StringContent("not-json") })
        {
            replay.Headers.Add("X-ServiceMantle-Request", "1");
            using var response = await browser.Bff.SendAsync(replay, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        }
        await using (var revoke = database.CreateContext())
        {
            (await revoke.ManagementRoleBindings.SingleAsync(TestContext.Current.CancellationToken)).IsActive = false;
            await revoke.SaveChangesAsync(TestContext.Current.CancellationToken);
        }
        using (var admin = await browser.Bff.GetAsync("/bff/admin", TestContext.Current.CancellationToken))
            Assert.Equal(HttpStatusCode.Forbidden, admin.StatusCode);
        using var head = await browser.Bff.SendAsync(new HttpRequestMessage(HttpMethod.Head, "/management/v1/setup"), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, head.StatusCode);
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task SetupHttp_RejectsMissingStateCsrfIdentityAndStrictInputWithoutWrites(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        await using var authority = await FakeAuthority.StartAsync();
        await using var bff = SetupHost(database, provider, authority);
        using var browser = BffTestServer.CreateBrowserOverAuthority(bff, authority.Server.CreateHandler(), new Uri(FakeAuthority.BaseAddress));
        using (var missing = await browser.Bff.GetAsync("/bff/login", TestContext.Current.CancellationToken))
            Assert.Equal(HttpStatusCode.ServiceUnavailable, missing.StatusCode);
        var terminal = new SilentTerminal();
        Assert.Equal(0, await RunCode(database, "create", terminal));
        using (var anonymous = await SendSetup(browser.Bff, terminal.Code!.Reveal(), null))
            Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        var form = await browser.FollowFromBffAsync("/bff/setup", TestContext.Current.CancellationToken);
        using var formResponse = form.Response;
        var html = await formResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var csrf = WebUtility.HtmlDecode(Regex.Match(html, "id=\"csrf\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value);
        using (var missingCsrf = await SendSetup(browser.Bff, terminal.Code.Reveal(), null))
            Assert.Equal(HttpStatusCode.BadRequest, missingCsrf.StatusCode);
        using (var invalid = await SendSetup(browser.Bff, new string('A', 32), csrf))
            Assert.Equal(HttpStatusCode.Unauthorized, invalid.StatusCode);
        Assert.Equal(0, authority.UserInfoCalls);
        // Every body shape goes through the actual code-only shared parser.
        foreach (var body in new[] { "{}", "[]", "{\"code\":\"short\"}",
            "{\"code\":\"" + terminal.Code.Reveal() + "\",\"code\":\"" + terminal.Code.Reveal() + "\"}",
            "{\"code\":\"" + terminal.Code.Reveal() + "\",\"input\":{}}",
            "{\"code\":\"" + terminal.Code.Reveal() + "\",\"issuer\":\"x\"}",
            "{\"code\":\"" + terminal.Code.Reveal() + "\",\"sub\":\"x\"}",
            "{\"code\":\"" + terminal.Code.Reveal() + "\",\"role\":\"admin\"}", new string(' ', 4097) })
        {
            await using var parserHost = SetupHost(database, provider, authority);
            using var parserClient = parserHost.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://bff.localhost"), AllowAutoRedirect = false });
            using var request = new HttpRequestMessage(HttpMethod.Post, "/management/v1/setup") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            request.Headers.Add("X-ServiceMantle-Request", "1");
            request.Headers.Add(BffSetupHosting.CsrfHeader, csrf);
            using var response = await parserClient.SendAsync(request, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
        authority.UserInfoMode = FakeAuthority.UserInfoResponse.InternalError;
        using (var unavailable = await SendSetup(browser.Bff, terminal.Code.Reveal(), csrf))
            Assert.Equal(HttpStatusCode.ServiceUnavailable, unavailable.StatusCode);
        Assert.Equal(1, bff.Services.GetRequiredService<MemoryTicketStore>().Count);
        authority.UserInfoMode = FakeAuthority.UserInfoResponse.SubjectMismatch;
        using (var invalid = await SendSetup(browser.Bff, terminal.Code.Reveal(), csrf))
            Assert.Equal(HttpStatusCode.Unauthorized, invalid.StatusCode);
        Assert.Equal(0, bff.Services.GetRequiredService<MemoryTicketStore>().Count);
        await using var read = database.CreateContext();
        Assert.Empty(await read.ManagementRoleBindings.ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal(0, await CountSharedAuditRowsAsync(read));
        Assert.True(await ValidCode(read, terminal.Code));
    }

    private static WebApplicationFactory<BffSample::Program> SetupHost(BffDatabase database, string provider, FakeAuthority authority, Action<IServiceCollection>? configure = null)
    {
        using var context = database.CreateContext();
        return BffTestServer.Create(FakeAuthority.BaseAddress, "reference-bff", "reference-bff-test-secret",
            SignaCoreHostFixture.RedirectUri, authority.CreateClient(), authority.Server.CreateHandler(),
            databaseProvider: provider, databaseConnectionString: context.Database.GetConnectionString(), configureTestServices: configure);
    }

    private static Task<HttpResponseMessage> SendSetup(HttpClient client, string code, string? csrf)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/management/v1/setup")
        { Content = new StringContent(JsonSerializer.Serialize(new { code }), Encoding.UTF8, "application/json") };
        request.Headers.Add("X-ServiceMantle-Request", "1");
        if (csrf is not null) request.Headers.Add(BffSetupHosting.CsrfHeader, csrf);
        return client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static async Task AssertSetupAuditSafe(ReferenceBffDbContext context, Guid target, string code)
    {
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText = "SELECT * FROM service_audit_logs";
        await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        Assert.True(await reader.ReadAsync(TestContext.Current.CancellationToken));
        var hasTarget = false;
        for (var i = 0; i < reader.FieldCount; i++)
        {
            if (reader.GetValue(i) is not string value) continue;
            hasTarget |= value == target.ToString("D");
            Assert.False(value.Contains(code, StringComparison.Ordinal) || value.Contains(FakeAuthority.DefaultSubject, StringComparison.Ordinal)
                || value.Contains(FakeAuthority.BaseAddress, StringComparison.Ordinal));
        }
        Assert.True(hasTarget);
        Assert.False(await reader.ReadAsync(TestContext.Current.CancellationToken));
    }
}
