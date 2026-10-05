using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle.Configuration;
using SignaCore.Database;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using SignaCore.Host.Security;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class HostedLoginHttpTestPolicyActivationTests : IAsyncLifetime
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private readonly string _directory = Path.Combine(PhysicalTempPath.Root(), "http-policy-" + Guid.NewGuid().ToString("N"));
    private readonly List<WebApplicationFactory<Program>> _hosts = [];
    private const string Origin = "http://10.20.30.40:5002";
    private const string Json = "[\"http://10.20.30.40:5002\"]";
    private const string Admin = "policy_admin";
    private const string Password = "PolicyTests-123!";

    public ValueTask InitializeAsync() { Directory.CreateDirectory(_directory); return ValueTask.CompletedTask; }
    public async ValueTask DisposeAsync()
    {
        foreach (var host in _hosts) await host.DisposeAsync();
        SqliteConnection.ClearAllPools();
        Directory.Delete(_directory, recursive: true);
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Staging")]
    [InlineData("Production")]
    [InlineData("Custom")]
    [InlineData("testing")]
    public async Task NonTestingActualHost_RefusesNonemptySharedList(string environment)
    {
        var bootstrap = await PrepareAsync(Json);
        var host = Host(bootstrap, environment);
        var error = Assert.ThrowsAny<Exception>(() => host.CreateClient());
        Assert.True(HasMessage(error, "HTTP hosted-login test origins require the Testing environment."));
    }

    [Fact]
    public async Task TestingActualHost_UsesSnapshotDespiteConfigurationOverlay_AndKeepsSecureCookies()
    {
        var bootstrap = await PrepareAsync(Json);
        var host = Host(bootstrap, "Testing", overlay: true);
        using var client = host.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        var policy = host.Services.GetRequiredService<HostedLoginHttpTestPolicy>();
        Assert.True(policy.Enabled);
        Assert.True(policy.ContainsOrigin(Origin));
        Assert.False(policy.ContainsOrigin("http://10.20.30.41:5008"));
        Assert.Equal("Testing", host.Services.GetRequiredService<Microsoft.Extensions.Hosting.IHostEnvironment>().EnvironmentName);
        // URI policy is projected only from the activated snapshot; the HTTPS carrier remains Secure.
        Assert.True(host.Services.GetRequiredService<SignaCore.Domain.Validators.OidcRedirectUriPolicy>().Allows(Origin + "/callback"));
        var app = await OAuthLoginSmsCodeTestSupport.SeedSmsAppAsync(host.Services, SignaCore.Database.Entity.SmsLoginMode.Disabled);
        var (handle, _) = await OAuthLoginSmsCodeTestSupport.SeedContinuationAsync(host.Services, app);
        using var page = await client.GetAsync("/oauth2/login?login_handle=" + handle, Ct);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var cookie = OAuthLoginTestSupport.GetSetCookieHeader(page, LoginAntiforgeryDefaults.CookieName);
        Assert.True(cookie is not null && cookie.Contains("secure", StringComparison.OrdinalIgnoreCase));
        Assert.Throws<SignaCore.Domain.Validators.OidcClientConfigurationException>(() =>
            SignaCore.Domain.Validators.OidcRedirectUriValidator.ValidateAndCanonicalize(Origin + "/callback", false));
    }

    [Theory]
    [InlineData("http://10.20.30.40:5002", true)]
    [InlineData("http://10.20.30.40:5008", false)]
    public async Task HttpPublicAuthority_RequiresExactOrigin(string publicUrl, bool succeeds)
    {
        var bootstrap = await PrepareAsync(Json, publicUrl);
        var host = Host(bootstrap, "Testing");
        if (succeeds)
        {
            using var client = host.CreateClient();
            Assert.True(host.Services.GetRequiredService<HostedLoginHttpTestPolicy>().Enabled);
        }
        else
        {
            var error = Assert.ThrowsAny<Exception>(() => host.CreateClient());
            Assert.True(HasMessage(error, "The HTTP public base URL authority must be in the shared hosted-login test origins."));
        }
    }

    [Fact]
    public async Task AuthenticatedUpdate_IsRestartOnly_CompetesByVersion_AndRejectedSyntaxWritesNothing()
    {
        var bootstrap = await PrepareAsync("[]");
        var host = Host(bootstrap, "Testing");
        using var client = host.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        await LoginAsync(client);
        var oldPolicy = host.Services.GetRequiredService<HostedLoginHttpTestPolicy>();
        Assert.False(oldPolicy.Enabled);
        var before = await VersionAsync(client);
        var audits = await AuditCountAsync(host);
        using var rejected = await UpdateAsync(client, before, "[\"http://127.0.0.1:80\"]");
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        Assert.Equal(before, await VersionAsync(client));
        Assert.Equal(audits, await AuditCountAsync(host));
        var responses = await Task.WhenAll(UpdateAsync(client, before, Json), UpdateAsync(client, before, "[\"http://10.20.30.41:5008\"]"));
        try
        {
            Assert.Single(responses, result => result.StatusCode == HttpStatusCode.OK);
            Assert.Single(responses, result => result.StatusCode == HttpStatusCode.Conflict);
        }
        finally { foreach (var result in responses) result.Dispose(); }
        Assert.Equal(before + 1, await VersionAsync(client));
        Assert.Equal(audits + 1, await AuditCountAsync(host));
        Assert.False(oldPolicy.Enabled);
        using var running = await client.GetAsync("/management/v1/settings", Ct);
        Assert.Equal(before.ToString(), running.Headers.GetValues("X-SignaCore-Running-Configuration-Version").Single());
        using var definitions = await client.GetAsync("/management/v1/settings/definitions", Ct);
        var catalog = await definitions.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: Ct);
        Assert.True(catalog.GetProperty("definitions").EnumerateArray().Single(item =>
            item.GetProperty("key").GetString() == HostedLoginHttpTestOrigins.SettingKey).GetProperty("requiresRestart").GetBoolean());
        var restarted = Host(bootstrap, "Testing");
        using var nextClient = restarted.CreateClient();
        Assert.True(restarted.Services.GetRequiredService<HostedLoginHttpTestPolicy>().Enabled);
        Assert.False(oldPolicy.Enabled);
        var refused = Host(bootstrap, "Production");
        var error = Assert.ThrowsAny<Exception>(() => refused.CreateClient());
        Assert.True(HasMessage(error, "HTTP hosted-login test origins require the Testing environment."));
    }

    [Fact]
    public async Task TwoHosts_WithDifferentSnapshots_AreIsolated()
    {
        var first = Host(await PrepareAsync(Json), "Testing");
        var second = Host(await PrepareAsync("[]"), "Production");
        using var a = first.CreateClient();
        using var b = second.CreateClient();
        Assert.True(first.Services.GetRequiredService<HostedLoginHttpTestPolicy>().ContainsOrigin(Origin));
        Assert.False(second.Services.GetRequiredService<HostedLoginHttpTestPolicy>().Enabled);
    }

    [Fact]
    public async Task OldAggregateWithNoNewKey_StartsWithoutBackfilling()
    {
        var bootstrap = await PrepareAsync("[]");
        var first = Host(bootstrap, "Production");
        using var client = first.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        await LoginAsync(client);
        var before = await VersionAsync(client);
        using var removed = await UpdateAsync(client, before, null);
        Assert.Equal(HttpStatusCode.OK, removed.StatusCode);
        var restarted = Host(bootstrap, "Production");
        using var next = restarted.CreateClient();
        Assert.False(restarted.Services.GetRequiredService<HostedLoginHttpTestPolicy>().Enabled);
        using var scope = restarted.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var aggregate = await SharedSettingTestDatabase.LoadAggregateAsync(db, Ct);
        Assert.False(SharedSettingTestDatabase.ParseValues(aggregate!).ContainsKey(HostedLoginHttpTestOrigins.SettingKey));
    }

    [Theory]
    [InlineData("Testing", "Production", true)]
    [InlineData("Production", "Testing", false)]
    public async Task ConflictingEnvironmentVariables_FollowTheActualWebApplicationEnvironment(
        string dotnetEnvironment, string aspnetEnvironment, bool starts)
    {
        var bootstrap = await PrepareAsync(Json);
        var start = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false
        };
        start.ArgumentList.Add(typeof(Program).Assembly.Location);
        start.Environment["Bootstrap__FilePath"] = bootstrap;
        start.Environment["Endpoints__Http"] = "0";
        start.Environment["DOTNET_ENVIRONMENT"] = dotnetEnvironment;
        start.Environment["ASPNETCORE_ENVIRONMENT"] = aspnetEnvironment;
        using var process = Process.Start(start)!;
        var ready = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var refusal = false;
        async Task ObserveAsync(StreamReader reader)
        {
            while (await reader.ReadLineAsync(Ct) is { } line)
            {
                if (line.Contains("Hosting environment:", StringComparison.Ordinal))
                    ready.TrySetResult(line.Contains("Testing", StringComparison.Ordinal));
                if (line.Contains("HTTP hosted-login test origins require the Testing environment.", StringComparison.Ordinal))
                    refusal = true;
            }
        }
        var output = ObserveAsync(process.StandardOutput);
        var errors = ObserveAsync(process.StandardError);
        try
        {
            if (starts)
            {
                Assert.True(await ready.Task.WaitAsync(TimeSpan.FromSeconds(30), Ct));
                Assert.False(process.HasExited);
            }
            else
            {
                await process.WaitForExitAsync(Ct).WaitAsync(TimeSpan.FromSeconds(30), Ct);
                await Task.WhenAll(output, errors);
                Assert.True(refusal, "Expected the closed Testing environment startup refusal.");
                Assert.NotEqual(0, process.ExitCode);
            }
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync(Ct);
            await Task.WhenAll(output, errors);
        }
    }

    private async Task<string> PrepareAsync(string origins, string url = "https://accounts.example.test")
    {
        var directory = Path.Combine(_directory, Guid.NewGuid().ToString("N"));
        return await InstallationTestSupport.PrepareCompletedInstallationAsync(directory,
            new DatabaseOptions { Provider = "SQLite", ConnectionString = "Data Source=" + directory + "/identity.db" },
            "policy-activation-synthetic-root", Admin, Password,
            new Dictionary<string, string>
            {
                [SystemSettingKeys.SecurityHostedLoginHttpTestOrigins] = origins,
                [SystemSettingKeys.PublicBaseUrl] = url, [SystemSettingKeys.JwtIssuer] = url
            }, Ct);
    }
    private WebApplicationFactory<Program> Host(string bootstrap, string environment, bool overlay = false)
    {
        var host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Bootstrap:FilePath", bootstrap);
            builder.UseSetting("Endpoints:Http", "0");
            builder.UseEnvironment(environment);
            if (overlay) builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(
                new Dictionary<string, string?> { [SystemSettingKeys.SecurityHostedLoginHttpTestOrigins + ":0"] = "http://10.20.30.41:5008" }));
        });
        _hosts.Add(host);
        return host;
    }
    private static async Task LoginAsync(HttpClient client)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/management/v1/session/login")
        { Content = JsonContent.Create(new { username = Admin, password = Password }) };
        request.Headers.Add("X-ServiceMantle-Request", "1");
        using var response = await client.SendAsync(request, Ct);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }
    private static Task<HttpResponseMessage> UpdateAsync(HttpClient client, long version, string? value) =>
        client.PostAsJsonAsync("/management/v1/settings", new
        { expectedVersion = version, changes = new[] { new { key = HostedLoginHttpTestOrigins.SettingKey, value } } }, Ct);
    private static async Task<long> VersionAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/management/v1/settings", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: Ct)).GetProperty("version").GetInt64();
    }
    private static async Task<int> AuditCountAsync(WebApplicationFactory<Program> host)
    {
        using var scope = host.Services.CreateScope();
        return (await SharedSettingTestDatabase.LoadSharedAuditJsonAsync(scope.ServiceProvider.GetRequiredService<IdentityDbContext>(), Ct)).Count;
    }
    private static bool HasMessage(Exception error, string message) =>
        error.Message == message || (error.InnerException is not null && HasMessage(error.InnerException, message));
}
