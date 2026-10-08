using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.AspNetCore.TestHost;
using SignaCore.Domain.Services.Sms;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using SignaCore.Host.Security;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class HttpIdentityCookieProfileTests : IAsyncLifetime
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private const string Origin = "http://10.20.30.40:5002";
    private readonly string _directory = Path.Combine(PhysicalTempPath.Root(), "http-cookie-" + Guid.NewGuid().ToString("N"));
    private readonly List<WebApplicationFactory<Program>> _hosts = [];
    private string _bootstrap = null!;
    public async ValueTask InitializeAsync() => _bootstrap = await PrepareAsync();
    public async ValueTask DisposeAsync()
    {
        foreach (var host in _hosts) await host.DisposeAsync();
        SqliteConnection.ClearAllPools();
        Directory.Delete(_directory, true);
    }
    private Task<string> PrepareAsync()
    {
        // No origins key, no Testing environment: plain HTTP works in any deployment shape
        // because the carrier is derived from the request scheme alone (ADR 0008).
        var path = Path.Combine(_directory, Guid.NewGuid().ToString("N"));
        return InstallationTestSupport.PrepareCompletedInstallationAsync(path,
            new DatabaseOptions { Provider = "SQLite", ConnectionString = "Data Source=" + path + "/identity.db" },
            "http-cookie-synthetic-root", "cookie_admin", "CookieTests-123!",
            new Dictionary<string, string> {
                [SystemSettingKeys.PublicBaseUrl] = "https://accounts.example.test",
                [SystemSettingKeys.JwtIssuer] = "https://accounts.example.test"
            }, Ct);
    }
    private WebApplicationFactory<Program> Host(string? bootstrap = null, Action<IServiceCollection>? configure = null)
    {
        var host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder => {
            builder.UseEnvironment("Production"); builder.UseSetting("Bootstrap:FilePath", bootstrap ?? _bootstrap);
            builder.UseSetting("Endpoints:Http", "0");
            if (configure is not null) builder.ConfigureTestServices(configure);
        });
        _hosts.Add(host); return host;
    }
    private static HttpClient Client(WebApplicationFactory<Program> host, string origin) => host.CreateClient(new() {
        BaseAddress = new Uri(origin), AllowAutoRedirect = false, HandleCookies = false
    });
    private static async Task<(string Cookie, string Token, string Handle)> PageAsync(WebApplicationFactory<Program> host, HttpClient client)
    {
        var app = await OAuthLoginSmsCodeTestSupport.SeedSmsAppAsync(host.Services, SmsLoginMode.Disabled);
        var (handle, _) = await OAuthLoginSmsCodeTestSupport.SeedContinuationAsync(host.Services, app);
        using var response = await client.GetAsync("/oauth2/login?login_handle=" + handle, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var name = client.BaseAddress!.Scheme == "http" ? IdentityCookieProfile.HttpCsrfCookie : LoginAntiforgeryDefaults.CookieName;
        var header = OAuthLoginTestSupport.GetSetCookieHeader(response, name)!;
        Assert.NotNull(header);
        Assert.Contains("; path=/", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("; httponly", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("; samesite=strict", header, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(client.BaseAddress.Scheme == "https", header.Contains("; secure", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain("; domain", header, StringComparison.OrdinalIgnoreCase);
        var html = await response.Content.ReadAsStringAsync(Ct);
        var token = Regex.Match(html, "name=\"__RequestVerificationToken\" value=\"([^\"]*)\"").Groups[1].Value;
        Assert.NotEmpty(token);
        return (header.Split(';')[0], token, handle);
    }
    private static async Task<string> IssueAsync(WebApplicationFactory<Program> host, string origin, Guid id)
    {
        using var scope = host.Services.CreateScope();
        var context = Context(scope.ServiceProvider, origin);
        await context.SignInAsync(IdentitySessionDefaults.AuthenticationScheme, IdentitySessionPrincipal.Create(id));
        return Assert.Single(context.Response.Headers.SetCookie.ToArray())!.Split(';')[0];
    }
    private static DefaultHttpContext Context(IServiceProvider services, string origin, string? cookie = null)
    {
        var uri = new Uri(origin);
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Scheme = uri.Scheme; context.Request.Host = HostString.FromUriComponent(uri);
        if (cookie is not null) context.Request.Headers.Cookie = cookie;
        return context;
    }
    private static async Task<bool> ReadAsync(WebApplicationFactory<Program> host, string origin, string cookie)
    {
        using var scope = host.Services.CreateScope();
        return (await Context(scope.ServiceProvider, origin, cookie).AuthenticateAsync(IdentitySessionDefaults.AuthenticationScheme)).Succeeded;
    }
    public static bool BrowserEnabled => !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("SIGNACORE_BROWSER_NODE"));
    [Fact(Skip = "Set SIGNACORE_BROWSER_NODE and SIGNACORE_PLAYWRIGHT_MODULE to run real Chromium transport acceptance.", SkipUnless = nameof(BrowserEnabled))]
    public async Task RealChromium_PasswordSsoRestartLogoutCancelAndSecurityFailures()
    {
        var sender = new FakeSmsSender();
        void SmsServices(IServiceCollection services)
        {
            services.Replace(ServiceDescriptor.Singleton(OAuthLoginSmsCodeTestSupport.CreateSmsOptions()));
            services.AddSingleton<ISmsSender>(sender);
        }
        var host = Host(configure:SmsServices); host.UseKestrel(0);
        using var initialize = host.CreateClient();
        var appId = await OAuthLoginTestSupport.SeedSuccessApplicationAsync(host.Services);
        using (var scope = host.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var app = await db.AppRegistrations.FindAsync([appId],Ct);
            app!.SmsLoginMode = SmsLoginMode.AutoProvision;
            app.SmsProfileKey = OAuthLoginSmsCodeTestSupport.ProfileKey;
            await db.SaveChangesAsync(Ct);
        }
        var username = "browser_" + Guid.NewGuid().ToString("N");
        const string password = "Browser-Password-123!";
        await OAuthLoginTestSupport.SeedUserAsync(host.Services, username, password);
        var path = Path.Combine(host.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.IWebHostEnvironment>().ContentRootPath,
            "..", "..", "tests", "SignaCore.IntegrationTests", "Browser", "http-identity-cookie.cjs");
        var start = new System.Diagnostics.ProcessStartInfo(Environment.GetEnvironmentVariable("SIGNACORE_BROWSER_NODE")!) {
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false
        };
        start.ArgumentList.Add(Path.GetFullPath(path));
        start.Environment["SIGNACORE_BROWSER_PORT"] = initialize.BaseAddress!.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
        start.Environment["SIGNACORE_BROWSER_USERNAME"] = username;
        start.Environment["SIGNACORE_BROWSER_PASSWORD"] = password;
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var certificateRequest = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=bff.success.test", rsa, System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        using var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1));
        start.Environment["SIGNACORE_BROWSER_CALLBACK_PFX"] = Convert.ToBase64String(certificate.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx));
        using var process = System.Diagnostics.Process.Start(start)!;
        var errors = process.StandardError.ReadToEndAsync(Ct);
        var accepted = false;
        var stage = "initial";
        try
        {
            while (await process.StandardOutput.ReadLineAsync(Ct).AsTask().WaitAsync(TimeSpan.FromSeconds(90),Ct) is { } line)
            {
                if (line.StartsWith("STEP_", StringComparison.Ordinal)) stage += " " + line;
                if (line == "RESTART")
                {
                    await host.DisposeAsync();
                    host = Host(configure:SmsServices); host.UseKestrel(0);
                    using var next = host.CreateClient();
                    await process.StandardInput.WriteLineAsync(next.BaseAddress!.Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
                    await process.StandardInput.FlushAsync(Ct);
                }
                if (line == "GET_SMS")
                {
                    await process.StandardInput.WriteLineAsync(Assert.Single(sender.Calls).Code);
                    await process.StandardInput.FlushAsync(Ct);
                }
                if (line == "PASS_BROWSER_COOKIE_TRANSPORT") accepted = true;
            }
            await process.WaitForExitAsync(Ct).WaitAsync(TimeSpan.FromSeconds(30),Ct);
            // The runner emits only fixed closed result markers; never echo process output.
            Assert.True(process.ExitCode == 0 && accepted, "Real browser cookie transport acceptance failed at " + stage + ".");
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree:true);
            await process.WaitForExitAsync(Ct);
            await errors;
        }
    }

    [Fact]
    public async Task RestartedSqliteHost_ReadsOnlyTheMatchingScheme_AndRejectsRenamedPayloads()
    {
        var first = Host();
        using var initialize = Client(first, Origin);
        var plainHttp = await IssueAsync(first, Origin, Guid.NewGuid());
        var secure = await IssueAsync(first, "https://10.20.30.40:5002", Guid.NewGuid());
        await first.DisposeAsync();
        var second = Host();
        Assert.True(await ReadAsync(second, Origin, plainHttp));
        Assert.True(await ReadAsync(second, "https://10.20.30.40:5002", secure));
        // The two carriers stay isolated by purpose: a renamed cookie never satisfies the other.
        Assert.False(await ReadAsync(second, Origin, secure.Replace(IdentitySessionDefaults.CookieName, IdentityCookieProfile.HttpIdentityCookie)));
        Assert.False(await ReadAsync(second, "https://10.20.30.40:5002", plainHttp.Replace(IdentityCookieProfile.HttpIdentityCookie, IdentitySessionDefaults.CookieName)));
        // Plain HTTP follows the scheme on any authority: host-only cookie scoping is the
        // browser's rule, not a server-side allowlist (ADR 0008).
        Assert.True(await ReadAsync(second, "http://10.20.30.40:5008", plainHttp));
        Assert.True(await ReadAsync(second, "http://10.20.30.41:5002", plainHttp));
    }
    [Fact]
    public async Task ConcurrentProfiles_KeepCsrfPairsIsolatedOnOneSqliteHost()
    {
        var first = Host();
        using var http = Client(first, Origin); using var https = Client(first, "https://10.20.30.40:5002");
        var pages = new[] { await PageAsync(first,http), await PageAsync(first,https) };
        // Render existing continuations concurrently: no fixture database writes are introduced.
        var rendered = await Task.WhenAll(http.GetAsync("/oauth2/login?login_handle="+pages[0].Handle,Ct),https.GetAsync("/oauth2/login?login_handle="+pages[1].Handle,Ct));
        using var httpPage = rendered[0]; using var httpsPage = rendered[1];
        Assert.NotNull(OAuthLoginTestSupport.GetSetCookieHeader(httpPage,IdentityCookieProfile.HttpCsrfCookie));
        Assert.NotNull(OAuthLoginTestSupport.GetSetCookieHeader(httpsPage,LoginAntiforgeryDefaults.CookieName));
        Assert.Null(OAuthLoginTestSupport.GetSetCookieHeader(httpPage,LoginAntiforgeryDefaults.CookieName));
        Assert.Null(OAuthLoginTestSupport.GetSetCookieHeader(httpsPage,IdentityCookieProfile.HttpCsrfCookie));
        var service = first.Services.GetRequiredService<ILoginAntiforgeryService>();
        Assert.True(service.IsValidPair(pages[0].Cookie.Split('=',2)[1], pages[0].Token, true));
        Assert.True(service.IsValidPair(pages[1].Cookie.Split('=',2)[1], pages[1].Token));
        for (var index=0;index<2;index++)
        {
            var target = index == 0 ? https : http; var source = pages[index]; var selected = pages[1-index];
            using var request = new HttpRequestMessage(HttpMethod.Post,"/oauth2/login") {
                Content = new FormUrlEncodedContent(new Dictionary<string,string> {
                    ["login_handle"] = selected.Handle, ["__RequestVerificationToken"] = source.Token, ["action"] = "cancel"
                })
            };
            request.Headers.TryAddWithoutValidation("Cookie", (index==0 ? LoginAntiforgeryDefaults.CookieName : IdentityCookieProfile.HttpCsrfCookie)+"="+source.Cookie.Split('=',2)[1]);
            using var response = await target.SendAsync(request,Ct);
            Assert.Equal(HttpStatusCode.BadRequest,response.StatusCode); Assert.False(response.Headers.Contains("Location"));
            Assert.False(response.Headers.Contains("Set-Cookie"));
        }
    }
    [Fact]
    public async Task PostgreSqlDatabaseContractTests_SharedReplicaHttpCookiesAndCsrfRemainProfileBound()
    {
        await using var harness = await OidcDatabaseTestSupport.Harness.CreateAsync(new Dictionary<string,string> {
            [SystemSettingKeys.PublicBaseUrl] = "https://accounts.example.test",
            [SystemSettingKeys.JwtIssuer] = "https://accounts.example.test"
        });
        var first = Host(harness.BootstrapFilePath); var second = Host(harness.BootstrapFilePath);
        using var a = Client(first,Origin); using var b = Client(second,Origin);
        var cookie = await IssueAsync(first,Origin,Guid.NewGuid());
        Assert.True(await ReadAsync(second,Origin,cookie));
        Assert.False(await ReadAsync(second,"https://10.20.30.40:5002",cookie.Replace(IdentityCookieProfile.HttpIdentityCookie,IdentitySessionDefaults.CookieName)));
        var pages = await Task.WhenAll(PageAsync(first,a),PageAsync(second,b));
        var csrf = second.Services.GetRequiredService<ILoginAntiforgeryService>();
        foreach(var page in pages) Assert.True(csrf.IsValidPair(page.Cookie.Split('=',2)[1],page.Token,true));
        Assert.False(csrf.IsValidPair(pages[0].Cookie.Split('=',2)[1],pages[1].Token,true));
        // Stop replicas before disposing their caller-owned PostgreSQL harness.
        await first.DisposeAsync(); await second.DisposeAsync();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CommittedLogout_DeletesOnlyCurrentIdentityAndCsrf_WithMatchingAttributes(bool httpTest)
    {
        var host = Host(); var origin = httpTest ? Origin : "https://10.20.30.40:5002";
        using var client = Client(host,origin); var page = await PageAsync(host,client);
        using var scope = host.Services.CreateScope();
        var app = await OAuthLoginSmsCodeTestSupport.SeedSmsAppAsync(host.Services,SmsLoginMode.Disabled);
        var request = await scope.ServiceProvider.GetRequiredService<ILogoutRequestStore>().CreateAsync(
            new LogoutRequestDescriptor(app.Id,Guid.NewGuid(),Guid.NewGuid(),null,null),DateTimeOffset.UtcNow,Ct);
        using var response = await client.GetAsync("/oauth2/logout?logout_handle="+request.LogoutHandle,Ct);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode);
        var cookies = response.Headers.GetValues("Set-Cookie").ToArray(); Assert.Equal(2,cookies.Length);
        foreach(var (name,sameSite) in new[] {(httpTest?IdentityCookieProfile.HttpIdentityCookie:IdentitySessionDefaults.CookieName,"lax"),(httpTest?IdentityCookieProfile.HttpCsrfCookie:LoginAntiforgeryDefaults.CookieName,"strict")})
        {
            var cookie = Assert.Single(cookies,value=>value.StartsWith(name+"=",StringComparison.Ordinal));
            Assert.Contains("; path=/",cookie,StringComparison.OrdinalIgnoreCase); Assert.Contains("; httponly",cookie,StringComparison.OrdinalIgnoreCase);
            Assert.Contains("; samesite="+sameSite,cookie,StringComparison.OrdinalIgnoreCase); Assert.Contains("; expires=",cookie,StringComparison.OrdinalIgnoreCase);
            Assert.Equal(!httpTest,cookie.Contains("; secure",StringComparison.OrdinalIgnoreCase)); Assert.DoesNotContain("; domain",cookie,StringComparison.OrdinalIgnoreCase);
        }
        using var replay = await client.GetAsync("/oauth2/logout?logout_handle="+request.LogoutHandle,Ct);
        Assert.Equal(HttpStatusCode.BadRequest,replay.StatusCode); Assert.False(replay.Headers.Contains("Set-Cookie"));
    }
}
