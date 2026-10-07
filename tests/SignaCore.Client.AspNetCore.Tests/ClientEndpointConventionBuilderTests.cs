extern alias ConsumerApp;

using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// <see cref="SignaCoreHostedLoginEndpointExtensions.MapSignaCoreHostedLogin"/> returns a
/// convention builder whose conventions reach all seven endpoints of the mapping at group
/// granularity: custom metadata is visible on every endpoint, <c>RequireRateLimiting</c> on the
/// group throttles the surface (429), ignoring the return value maps exactly as before, and the
/// startup validations are unchanged.
/// </summary>
public sealed class ClientEndpointConventionBuilderTests
{
    private sealed record MarkerMetadata(string Value);

    private sealed class Capture
    {
        public IEndpointConventionBuilder? Group { get; set; }
    }

    private static (WebApplication App, Capture Captured) CreateApp(
        Action<SignaCoreHostedLoginOptions>? configure = null,
        Action<IEndpointConventionBuilder>? useGroup = null,
        Action<IServiceCollection>? configureServices = null,
        bool useRateLimiter = false)
    {
        var capture = new Capture();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.WebHost.UseUrls("https://bff.localhost");
        builder.Services.AddSignaCoreHostedLogin(options =>
        {
            options.Authority = "https://idp.localhost";
            options.ClientId = "client-pack-app";
            options.ClientSecret = "client-pack-test-secret";
            options.RedirectUri = "https://bff.localhost/auth/callback";
            configure?.Invoke(options);
        });
        configureServices?.Invoke(builder.Services);

        var app = builder.Build();
        if (useRateLimiter)
        {
            // Conventions like RequireRateLimiting need their middleware in the pipeline; the
            // package's mapping itself is convention-agnostic.
            app.UseRateLimiter();
        }

        var group = app.MapSignaCoreHostedLogin("/auth");
        capture.Group = group;
        useGroup?.Invoke(group);
        return (app, capture);
    }

    private static async Task<HttpClient> StartClientAsync(WebApplication app)
    {
        await app.StartAsync(TestContext.Current.CancellationToken);
        var server = app.GetTestServer();
        server.BaseAddress = new Uri("https://bff.localhost");
        return server.CreateClient();
    }

    [Fact]
    public async Task AConventionOnTheReturnedGroup_ReachesAllSevenEndpoints()
    {
        var (app, _) = CreateApp(useGroup: group => group.WithMetadata(new MarkerMetadata("group")));
        using var _ = app;
        using var client = await StartClientAsync(app);
        try
        {
            var dataSource = app.Services.GetRequiredService<EndpointDataSource>();
            var marked = dataSource.Endpoints
                .Where(endpoint => endpoint.Metadata.OfType<MarkerMetadata>().Any())
                .Select(endpoint => endpoint.DisplayName)
                .OrderBy(name => name, StringComparer.Ordinal)
                .ToArray();
            // Exactly the seven endpoints of the mapping carry the convention's metadata —
            // nothing else the test host defines is touched.
            Assert.Equal(7, marked.Length);
        }
        finally
        {
            await app.StopAsync();
        }
    }

    [Fact]
    public async Task WithoutAnyConvention_TheEndpointsMapExactlyAsBefore()
    {
        var (app, _) = CreateApp();
        using var _ = app;
        using var client = await StartClientAsync(app);
        try
        {
            var dataSource = app.Services.GetRequiredService<EndpointDataSource>();
            Assert.DoesNotContain(
                dataSource.Endpoints,
                endpoint => endpoint.Metadata.OfType<MarkerMetadata>().Any());

            // The surface answers as always: csrf anonymously, the session endpoint anonymously.
            using var csrf = await client.GetAsync("/auth/csrf", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, csrf.StatusCode);
            using var session = await client.GetAsync("/auth/session", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, session.StatusCode);
        }
        finally
        {
            await app.StopAsync();
        }
    }

    [Fact]
    public async Task RequireRateLimitingOnTheGroup_ThrottlesTheWholeSurface()
    {
        var (app, _) = CreateApp(
            configureServices: services => services.AddRateLimiter(options =>
            {
                options.RejectionStatusCode = (int)HttpStatusCode.TooManyRequests;
                options.AddPolicy("one-per-window", context => RateLimitPartition.GetFixedWindowLimiter(
                    context.Connection.RemoteIpAddress?.ToString() ?? "anonymous",
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 1,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0
                    }));
            }),
            useGroup: group => group.RequireRateLimiting("one-per-window"),
            useRateLimiter: true);
        using var _ = app;
        using var client = await StartClientAsync(app);
        try
        {
            // The first request through the surface passes; the second is rejected by the
            // consumer's partition with 429 — the package's endpoints carry the requirement.
            using var first = await client.GetAsync("/auth/csrf", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
            using var second = await client.GetAsync("/auth/csrf", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);
        }
        finally
        {
            await app.StopAsync();
        }
    }

    [Fact]
    public async Task AMismatchedRedirectUri_StillFailsMappingWithTheHistoricalDiagnostic()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
        {
            var (app, _) = CreateApp(options => options.RedirectUri = "https://bff.localhost/elsewhere/callback");
            using var _ = app;
        });
        Assert.Contains(
            "the redirect URI's path must be exactly <prefix>/callback.",
            exception.Message,
            StringComparison.Ordinal);
        await Task.CompletedTask;
    }
}
