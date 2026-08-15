using System.Text.Json;
using Microsoft.AspNetCore.Http;
using SignaCore.Host.Middleware;
using Xunit;

namespace SignaCore.Tests.Host.Middleware;

public class SetupModeGateMiddlewareTests
{
    /// <summary>
    /// An API client that silently follows a redirect into an HTML setup page is far harder to
    /// diagnose than an explicit status, so API paths get a structured 503 rather than a redirect.
    /// </summary>
    [Theory]
    [InlineData("/api/auth/token")]
    [InlineData("/api/admin/session/login")]
    [InlineData("/oauth2/token")]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks")]
    public async Task ApiRequests_ReceiveStructuredInstallationRequired(string path)
    {
        var context = Context(path, acceptsHtml: true);

        await Invoke(context);

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, context.Response.StatusCode);
        Assert.Equal("installation_required", ReadJsonProperty(context, "error"));
    }

    [Theory]
    [InlineData("/api/setup/status")]
    [InlineData("/api/setup/complete")]
    [InlineData("/health/live")]
    [InlineData("/health/ready")]
    [InlineData("/health")]
    [InlineData("/metrics")]
    public async Task SetupAndHealthRequests_PassThrough(string path)
    {
        var context = Context(path, acceptsHtml: false);

        var reachedNext = await Invoke(context);

        Assert.True(reachedNext);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/admin")]
    [InlineData("/admin/users")]
    public async Task BrowserNavigation_IsRedirectedToSetup(string path)
    {
        var context = Context(path, acceptsHtml: true);

        await Invoke(context);

        Assert.Equal(StatusCodes.Status302Found, context.Response.StatusCode);
        Assert.Equal("/setup", context.Response.Headers.Location);
    }

    [Fact]
    public async Task SetupPage_IsServedRatherThanRedirectedIntoItself()
    {
        var context = Context("/setup", acceptsHtml: true);

        var reachedNext = await Invoke(context);

        Assert.True(reachedNext);
        Assert.NotEqual(StatusCodes.Status302Found, context.Response.StatusCode);
    }

    /// <summary>
    /// The setup page's own CSS and JS are plain GETs without an HTML Accept header; redirecting
    /// them would leave the operator staring at an unstyled page.
    /// </summary>
    [Theory]
    [InlineData("/assets/index.css")]
    [InlineData("/favicon.svg")]
    public async Task StaticAssets_PassThroughToTheSpaBranch(string path)
    {
        var context = Context(path, acceptsHtml: false);

        Assert.True(await Invoke(context));
    }

    /// <summary>A non-GET without an HTML Accept header is an API client, not a browser.</summary>
    [Fact]
    public async Task NonBrowserRequestsOutsideTheApiPrefixes_AreNotRedirected()
    {
        var context = Context("/something", acceptsHtml: false);
        context.Request.Method = HttpMethods.Post;

        await Invoke(context);

        Assert.NotEqual(StatusCodes.Status302Found, context.Response.StatusCode);
    }

    private static async Task<bool> Invoke(DefaultHttpContext context)
    {
        var reachedNext = false;
        var middleware = new SetupModeGateMiddleware(_ =>
        {
            reachedNext = true;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context);
        return reachedNext;
    }

    private static DefaultHttpContext Context(string path, bool acceptsHtml)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        if (acceptsHtml)
        {
            context.Request.Headers.Accept = "text/html,application/xhtml+xml";
        }

        return context;
    }

    private static string? ReadJsonProperty(HttpContext context, string property)
    {
        context.Response.Body.Position = 0;
        using var document = JsonDocument.Parse(context.Response.Body);
        return document.RootElement.GetProperty(property).GetString();
    }
}
